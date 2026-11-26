use super::{invalid, parse, Execute};
use std::{
    env, io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};

pub struct Native(Option<PathBuf>);
#[cfg(unix)]
use crate::process_group::ProcessGroup;
impl Native {
    pub(super) fn detect(root: &Path) -> (Self, &'static str, &'static str) {
        if !cfg!(target_os = "linux") {
            return (
                Self(None),
                "unsupported",
                "Управление изоляцией доступно на роутере Keenetic",
            );
        }
        if nfqws2_config::Resolver::new_at(root).platform() == nfqws2_config::Platform::OpenWrt {
            return (
                Self(None),
                "openwrt",
                "На OpenWrt настройте изоляцию гостевой Wi-Fi сети в LuCI.",
            );
        }
        let paths = env::var_os("PATH").unwrap_or_default();
        let path = env::split_paths(&paths).map(|p| p.join("ndmc")).find(|p| {
            let Ok(m) = p.metadata() else { return false };
            if !m.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        });
        if path.is_none() {
            (
                Self(None),
                "unknown",
                "Штатный контроллер Keenetic ndmc не найден",
            )
        } else {
            (Self(path), "keenetic", "")
        }
    }
}
async fn bounded(r: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let limit = 2 << 20;
    let mut data = Vec::new();
    r.take(limit + 1).read_to_end(&mut data).await?;
    if data.len() as u64 > limit {
        return Err(invalid("слишком большой ответ Keenetic"));
    }
    Ok(data)
}
fn rejected(s: &str) -> bool {
    s.lines().any(|l| {
        let l = l.trim_start().to_ascii_lowercase();
        l.starts_with("error:")
            || l.starts_with("%error:")
            || l.starts_with("command not found")
            || l.split_once("error").is_some_and(|(prefix, suffix)| {
                prefix.contains("::") && suffix.trim_start().starts_with('[')
            })
    })
}
impl Execute for Native {
    async fn command(&self, arg: &str) -> io::Result<String> {
        let mut cmd = Command::new(self.0.as_ref().ok_or_else(|| invalid("ndmc недоступен"))?);
        cmd.args(["-c", arg])
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|_| io::Error::other("не удалось запустить ndmc"))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        #[cfg(unix)]
        let mut group = ProcessGroup(child.id());
        let read = async { tokio::try_join!(bounded(stdout), bounded(stderr), child.wait()) };
        let (out, err, status) = match timeout(Duration::from_secs(5), read).await {
            Ok(Ok(result)) => result,
            _ => {
                #[cfg(unix)]
                drop(group);
                let _ = child.kill().await;
                return Err(io::Error::other(
                    "Keenetic: команда не завершилась или ответ превышает лимит",
                ));
            }
        };
        #[cfg(unix)]
        {
            group.0 = None;
        }
        if !status.success() || out.len() + err.len() > 2 << 20 {
            return Err(io::Error::other("Keenetic отклонил команду"));
        }
        let mut out = parse::plain(&String::from_utf8_lossy(&out));
        if !err.is_empty() {
            out.push('\n');
            out.push_str(&parse::plain(&String::from_utf8_lossy(&err)));
        }
        if rejected(&out) {
            return Err(io::Error::other("Keenetic отклонил команду"));
        }
        Ok(out)
    }
}
