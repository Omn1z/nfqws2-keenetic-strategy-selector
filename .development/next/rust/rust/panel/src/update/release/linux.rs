use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufReader, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::{NamedTempFile, TempPath};
pub(in crate::update) struct Binary {
    target: PathBuf,
    staged: TempPath,
    previous: File,
}
fn mode_owner(file: &File, old: &File) -> io::Result<()> {
    let meta = old.metadata()?;
    let current = file.metadata()?;
    if (current.uid(), current.gid()) != (meta.uid(), meta.gid())
        && unsafe { libc::fchown(file.as_raw_fd(), meta.uid(), meta.gid()) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    file.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o777))?;
    file.sync_all()
}
fn same_process(target: &Path, original: &File) -> io::Result<()> {
    let old = original.metadata()?;
    let live = fs::metadata(target)?;
    if live.dev() != old.dev() || live.ino() != old.ino() || live.mode() != old.mode() {
        return Err(bad("исполняемый файл панели изменился во время обновления"));
    }
    Ok(())
}
impl Binary {
    pub(in crate::update) fn activate(self) -> io::Result<()> {
        self.replace_then(
            |target| {
                Err(std::process::Command::new(target)
                    .args(std::env::args_os().skip(1))
                    .exec())
            },
            || Ok(()),
        )
    }
    fn replace_then(
        mut self,
        apply: impl FnOnce(&Path) -> io::Result<()>,
        recover: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        // The CLI and daemon may check the same executable concurrently.
        // Lock both generations so neither can replace the other's rollback.
        let next = File::open(&self.staged)?;
        self.previous.try_lock().map_err(io::Error::other)?;
        next.try_lock().map_err(io::Error::other)?;
        same_process(&self.target, &self.previous)?;
        let dir = self
            .target
            .parent()
            .ok_or_else(|| bad("путь исполняемого файла"))?;
        self.staged.persist(&self.target).map_err(|e| e.error)?;
        let result = File::open(dir)
            .and_then(|d| d.sync_all())
            .and_then(|_| apply(&self.target));
        let Err(error) = result else {
            return Ok(());
        };
        same_process(&self.target, &next)?;
        // The open descriptor still owns the old executable, so rollback
        // after a failed restart needs no permanent backup on the router.
        let mut rollback = NamedTempFile::new_in(dir)?;
        io::copy(&mut self.previous, &mut rollback)?;
        mode_owner(rollback.as_file(), &self.previous)?;
        rollback.persist(&self.target)?;
        File::open(dir)?.sync_all()?;
        recover().map_err(|e| {
            io::Error::other(format!(
                "{error}; прежний файл восстановлен, повторный запуск: {e}"
            ))
        })?;
        Err(error)
    }
}
fn verified(path: &Path, expected: [u8; 32]) -> io::Result<()> {
    let file = File::open(path)?;
    if file.metadata()?.len() < 64 {
        return Err(bad("образ ELF слишком мал"));
    }
    let mut input = BufReader::new(file);
    let mut ident = [0; 20];
    input.read_exact(&mut ident)?;
    check_elf(&ident)?;
    let mut hash = Sha256::new();
    hash.update(ident);
    let mut chunk = [0; 16384];
    loop {
        let n = input.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        hash.update(&chunk[..n]);
    }
    let digest: [u8; 32] = hash.finalize().into();
    if digest != expected {
        return Err(bad("SHA256 образа Rust не совпал"));
    }
    Ok(())
}
fn mark(s: &Shared, phase: &str) {
    s.update.state.lock().unwrap().stage = phase.to_owned();
}
async fn prepare(
    config: &nfqws2_config::Config,
    progress: impl Fn(&str, Option<&str>),
) -> io::Result<(Binary, String)> {
    progress("checking", None);
    let r = latest(&config.repo, &config.version).await?;
    progress("checked", Some(&r.tag));
    if !r.available {
        return Err(bad("уже установлена текущая версия"));
    }
    if std::env::var("N2S_EXPECT_VERSION").is_ok_and(|expected| {
        !expected.is_empty() && expected.trim_start_matches('v') != r.tag.trim_start_matches('v')
    }) {
        return Err(bad("версия выпуска отличается от запрошенной"));
    }
    let mut manifest = Vec::new();
    download(
        &format!("{}/SHA256SUMS", r.base),
        &mut manifest,
        1 << 20,
        12,
    )
    .await?;
    let digest = checksum(&manifest, &r.name)?;
    let target = std::env::current_exe()?;
    let previous = File::open("/proc/self/exe")?;
    same_process(&target, &previous)?;
    let temp = NamedTempFile::new_in(
        target
            .parent()
            .ok_or_else(|| bad("нет каталога программы"))?,
    )?;
    progress("downloading", None);
    let mut out = tokio::fs::File::from_std(temp.reopen()?);
    download(&format!("{}/{}", r.base, r.name), &mut out, 64 << 20, 180).await?;
    out.sync_all().await?;
    drop(out);
    progress("replacing", None);
    let expected = r.tag.clone();
    let binary = tokio::task::spawn_blocking(move || {
        verified(temp.path(), digest)?;
        mode_owner(temp.as_file(), &previous)?;
        Ok::<_, io::Error>(Binary {
            target,
            previous,
            staged: temp.into_temp_path(),
        })
    })
    .await
    .map_err(io::Error::other)??;
    let version = tokio::time::timeout(
        Duration::from_secs(8),
        crate::packages::command(&binary.staged, &["version"]),
    )
    .await
    .map_err(io::Error::other)??;
    if !version.0 || version.1.trim_start_matches('v') != expected.trim_start_matches('v') {
        return Err(bad("скачанный файл сообщил другую версию"));
    }
    Ok((binary, r.tag))
}
pub(in crate::update) async fn install_cli(config: &nfqws2_config::Config) -> io::Result<String> {
    let init = PathBuf::from(&config.init_script);
    if !init.is_absolute()
        || !init
            .metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "не найден исполняемый init-скрипт панели",
        ));
    }
    let (binary, version) = prepare(config, |_, _| {}).await?;
    tokio::task::spawn_blocking(move || {
        let restart = || {
            nfqws2_router_command::output(
                std::process::Command::new(&init).arg("restart"),
                std::time::Instant::now() + Duration::from_secs(45),
                64 * 1024,
            )
            .map(drop)
        };
        binary.replace_then(|_| restart(), restart)
    })
    .await
    .map_err(io::Error::other)??;
    Ok(version)
}
pub(in crate::update) async fn update(s: Shared) {
    let progress = |phase: &str, version: Option<&str>| {
        let mut state = s.update.state.lock().unwrap();
        state.stage = phase.into();
        if let Some(version) = version {
            state.latest = version.into();
        }
    };
    match prepare(&s.config, progress).await {
        Ok((binary, _)) => {
            *s.update.ready.lock().unwrap() = Some(Pending { binary });
            mark(&s, "restarting");
            s.restart.send_replace(true);
        }
        Err(e) => {
            let mut st = s.update.state.lock().unwrap();
            st.stage = "error".into();
            st.error = e.to_string();
            st.running = false;
            st.finished_at = now();
            s.logs.append("update", "error", &st.error);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn staged_for_test(dir: &Path) -> Binary {
        use std::io::Write;
        let target = dir.join("panel");
        fs::write(&target, b"previous").unwrap();
        let mut staged = NamedTempFile::new_in(dir).unwrap();
        staged.write_all(b"next").unwrap();
        staged.as_file().sync_all().unwrap();
        Binary {
            previous: File::open(&target).unwrap(),
            target,
            staged: staged.into_temp_path(),
        }
    }
    #[test]
    fn restart_failure_restores_previous_executable_before_recovering_service() {
        let dir = tempfile::tempdir().unwrap();
        let binary = staged_for_test(dir.path());
        let error = binary
            .replace_then(
                |target| {
                    assert_eq!(fs::read(target).unwrap(), b"next");
                    Err(io::Error::other("simulated restart failure"))
                },
                || {
                    assert_eq!(fs::read(dir.path().join("panel")).unwrap(), b"previous");
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("simulated"));
        let binary = staged_for_test(dir.path());
        binary
            .replace_then(
                |target| {
                    assert_eq!(fs::read(target).unwrap(), b"next");
                    Ok(())
                },
                || panic!("unexpected recovery"),
            )
            .unwrap();
        assert_eq!(fs::read(dir.path().join("panel")).unwrap(), b"next");
    }
    #[test]
    fn concurrent_replacement_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let binary = staged_for_test(dir.path());
        let other = dir.path().join("concurrent");
        fs::write(&other, b"other").unwrap();
        fs::rename(other, &binary.target).unwrap();
        assert!(binary
            .replace_then(
                |_| panic!("unexpected restart"),
                || panic!("unexpected recovery")
            )
            .is_err());
        assert_eq!(fs::read(dir.path().join("panel")).unwrap(), b"other");
    }
    #[test]
    fn only_a_matching_local_elf_with_verified_hash_passes() {
        let path = std::env::current_exe().unwrap();
        let digest = Sha256::digest(fs::read(&path).unwrap()).into();
        verified(&path, digest).unwrap();
        assert!(verified(&path, [0; 32]).is_err());
        let mut blob = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut blob, &[0; 64]).unwrap();
        assert!(verified(blob.path(), digest).is_err());
    }
}
