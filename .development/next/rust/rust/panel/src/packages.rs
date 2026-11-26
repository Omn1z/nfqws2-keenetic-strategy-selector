use crate::http::{ApiJson, Shared};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use nfqws2_config::{Key, Platform, Resolver};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env, io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Mutex,
    time::timeout,
};

const MODULES: [&str; 6] = [
    "nfqws2-strategy-runs",
    "nfqws2-strategy-blockcheck",
    "nfqws2-strategy-strategies",
    "nfqws2-strategy-geo",
    "nfqws2-strategy-trace",
    "nfqws2-strategy-tgws",
];
const OUTPUT_LIMIT: usize = 16 * 1024;
pub(crate) static INSTALL: Mutex<()> = Mutex::const_new(());
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/system/install", post(install))
        .route("/api/modules", get(modules))
}
async fn modules() -> Json<Value> {
    Json(json!({"packages":if cfg!(feature="compact") {&MODULES[..]} else {&[]}}))
}
#[derive(Deserialize)]
struct Package {
    package: String,
}
fn allowed(pkg: &str) -> bool {
    pkg == "tcpdump" || (cfg!(feature = "compact") && MODULES.contains(&pkg))
}
fn executable(path: &Path) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    meta.is_file()
}
#[cfg(feature = "compact")]
fn verify_module(root: &Path, pkg: &str) -> io::Result<()> {
    use crate::assets::{Asset, ASSETS};
    let Some(module) = pkg.strip_prefix("nfqws2-strategy-") else {
        return Ok(());
    };
    let dir = root.join(module);
    let worker = dir.join(format!("nfqws2-{module}"));
    if !executable(&worker) || worker.metadata()?.len() == 0 {
        return Err(io::Error::other(format!(
            "Отсутствует исполнитель модуля {module}"
        )));
    }
    let require_file = |path: &Path| {
        if path.metadata().is_ok_and(|m| m.is_file() && m.len() > 0) {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Отсутствует файл модуля: {}",
                path.display()
            )))
        }
    };
    if module == "strategies" {
        require_file(&dir.join("catalog.json"))?;
    }
    for (_, asset) in ASSETS {
        if let Asset::Module(rel) = asset {
            if rel.split_once('/').is_some_and(|(id, _)| id == module) {
                require_file(&root.join(format!("{rel}.gz")))?;
            }
        }
    }
    Ok(())
}
pub(crate) fn manager(pkg: &str) -> io::Result<(PathBuf, bool)> {
    find_manager(pkg == "tcpdump")
}
pub(crate) fn find_manager(allow_apk: bool) -> io::Result<(PathBuf, bool)> {
    let paths = Resolver::current();
    if paths.platform() == Platform::OpenWrt {
        // Entware can also be mounted under /opt on OpenWrt. Its package
        // database and the native SDK feed install into different roots.
        return native_manager(paths.path(Key::EtcDir).parent().expect("root of /etc"));
    }
    let path = env::var_os("PATH").unwrap_or_default();
    for name in ["apk", "opkg"] {
        if name == "apk" && !allow_apk {
            continue;
        }
        if let Some(binary) = env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|p| executable(p))
        {
            return Ok((binary, name == "apk"));
        }
    }
    let opt = paths.path(Key::EntwareOpkg);
    if executable(opt) {
        return Ok((opt.to_path_buf(), false));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "package manager not found",
    ))
}
fn native_manager(root: &Path) -> io::Result<(PathBuf, bool)> {
    for name in ["apk", "opkg"] {
        for dir in ["bin", "sbin", "usr/bin", "usr/sbin"] {
            let path = root.join(dir).join(name);
            if executable(&path) {
                return Ok((path, name == "apk"));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "OpenWrt: apk/opkg не найден",
    ))
}
async fn drain(mut pipe: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let n = pipe.read(&mut buf).await?;
        if n == 0 {
            return Ok(retained);
        }
        retained.extend_from_slice(&buf[..n]);
        if retained.len() > OUTPUT_LIMIT {
            retained.drain(..retained.len() - OUTPUT_LIMIT);
        }
    }
}
pub(crate) async fn command(program: &Path, args: &[&str]) -> io::Result<(bool, String)> {
    let mut cmd = Command::new(program);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .args(args)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child.stdout.take().expect("piped stdout");
    let err = child.stderr.take().expect("piped stderr");
    #[cfg(unix)]
    let mut group = crate::process_group::ProcessGroup(child.id());
    let (code, out, err) = tokio::try_join!(child.wait(), drain(out), drain(err))?;
    #[cfg(unix)]
    {
        group.0 = None;
    }
    let mut result = String::from_utf8_lossy(&out).into_owned();
    if !err.is_empty() {
        result.push('\n');
        result.push_str(&String::from_utf8_lossy(&err));
    }
    Ok((code.success(), result.trim().into()))
}
async fn execute(program: &Path, apk: bool, pkg: &str) -> io::Result<Value> {
    let args = if apk {
        vec!["--update-cache", "add", pkg]
    } else {
        vec!["install", pkg]
    };
    let (success, mut output) = command(program, &args).await?;
    if success {
        return Ok(json!({"ok":true,"output":output}));
    }
    if apk {
        return Ok(json!({"ok":false,"output":output,"error":"package installation failed"}));
    }
    let (_, update) = command(program, &["update"]).await?;
    let (success, retry) = command(program, &args).await?;
    output.push_str(&format!("\n{update}\n{retry}"));
    Ok(if success {
        json!({"ok":true,"output":output})
    } else {
        json!({"ok":false,"output":output,"error":"package installation failed"})
    })
}
async fn install(State(s): State<Shared>, ApiJson(p): ApiJson<Package>) -> Json<Value> {
    let fail = |msg: &str| Json(json!({"ok":false,"output":"","error":msg}));
    if !allowed(&p.package) {
        return fail("Пакет не разрешён к установке");
    }
    let Ok(_lock) = INSTALL.try_lock() else {
        return fail("Установка уже выполняется");
    };
    let (pm, apk) = match manager(&p.package) {
        Ok(v) => v,
        Err(e) => return fail(&e.to_string()),
    };
    s.logs
        .append("system", "info", &format!("install {}", p.package));
    match timeout(Duration::from_secs(180), execute(&pm, apk, &p.package)).await {
        Ok(Ok(value)) => {
            #[cfg(feature = "compact")]
            if value["ok"] == true {
                if let Err(error) = verify_module(&crate::assets::module_dir(), &p.package) {
                    return Json(
                        json!({"ok":false,"output":value["output"],"error":error.to_string()}),
                    );
                }
            }
            if p.package == "nfqws2-strategy-trace" && value["ok"] == true {
                crate::trace::awg::restore(&s).await;
            }
            Json(value)
        }
        Ok(Err(e)) => fail(&e.to_string()),
        Err(_) => fail("Время установки истекло"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_package_database_takes_precedence_over_entware() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let tool = |name: &str| {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"tool").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            path
        };
        tool("opt/bin/opkg");
        assert_eq!(
            native_manager(root).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let legacy = tool("bin/opkg");
        assert_eq!(native_manager(root).unwrap(), (legacy, false));
        let apk = tool("usr/bin/apk");
        assert_eq!(native_manager(root).unwrap(), (apk, true));
    }
    #[cfg(feature = "compact")]
    #[test]
    fn successful_opkg_exit_requires_the_installed_worker_catalog_and_matching_page() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let package = "nfqws2-strategy-strategies";
        let root = temp.path();
        let directory = root.join("strategies");
        fs::create_dir(&directory).unwrap();
        assert!(verify_module(root, package).is_err());
        let worker = directory.join("nfqws2-strategies");
        fs::write(&worker, b"fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&worker, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(verify_module(root, package)
            .unwrap_err()
            .to_string()
            .contains("catalog.json"));
        fs::write(directory.join("catalog.json"), b"[]").unwrap();
        assert!(verify_module(root, package)
            .unwrap_err()
            .to_string()
            .contains(".js.gz"));
        for (_, asset) in crate::assets::ASSETS {
            if let crate::assets::Asset::Module(rel) = asset {
                if rel.starts_with("strategies/") {
                    fs::write(root.join(format!("{rel}.gz")), b"page").unwrap();
                }
            }
        }
        assert!(verify_module(root, package).is_ok());
        assert!(verify_module(root, "tcpdump").is_ok());
    }
    #[tokio::test]
    async fn output_is_bounded_and_whitelist_is_exact() {
        let input = vec![b'a'; OUTPUT_LIMIT + 3000];
        assert_eq!(drain(input.as_slice()).await.unwrap().len(), OUTPUT_LIMIT);
        for pkg in [
            "",
            "--force-depends",
            "tcpdump other",
            "../nfqws2-strategy-geo",
        ] {
            assert!(!allowed(pkg));
        }
        assert_eq!(allowed(MODULES[0]), cfg!(feature = "compact"));
        assert!(allowed("tcpdump"));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn refreshes_once_then_uses_same_package() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let pm = dir.path().join("opkg");
        fs::write(&pm,"#!/bin/sh\ncd \"$(dirname \"$0\")\" || exit 1\nprintf '%s\\n' \"$*\" >>calls\nif [ \"$1\" = update ]; then touch refreshed; fi\ntest -f refreshed\n").unwrap();
        fs::set_permissions(&pm, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(execute(&pm, false, "tcpdump").await.unwrap()["ok"], true);
        assert_eq!(
            fs::read_to_string(dir.path().join("calls")).unwrap(),
            "install tcpdump\nupdate\ninstall tcpdump\n"
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn apk_installs_the_selected_module_with_one_index_refresh() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let pm = dir.path().join("apk");
        fs::write(
            &pm,
            "#!/bin/sh\nprintf '%s\\n' \"$*\"\n[ \"$3\" = nfqws2-strategy-geo ]\n",
        )
        .unwrap();
        fs::set_permissions(&pm, fs::Permissions::from_mode(0o700)).unwrap();
        for (pkg, success) in [("nfqws2-strategy-geo", true), ("missing", false)] {
            let result = execute(&pm, true, pkg).await.unwrap();
            assert_eq!(result["ok"], success);
            assert_eq!(result["output"], format!("--update-cache add {pkg}"));
        }
    }
}
