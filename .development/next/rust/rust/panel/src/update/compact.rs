use super::{now, update_help, Job, Shared};
use crate::packages;
use nfqws2_config::{Config, Key, Resolver};
use nfqws2_store::Store;
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::Mutex, time::timeout};

use super::compact_version::{candidate, Target, BASE};
const RECEIPT: &str = "compact-update.json";
static REFRESHED: Mutex<Option<Instant>> = Mutex::const_new(None);

// A diagnostic sidecar can run the same build with its own data directory.
// Only the executable behind the active compact service may run its installer.
fn installer(config: &Config) -> io::Result<PathBuf> {
    let paths = Resolver::current();
    let root = paths.path(Key::ModuleDir).parent().unwrap();
    let panel = root.join("n2s-compact");
    let script = root.join("install.sh");
    let installed = fs::metadata(&panel);
    let running = fs::metadata("/proc/self/exe")?;
    let data = fs::canonicalize(&config.data_dir);
    if !installed.is_ok_and(|m| (m.dev(), m.ino()) == (running.dev(), running.ino()))
        || fs::read_link(paths.path(Key::StrategyBin)).ok().as_ref() != Some(&panel)
        || !data.is_ok_and(|p| {
            fs::canonicalize(paths.path(Key::DataDir)).is_ok_and(|expected| expected == p)
        })
        || Path::new(&config.init_script) != paths.path(Key::StrategyInit)
        || !script.is_file()
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, update_help()));
    }
    Ok(script)
}

async fn query() -> io::Result<Option<Target>> {
    let (manager, apk) = packages::find_manager(false)?;
    let _package_lock = packages::INSTALL.lock().await;
    let mut last = REFRESHED.lock().await;
    let run = async |args: &[&str]| {
        let result = timeout(Duration::from_secs(65), packages::command(&manager, args)).await??;
        if result.0 {
            Ok(result.1)
        } else {
            Err(io::Error::other(
                "Пакетный менеджер не смог проверить настроенные источники",
            ))
        }
    };
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(300)) {
        run(&["update"]).await?;
        *last = Some(Instant::now());
    }
    let args: &[&str] = if apk {
        &["list", "--upgradable", BASE]
    } else {
        &["list-upgradable", BASE]
    };
    let paths = Resolver::current();
    let target = candidate(&run(args).await?, apk, false, paths.platform())?;
    // A previous failed package transaction can leave the database ahead of
    // its restored files. The installer retains this marker until it repairs
    // every selected module, even if the feed reports no new revision.
    if target.is_some()
        || !paths
            .path(Key::ModuleDir)
            .parent()
            .unwrap()
            .join(".compact-repair")
            .is_file()
    {
        return Ok(target);
    }
    let args: &[&str] = if apk {
        &["list", "--installed", BASE]
    } else {
        &["list-installed", BASE]
    };
    candidate(&run(args).await?, apk, true, paths.platform())
}

pub(super) async fn check(config: &Config) -> io::Result<Value> {
    installer(config)?;
    let next = query().await?;
    Ok(
        json!({"current":config.version, "latest":next.as_ref().map_or(config.version.as_str(), |t| &t.build), "available":next.is_some()}),
    )
}

fn lock_file(dir: &str) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(Path::new(dir).join(".store/compact-update.lock"))
}
fn interrupted(mut job: Job) -> Job {
    job.running = false;
    job.stage = "error".into();
    job.error = "Процесс пакетного обновления завершился до подтверждения".into();
    job
}
pub(super) fn status(s: &Shared, local: Job) -> Job {
    let Ok(saved) = s.store.read_runtime::<Job>(RECEIPT, 8192) else {
        return local;
    };
    if local.started_at > saved.started_at
        || (local.stage == "error" && local.started_at == saved.started_at)
    {
        return local;
    }
    if saved.running && lock_file(&s.config.data_dir).is_ok_and(|f| f.try_lock().is_ok()) {
        return interrupted(saved);
    }
    saved
}
pub(super) async fn install_cli(config: &Config) -> io::Result<String> {
    let path = installer(config)?;
    let store = Store::open(&config.data_dir)?;
    let lock = lock_file(&config.data_dir)?;
    lock.try_lock()
        .map_err(|_| io::Error::other("Пакетное обновление уже выполняется"))?;
    let mut job = Job {
        running: true,
        current: config.version.clone(),
        stage: "checking".into(),
        started_at: now(),
        ..Job::default()
    };
    let save = |job: &Job| store.transaction(|tx| tx.save_runtime(RECEIPT, job));
    save(&job)?;
    let result = async {
        let target = query()
            .await?
            .ok_or_else(|| io::Error::other("Уже установлена текущая версия пакетной панели"))?;
        job.latest = target.build.clone();
        job.stage = "installing".into();
        save(&job)?;
        // opkg may replace the maintenance script itself. Keep the exact
        // installer in a private file until its rollback/trap has completed.
        let mut script = tempfile::NamedTempFile::new()?;
        io::copy(&mut File::open(path)?, script.as_file_mut())?;
        let status = Command::new("/bin/sh")
            .arg(script.path())
            .env("N2S_PROFILE", "compact")
            .env("N2S_SKIP_DEPS", "1")
            .env("N2S_REQUIRE_NATIVE", "1")
            .env("N2S_EXPECT_PACKAGE_VERSION", target.package)
            .env("N2S_EXPECT_VERSION", &target.build)
            .env_remove("N2S_BIN_SRC")
            .stdin(Stdio::null())
            .status()
            .await?;
        if !status.success() {
            return Err(io::Error::other(
                "Штатный установщик не подтвердил пакетное обновление",
            ));
        }
        Ok(target.build)
    }
    .await;
    job.running = false;
    job.finished_at = now();
    match &result {
        Ok(build) => {
            job.stage = "done".into();
            job.latest.clone_from(build);
        }
        Err(error) => {
            job.stage = "error".into();
            job.error = error.to_string();
        }
    }
    save(&job)?;
    result
}

pub(super) async fn update(s: Shared) {
    let run = async {
        installer(&s.config)?;
        let _package_lock = packages::INSTALL.lock().await;
        // Separate process group and no inherited service pipes. The CLI must
        // survive the installer stopping this HTTP process and retain its lock.
        let status = Command::new("/proc/self/exe")
            .arg("update")
            .env("N2S_DATA", &s.config.data_dir)
            .env("N2S_INIT", &s.config.init_script)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        if !status.success() {
            return Err(io::Error::other(
                "Проверка или установка пакетного обновления завершилась ошибкой",
            ));
        }
        Ok(())
    }
    .await;
    let mut local = s.update.state.lock().unwrap();
    local.running = false;
    local.finished_at = now();
    if let Err(err) = run {
        local.stage = "error".into();
        local.error = err.to_string();
    } else {
        local.stage = "done".into();
    }
}
