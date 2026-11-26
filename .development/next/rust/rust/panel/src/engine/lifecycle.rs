use super::{
    automation::{write_state, FILE as AUTOMATION},
    pid_path, running,
};
use crate::http::{ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, State},
    routing::post,
    Json, Router,
};
use nfqws2_config::Config;
use nfqws2_router_command::{Runner, System};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) static OPERATIONS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Start,
    Stop,
    Restart,
    RestoreOff,
}

trait Commands: Runner {
    fn available(&self, cfg: &Config) -> io::Result<()>;
    fn init(&self, cfg: &Config, action: &str, deadline: Instant) -> io::Result<()>;
}
struct RouterEngine<'a, C> {
    proc: &'a Path,
    commands: &'a C,
}
fn invalid(msg: &str) -> io::Error {
    io::Error::other(msg)
}
fn remove_runtime(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(m) if m.is_file() => fs::remove_file(path),
        Ok(_) => Err(invalid("runtime-файл NFQWS2 не является обычным файлом")),
        Err(e) => Err(e),
    }
}
fn queue_rule(output: &str, queue: i32) -> bool {
    output
        .lines()
        .filter(|line| line.starts_with("-A ") && line.contains("NFQUEUE"))
        .any(|line| {
            // Remove quoted comments before checking the actual target and its arguments.
            let mut quoted = false;
            let mut escaped = false;
            let words: String = line
                .chars()
                .filter(|&c| {
                    if escaped {
                        escaped = false;
                        return !quoted;
                    }
                    if c == '\\' {
                        escaped = true;
                        return !quoted;
                    }
                    if c == '"' {
                        quoted = !quoted;
                        return false;
                    }
                    !quoted
                })
                .collect();
            let words: Vec<_> = words.split_whitespace().collect();
            words.windows(2).any(|p| p == ["-j", "NFQUEUE"])
                && words.windows(2).any(|p| {
                    if p[0] == "--queue-num" {
                        return p[1].parse::<i32>() == Ok(queue);
                    }
                    if p[0] != "--queue-balance" {
                        return false;
                    }
                    p[1].split_once(':')
                        .and_then(|(a, b)| Some(a.parse::<i32>().ok()?..=b.parse::<i32>().ok()?))
                        .is_some_and(|r| r.contains(&queue))
                })
        })
}
fn firewall_stopped(
    cfg: &Config,
    queue: i32,
    deadline: Instant,
    runner: &impl Runner,
    proc: &Path,
) -> io::Result<()> {
    for executable in ["iptables", "ip6tables"] {
        let rules = match runner.run(executable, &["-w", "2", "-t", "mangle", "-S"], deadline) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => match runner.run(executable, &["-t", "mangle", "-S"], deadline) {
                Ok(v) => v,
                Err(_)
                    if executable == "ip6tables"
                        && !fs::read_to_string(proc.join("net/ip6_tables_names"))
                            .unwrap_or_default()
                            .lines()
                            .any(|v| v == "mangle") =>
                {
                    continue
                }
                Err(e) => return Err(e),
            },
        };
        if queue_rule(&rules, queue)
            || (queue != cfg.main_queue && queue_rule(&rules, cfg.main_queue))
        {
            return Err(io::Error::other(format!(
                "в {executable} осталось правило NFQUEUE для NFQWS2"
            )));
        }
    }
    Ok(())
}
impl Commands for System {
    fn available(&self, cfg: &Config) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&cfg.nfqws2_init)?;
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                Ok(())
            } else {
                Err(invalid("init-скрипт NFQWS2 не исполняемый"))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cfg;
            Err(invalid("управление NFQWS2 доступно в Linux"))
        }
    }
    fn init(&self, cfg: &Config, action: &str, deadline: Instant) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let mut cmd = std::process::Command::new(&cfg.nfqws2_init);
            cmd.arg(action);
            nfqws2_router_command::output(&mut cmd, deadline, 128 << 10).map(|_| ())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cfg, action, deadline);
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}
impl<C: Commands> RouterEngine<'_, C> {
    fn wait(&self, cfg: &Config, on: bool, queue: i32, deadline: Instant) -> io::Result<()> {
        let end = deadline.min(Instant::now() + Duration::from_secs(4));
        loop {
            if super::observed(cfg, self.proc, Some(queue)) == on {
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(invalid(if on {
                    "основной процесс NFQWS2 не запущен"
                } else {
                    "основная очередь или процесс NFQWS2 остаётся активным"
                }));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    fn stop(&self, cfg: &Config, deadline: Instant) -> io::Result<()> {
        let queue = super::effective_queue(cfg);
        let stopped = self.commands.init(cfg, "stop", deadline);
        if stopped.as_ref().is_err_and(|e| {
            matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::Unsupported
            )
        }) {
            return stopped;
        }
        self.wait(cfg, false, queue, deadline)?;
        let _ = self.commands.init(cfg, "firewall_stop", deadline);
        firewall_stopped(cfg, queue, deadline, self.commands, self.proc)?;
        remove_runtime(&PathBuf::from(format!("{}.run", cfg.nfqws2_conf)))?;
        remove_runtime(&pid_path(cfg))
    }
}
impl<C: Commands> RouterEngine<'_, C> {
    fn running(&self, cfg: &Config) -> bool {
        running(cfg, self.proc)
    }
    fn operate(&self, cfg: &Config, action: Action) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        if matches!(action, Action::Stop | Action::RestoreOff | Action::Restart) {
            self.stop(cfg, deadline)?;
        }
        if matches!(action, Action::Start | Action::Restart) {
            remove_runtime(&PathBuf::from(format!("{}.run", cfg.nfqws2_conf)))?;
            self.commands.init(cfg, "start", deadline)?;
            self.wait(cfg, true, super::effective_queue(cfg), deadline)?;
        }
        Ok(())
    }
}

pub(super) fn manual_off(db: &Store) -> io::Result<bool> {
    let state: Value = crate::data::or_default(db, AUTOMATION)?;
    if !state.is_object() && !state.is_null() {
        return Err(invalid("некорректный формат automation.json"));
    }
    match state.get("nfqws2_manual_off") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(off)) => Ok(*off),
        _ => Err(invalid("некорректное состояние ручного выключения NFQWS2")),
    }
}
fn persist(db: &Store, off: bool) -> io::Result<()> {
    db.transaction(|tx| {
        let mut state: Value = crate::data::or_default(db, AUTOMATION)?;
        if !state.is_object() && !state.is_null() {
            return Err(invalid("некорректный формат automation.json"));
        }
        state["nfqws2_manual_off"] = json!(off);
        write_state(tx, state)
    })
}
pub(crate) fn pause_acceleration(
    db: &Store,
    cfg: &Config,
) -> io::Result<nfqws2_awg_rules::kernel::EngineChange> {
    // Selective PPE state belongs to the controller that created this journal.
    match Path::new(&cfg.data_dir).join("awg-acceleration-state.json").symlink_metadata() {
        Ok(_) => Err(invalid("Обнаружен журнал ускорения AWG. Для сохранения настроек PPE требуется контроллер ускорения Go.")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => nfqws2_awg_rules::kernel::pause_for_engine(db, &System),
        Err(e) => Err(e),
    }
}
fn change(
    db: &Store,
    cfg: &Config,
    engine: &RouterEngine<'_, impl Commands>,
    action: Action,
) -> io::Result<()> {
    let off = manual_off(db)?;
    if action == Action::RestoreOff && !off {
        return Ok(());
    }
    if action == Action::Restart && off {
        return Err(invalid(
            "NFQWS2 выключен вручную. Включите службу перед перезапуском.",
        ));
    }
    let already_running = action == Action::Start && engine.running(cfg);
    if already_running && !off {
        return Ok(());
    }
    let _acceleration = pause_acceleration(db, cfg)?;
    if action == Action::Stop && !off {
        persist(db, true)?;
    }
    if !already_running {
        engine.commands.available(cfg)?;
    }
    let start = !already_running && matches!(action, Action::Start | Action::Restart);
    let rev = if start {
        db.transaction(|_| crate::editor::prepare_for_engine(cfg))?
    } else {
        None
    };
    let result = if already_running {
        Ok(())
    } else {
        engine.operate(cfg, action)
    };
    let result = result.and_then(|()| {
        if action == Action::Start && off {
            persist(db, false)
        } else {
            Ok(())
        }
    });
    if let Err(error) = result {
        if action == Action::Start && off {
            if let Err(cleanup) = engine.operate(cfg, Action::Stop) {
                return Err(io::Error::other(format!(
                    "{error}. Остановка после ошибки запуска: {cleanup}"
                )));
            }
        }
        return Err(error);
    }
    if start {
        db.transaction(|_| crate::editor::mark_engine_applied(cfg, rev.as_deref()))?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Outcome {
    name: String,
    ok: bool,
    detail: String,
}
async fn execute(s: Shared, action: Action) -> io::Result<()> {
    let lock = OPERATIONS.lock().await;
    tokio::task::spawn_blocking(move || {
        let _lock = lock;
        let result = change(
            &s.store,
            &s.config,
            &RouterEngine {
                proc: Path::new("/proc"),
                commands: &System,
            },
            action,
        );
        if matches!(action, Action::Stop | Action::RestoreOff) {
            // An init script can stop the process but fail to remove its queue.
            s.watchdog.lock().unwrap().retry_stop = result.is_err();
        }
        result
    })
    .await
    .map_err(io::Error::other)?
}
pub(crate) async fn restore_manual_off(s: &Shared) {
    if let Err(e) = execute(s.clone(), Action::RestoreOff).await {
        s.logs.append("nfqws2", "warn", &e.to_string());
    }
}
/// Caller holds OPERATIONS. An automatic start must never clear manual OFF.
pub(super) fn watchdog(s: &Shared, start: bool, retry_stop: bool) -> io::Result<()> {
    let engine = RouterEngine {
        proc: Path::new("/proc"),
        commands: &System,
    };
    if manual_off(&s.store)? {
        if retry_stop || running(&s.config, engine.proc) {
            change(&s.store, &s.config, &engine, Action::RestoreOff)?;
        }
    } else if start && !running(&s.config, engine.proc) {
        change(&s.store, &s.config, &engine, Action::Start)?;
    }
    Ok(())
}
pub(crate) async fn restart_after_config(s: Shared) -> io::Result<()> {
    execute(s, Action::Restart).await
}
/// Caller holds OPERATIONS across the preference check, config write and restart.
pub(super) fn restart_locked(s: &Shared) -> io::Result<()> {
    change(
        &s.store,
        &s.config,
        &RouterEngine {
            proc: Path::new("/proc"),
            commands: &System,
        },
        Action::Restart,
    )
}
/// Package hooks can start the engine even when installation fails. The caller
/// holds OPERATIONS, so use the engine directly without taking the lock twice.
pub(super) async fn stop_after_update(s: Shared) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        change(
            &s.store,
            &s.config,
            &RouterEngine {
                proc: Path::new("/proc"),
                commands: &System,
            },
            Action::RestoreOff,
        )
    })
    .await
    .map_err(io::Error::other)?
}
async fn outcome(s: Shared, name: &str, action: Action) -> Outcome {
    let changed = match name {
        "nfqws2" => execute(s.clone(), action).await,
        "tgws" => crate::tgws::restart(&s)
            .await
            .map_err(|e| io::Error::other(e.1)),
        "socks5" => crate::socks5::restart(&s)
            .await
            .map_err(|e| io::Error::other(e.1)),
        _ => Err(invalid("неизвестный сервис")),
    };
    let ok = changed.is_ok();
    let detail = changed.err().map_or_else(
        || match action {
            Action::Stop | Action::RestoreOff => "остановлен".to_owned(),
            Action::Start => "запущен".to_owned(),
            Action::Restart => "перезапущен".to_owned(),
        },
        |e| e.to_string(),
    );
    s.logs
        .append("system", if ok { "info" } else { "warn" }, &detail);
    Outcome {
        name: name.into(),
        ok,
        detail,
    }
}
async fn single(s: Shared, action: Action) -> Result<Json<Outcome>, ApiError> {
    Ok(Json(
        tokio::spawn(async move { outcome(s, "nfqws2", action).await })
            .await
            .map_err(io::Error::other)?,
    ))
}
#[derive(Deserialize)]
struct Services {
    #[serde(default)]
    services: Vec<String>,
}
async fn restart(
    State(s): State<Shared>,
    ApiJson(req): ApiJson<Services>,
) -> Result<Json<Value>, ApiError> {
    let rows = tokio::spawn(async move {
        let mut rows = Vec::new();
        for name in req.services {
            rows.push(outcome(s.clone(), &name, Action::Restart).await);
        }
        rows
    })
    .await
    .map_err(io::Error::other)?;
    Ok(Json(json!({"results":rows})))
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/api/nfqws2/start",
            post(|State(s): State<Shared>| single(s, Action::Start)),
        )
        .route(
            "/api/nfqws2/stop",
            post(|State(s): State<Shared>| single(s, Action::Stop)),
        )
        .route(
            "/api/services/restart",
            post(restart).layer(DefaultBodyLimit::max(4096)),
        )
}
#[cfg(test)]
mod tests;
