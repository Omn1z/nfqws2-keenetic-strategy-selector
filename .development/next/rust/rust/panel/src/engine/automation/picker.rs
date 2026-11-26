use super::{candidates, invalid, lifecycle, read, view, write_state};
use crate::{
    blockcheck::Permit,
    http::{blocking, ApiError, Shared},
};
use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{task::JoinHandle, time::Instant};

const TARGETS: [&str; 5] = [
    "youtube.com",
    "googlevideo.com",
    "instagram.com",
    "x.com",
    "openai.com",
];
const PICK_TIMEOUT: Duration = Duration::from_secs(8 * 60);

#[derive(Default)]
pub(crate) struct Picker {
    running: Arc<AtomicBool>,
    stopping: AtomicBool,
    task: Mutex<Option<JoinHandle<()>>>,
}
impl Picker {
    pub(super) fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    fn reserve(&self) -> io::Result<PickPermit> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(invalid("панель останавливается"));
        }
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| invalid("auto-pick already in progress"))?;
        Ok(PickPermit(self.running.clone()))
    }
}
struct PickPermit(Arc<AtomicBool>);
impl Drop for PickPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
#[derive(Clone, Copy)]
enum Reason {
    Manual,
    FirstBoot,
    Periodic,
}
impl Reason {
    fn name(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::FirstBoot => "first-boot",
            Self::Periodic => "periodic",
        }
    }
}
fn allowed(s: &Shared, reason: Reason) -> io::Result<bool> {
    if s.auto_pick.stopping.load(Ordering::Acquire) || lifecycle::manual_off(&s.store)? {
        return Ok(false);
    }
    let v = read(&s.store)?;
    Ok(match reason {
        Reason::Manual => true,
        Reason::FirstBoot => v["auto_pick"] == true,
        Reason::Periodic => v["auto_pick"] == true && v["periodic_scan"] == true,
    })
}
/// Reserve before spawning: concurrent HTTP requests cannot both be accepted.
async fn queue(s: Shared, reason: Reason) -> io::Result<Value> {
    let _lock = lifecycle::OPERATIONS.lock().await;
    if !allowed(&s, reason)? {
        return Err(invalid(
            "NFQWS2 выключен вручную или автоматический подбор отключён",
        ));
    }
    if s.active_test.load(Ordering::Acquire) {
        return Err(invalid("a run is already in progress"));
    }
    let permit = s.auto_pick.reserve()?;
    let test_permit = Arc::new(Permit::acquire(&s.active_test)?);
    let response = match reason {
        Reason::Manual => view(&s)?,
        Reason::FirstBoot | Reason::Periodic => Value::Null,
    };
    let state = s.clone();
    let task = tokio::spawn(async move {
        let _permit = permit;
        state.logs.append(
            "automation",
            "info",
            &format!("auto-pick start ({})", reason.name()),
        );
        if let Err(e) = run(state.clone(), reason, test_permit).await {
            let message = e.to_string();
            let update = state.clone();
            let recorded = message.clone();
            if let Err(e) = blocking(move || record(&update, Err(&recorded))).await {
                state.logs.append("automation", "warn", &e.1);
            }
            state.logs.append("automation", "error", &message);
        }
    });
    *s.auto_pick.task.lock().unwrap() = Some(task);
    Ok(response)
}
pub(crate) async fn pick_now(
    State(s): State<Shared>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    queue(s, Reason::Manual)
        .await
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
        .map_err(|e| ApiError(StatusCode::CONFLICT, e.to_string()))
}
fn record(s: &Shared, result: Result<&Value, &str>) -> io::Result<()> {
    s.store.transaction(|tx| {
        let mut v = read(&s.store)?;
        match result {
            Ok(winner) => {
                v["last_pick_at"] = json!(nfqws2_awg_profile::now());
                v["last_pick_args"] = winner["args"].clone();
                v["last_pick_name"] = winner["name"].clone();
                v["last_pick_error"] = json!("");
            }
            Err(message) => v["last_pick_error"] = json!(message),
        }
        write_state(tx, v)
    })
}
fn winner(report: &Value) -> io::Result<Value> {
    if report["status"] != "done" {
        return Err(io::Error::other(format!(
            "auto-pick run {}: {}",
            report["status"].as_str().unwrap_or("error"),
            report["error"].as_str().unwrap_or("прогон прерван")
        )));
    }
    let mut best: Option<(&Value, f64)> = None;
    for row in report["results"].as_array().into_iter().flatten() {
        let valid = row["success"] == true
            && row["targets_total"]
                .as_u64()
                .is_some_and(|n| n > 0 && row["targets_ok"].as_u64() == Some(n))
            && row["error"].as_str().is_none_or(str::is_empty)
            && row["args"]
                .as_str()
                .is_some_and(|a| nfqws2_config::validate_https_strategy(a).is_ok());
        let Some(score) = row["coefficient"]
            .as_f64()
            .filter(|v| v.is_finite() && *v >= 0.0)
        else {
            continue;
        };
        if valid && best.is_none_or(|(_, prev)| score > prev) {
            best = Some((row, score));
        }
    }
    best.map(|(row, _)| row.clone())
        .ok_or_else(|| invalid("no working HTTPS (TCP/443, TLS) strategy found"))
}
async fn run(s: Shared, reason: Reason, test_permit: Arc<Permit>) -> io::Result<()> {
    let state = s.clone();
    let (request, _acceleration) = blocking(move || {
        if !allowed(&state, reason)? {
            return Err(invalid("авто-пик отключён"));
        }
        let guard = lifecycle::pause_acceleration(&state.store, &state.config)?;
        let mut config = state.config.clone();
        config.load_from_nfqws2_conf()?;
        Ok((
            json!({"targets":TARGETS,"threads":6,"auto":true,
            "strategies":candidates::load(&state)?,"config":config}),
            guard,
        ))
    })
    .await
    .map_err(|e| io::Error::other(e.1))?;
    let report = crate::runs::start_matrix(s.clone(), request, test_permit.clone())
        .await
        .map_err(|e| io::Error::other(e.1))?;
    let id = report["id"]
        .as_str()
        .ok_or_else(|| invalid("прогон не вернул ID"))?
        .to_owned();
    let deadline = Instant::now() + PICK_TIMEOUT;
    let mut timeout = false;
    loop {
        // Wait for the child to exit and clean its rules before any restart.
        if s.runs.live().await.is_none_or(|(active, _)| active != id) {
            break;
        }
        if Instant::now() >= deadline || s.auto_pick.stopping.load(Ordering::Acquire) {
            timeout = true;
            crate::runs::cancel_matching(&s, &id).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if timeout {
        return Err(invalid("auto-pick timeout or shutdown"));
    }
    let state = s.clone();
    let selected = blocking(move || {
        let report = state
            .store
            .read_limited::<Value>(&format!("runs/{id}.json"), 16 << 20)?;
        winner(&report)
    })
    .await
    .map_err(|e| io::Error::other(e.1))?;
    let lock = lifecycle::OPERATIONS.lock().await;
    blocking(move || {
        let _lock = lock;
        let _test_permit = test_permit;
        apply(&s, reason, &selected, || lifecycle::restart_locked(&s))?;
        record(&s, Ok(&selected))?;
        s.logs.append(
            "automation",
            "info",
            &format!(
                "auto-pick applied: {}",
                selected["name"].as_str().unwrap_or("")
            ),
        );
        Ok(())
    })
    .await
    .map_err(|e| io::Error::other(e.1))
}
fn apply(
    s: &Shared,
    reason: Reason,
    selected: &Value,
    restart: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Revalidate at the write boundary, including reports from older versions.
    winner(&json!({"status":"done","results":[selected]}))?;
    if !allowed(s, reason)? {
        return Err(invalid(
            "NFQWS2 выключен вручную или авто-пик отключён; стратегия не применена",
        ));
    }
    let _acceleration = lifecycle::pause_acceleration(&s.store, &s.config)?;
    s.store.transaction(|_| {
        crate::editor::save_strategy(&s.config, selected["args"].as_str().unwrap())
    })?;
    restart().map_err(|e| io::Error::other(format!("стратегия сохранена; перезапуск NFQWS2: {e}")))
}
pub(super) async fn scheduled(s: Shared, first: bool, healthy: bool) -> io::Result<()> {
    if s.auto_pick.running() || s.active_test.load(Ordering::Acquire) {
        return Ok(());
    }
    let state = s.clone();
    let reason = blocking(move || {
        let v = read(&state.store)?;
        if !allowed(&state, Reason::FirstBoot)? {
            return Ok(None);
        }
        let last = v["last_pick_at"].as_u64().unwrap_or(0);
        if first && last == 0 {
            use std::io::Read;
            let mut source = String::new();
            std::fs::File::open(&state.config.nfqws2_conf)?
                .take((1 << 20) + 1)
                .read_to_string(&mut source)?;
            if source.len() > 1 << 20 {
                return Err(invalid("слишком большая конфигурация NFQWS2"));
            }
            if nfqws2_config::literal_shell_config_value(&source, "NFQWS_ARGS")?
                .is_some_and(|a| !a.trim().is_empty())
            {
                state.store.transaction(|tx| {
                    let mut v = read(&state.store)?;
                    v["last_pick_at"] = json!(nfqws2_awg_profile::now());
                    v["last_pick_args"] = json!("(pre-existing)");
                    write_state(tx, v)
                })?;
                return Ok(None);
            }
            return Ok(Some(Reason::FirstBoot));
        }
        let interval = v["interval_h"]
            .as_u64()
            .filter(|n| *n > 0)
            .unwrap_or(24)
            .saturating_mul(3600);
        Ok((last > 0
            && v["periodic_scan"] == true
            && healthy
            && nfqws2_awg_profile::now().saturating_sub(last) >= interval)
            .then_some(Reason::Periodic))
    })
    .await
    .map_err(|e| io::Error::other(e.1))?;
    if let Some(reason) = reason {
        queue(s, reason).await?;
    }
    Ok(())
}
pub(crate) async fn shutdown(s: &Shared) {
    {
        let _lock = lifecycle::OPERATIONS.lock().await;
        s.auto_pick.stopping.store(true, Ordering::Release);
    }
    s.runs.shutdown().await;
    let task = s.auto_pick.task.lock().unwrap().take();
    if let Some(task) = task {
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests;
