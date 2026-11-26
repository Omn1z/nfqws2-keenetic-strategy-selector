use crate::{
    data,
    http::{blocking, ApiError, ApiJson, Shared},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Deserialize, Serialize)]
struct Target {
    host: String,
    blocked: bool,
    verdict: String,
    code: u16,
    size: u64,
    ttfb_ms: u64,
    speed_bps: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    err: String,
}
#[derive(Clone, Serialize)]
struct Snapshot {
    id: String,
    list_id: String,
    list_name: String,
    threads: usize,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    total: usize,
    done: usize,
    started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at: Option<u64>,
    targets: Vec<Target>,
}
struct Running {
    snapshot: Snapshot,
    control: Option<ChildStdin>,
}
#[derive(Default)]
struct Manager {
    active: Option<Running>,
    last: Option<Snapshot>,
}
#[derive(Default)]
pub struct BlockCheckState {
    inner: Arc<Mutex<Manager>>,
}
impl BlockCheckState {
    pub async fn shutdown(&self) {
        loop {
            {
                let mut mgr = self.inner.lock().unwrap();
                let Some(run) = mgr.active.as_mut() else {
                    return;
                };
                run.control.take();
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}
impl Drop for BlockCheckState {
    fn drop(&mut self) {
        if let Some(run) = self.inner.lock().unwrap().active.as_mut() {
            run.control.take();
        }
    }
}
pub(crate) struct Permit(Arc<AtomicBool>);
impl Permit {
    pub(crate) fn acquire(flag: &Arc<AtomicBool>) -> io::Result<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| invalid("a run is already in progress"))?;
        Ok(Self(flag.clone()))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn executable() -> io::Result<PathBuf> {
    let filename = format!("nfqws2-blockcheck{}", std::env::consts::EXE_SUFFIX);
    #[cfg(feature = "compact")]
    {
        Ok(crate::assets::module_dir()
            .join("blockcheck")
            .join(filename))
    }
    #[cfg(not(feature = "compact"))]
    {
        Ok(std::env::current_exe()?.with_file_name(filename))
    }
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/blockcheck", post(start))
        .route("/api/blockcheck/{id}", get(status))
        .route("/api/blockcheck/{id}/cancel", post(cancel))
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct Start {
    list_id: String,
    targets: Vec<String>,
    threads: i32,
}
#[derive(Serialize)]
struct Job<'a> {
    targets: &'a [String],
    threads: usize,
    port_base: i32,
    ports_per_worker: i32,
    wan_ifaces: &'a [String],
}
async fn start(
    State(s): State<Shared>,
    ApiJson(req): ApiJson<Start>,
) -> Result<Json<Snapshot>, ApiError> {
    let path = executable()?;
    if !path.is_file() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "установите модуль nfqws2-strategy-blockcheck".into(),
        ));
    }
    let mut recover = Command::new(&path);
    recover.arg("--recover");
    start_with(s, req, Command::new(path), Some(recover)).await
}
async fn start_with(
    s: Shared,
    req: Start,
    cmd: Command,
    recover: Option<Command>,
) -> Result<Json<Snapshot>, ApiError> {
    let snapshot = blocking(move || {
        let (targets, list_name) = if req.list_id.is_empty() {
            (data::clean_lines(req.targets), "произвольный набор".into())
        } else {
            let list = data::list(&s.store, &req.list_id).map_err(|_| invalid("list not found"))?;
            let mut targets = list.domains.unwrap_or_default();
            targets.extend(list.ips.unwrap_or_default());
            (targets, list.name)
        };
        if targets.is_empty() {
            return Err(invalid("no targets"));
        }
        let threads = (if req.threads <= 0 {
            4
        } else {
            req.threads.min(8)
        } as usize)
            .min(targets.len());
        let snapshot = Snapshot {
            id: nfqws2_store::new_id()?,
            list_id: req.list_id,
            list_name,
            threads,
            status: "running".into(),
            error: String::new(),
            total: targets.len(),
            done: 0,
            started_at: now(),
            finished_at: None,
            targets: Vec::new(),
        };
        let job = Job {
            targets: &targets,
            threads,
            port_base: s.config.port_base,
            ports_per_worker: s.config.ports_per_worker,
            wan_ifaces: &s.config.wan_ifaces,
        };
        launch(cmd, recover, &s.blockcheck, &s.active_test, &job, snapshot)
    })
    .await?;
    Ok(Json(snapshot))
}
#[cfg(test)]
mod tests;
fn launch(
    mut cmd: Command,
    recover: Option<Command>,
    state: &BlockCheckState,
    active: &Arc<AtomicBool>,
    job: &Job<'_>,
    snapshot: Snapshot,
) -> io::Result<Snapshot> {
    let permit = Permit::acquire(active)?;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut control = child.stdin.take().unwrap();
    let mut writer = io::BufWriter::new(&mut control);
    let written = serde_json::to_writer(&mut writer, job)
        .map_err(io::Error::from)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush());
    drop(writer);
    if let Err(e) = written {
        drop(control);
        let _ = child.wait();
        return Err(e);
    }
    state.inner.lock().unwrap().active = Some(Running {
        control: Some(control),
        snapshot: snapshot.clone(),
    });
    let inner = state.inner.clone();
    tokio::task::spawn_blocking(move || supervise(&inner, &mut child, recover, permit));
    Ok(snapshot)
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Event {
    Target {
        target: Target,
    },
    End {
        status: String,
        #[serde(default)]
        error: String,
    },
}
fn consume(reader: &mut impl BufRead, inner: &Mutex<Manager>) -> io::Result<(String, String)> {
    let mut terminal = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.take(65536).read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.last() != Some(&b'\n') || terminal.is_some() {
            return Err(io::Error::other("invalid BlockCheck helper output"));
        }
        match serde_json::from_slice::<Event>(&line)? {
            Event::End { status, error }
                if matches!(status.as_str(), "done" | "cancelled" | "error") =>
            {
                terminal = Some((status, error))
            }
            Event::Target { target } => {
                let mut mgr = inner.lock().unwrap();
                let run = &mut mgr
                    .active
                    .as_mut()
                    .ok_or_else(|| io::Error::other("missing active check"))?
                    .snapshot;
                if run.done >= run.total {
                    return Err(io::Error::other("excess BlockCheck results"));
                }
                run.targets.push(target);
                run.done += 1;
            }
            _ => return Err(io::Error::other("invalid BlockCheck helper status")),
        }
    }
    terminal.ok_or_else(|| io::Error::other("BlockCheck helper stopped without a verified result"))
}
fn supervise(inner: &Mutex<Manager>, child: &mut Child, recover: Option<Command>, permit: Permit) {
    let mut read = BufReader::new(child.stdout.take().unwrap());
    let result = consume(&mut read, inner);
    if let Some(run) = inner.lock().unwrap().active.as_mut() {
        run.control.take();
    }
    // Close output if malformed so the helper can abandon in-flight probes.
    drop(read);
    let exit = child.wait();
    let incomplete = result.is_err() || exit.as_ref().map_or(true, |s| s.code().is_none());
    let (mut status, mut error) = result.unwrap_or_else(|e| ("error".into(), e.to_string()));
    if status != "error" && !exit.is_ok_and(|e| e.success()) {
        status = "error".into();
        error = "BlockCheck helper exited unsuccessfully".into();
    }
    // A signal can terminate the process between two successful iptables
    // commands. A fresh helper removes only our reserved chains, under the
    // same filesystem lock. Keep the panel's operation permit until it exits.
    if incomplete || error.contains("firewall rollback:") {
        if let Some(mut cmd) = recover {
            match cmd.stdin(Stdio::null()).output() {
                Ok(out) if !out.status.success() => error.push_str(&format!(
                    "; recovery {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                )),
                Err(e) => error.push_str(&format!("; recovery: {e}")),
                _ => (),
            }
        }
    }
    let mut mgr = inner.lock().unwrap();
    let Some(r) = mgr.active.take() else {
        return;
    };
    let mut snapshot = r.snapshot;
    if status == "done" && snapshot.done != snapshot.total {
        status = "error".into();
        error = "incomplete BlockCheck results".into();
    }
    if status == "error" {
        snapshot.targets.clear();
        snapshot.done = 0;
    }
    snapshot
        .targets
        .sort_by(|a, b| b.blocked.cmp(&a.blocked).then(a.host.cmp(&b.host)));
    snapshot.finished_at = Some(now());
    snapshot.status = status;
    snapshot.error = error;
    mgr.last = Some(snapshot);
    drop(permit);
}
async fn status(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Snapshot>, ApiError> {
    let mgr = s.blockcheck.inner.lock().unwrap();
    mgr.active
        .as_ref()
        .map(|r| &r.snapshot)
        .filter(|r| r.id == id)
        .or_else(|| mgr.last.as_ref().filter(|r| r.id == id))
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "block check not found".into()))
}
async fn cancel(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let mut mgr = s.blockcheck.inner.lock().unwrap();
    let run = mgr
        .active
        .as_mut()
        .filter(|r| r.snapshot.id == id)
        .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "block check not active".into()))?;
    run.control.take();
    Ok(Json(json!({"status":"cancelling"})))
}
