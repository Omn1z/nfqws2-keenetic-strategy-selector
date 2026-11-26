use crate::http::{ApiError, Shared};
pub(crate) mod awg;
mod captured;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    fs::File,
    io,
    net::IpAddr,
    path::PathBuf,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{Child, ChildStdin, Command},
    time::timeout,
};

const MAX_PCAP: u64 = 2 * 1024 * 1024;
const HISTORY: usize = 3;
const HELLO_HISTORY: usize = 5;
struct Record {
    id: String,
    mode: &'static str,
    doc: Value,
    pending_candidates: Option<Value>,
    file: Option<Arc<File>>,
    control: Option<ChildStdin>,
}
#[derive(Default)]
struct Book {
    active: Option<Record>,
    finished: VecDeque<Record>,
}
impl Book {
    fn find(&self, mode: &str, id: &str) -> Option<&Record> {
        self.active
            .iter()
            .chain(self.finished.iter())
            .find(|r| r.mode == mode && r.id == id)
    }
}
#[derive(Default)]
pub struct TraceState {
    pub awg: awg::Service,
    jobs: Arc<Mutex<Book>>,
    busy: Arc<AtomicBool>,
    captures: Mutex<Vec<std::sync::Weak<File>>>,
    hello_files: Mutex<Vec<std::sync::Weak<File>>>,
}
impl TraceState {
    pub fn new(root: &std::path::Path) -> Self {
        Self {
            awg: awg::Service::new(root),
            jobs: Default::default(),
            busy: Default::default(),
            captures: Default::default(),
            hello_files: Default::default(),
        }
    }
    pub async fn shutdown(&self) {
        self.awg.shutdown().await;
        while self.busy.load(Ordering::Acquire) {
            if let Some(job) = self.jobs.lock().unwrap().active.as_mut() {
                job.control.take();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
impl Drop for TraceState {
    fn drop(&mut self) {
        if let Some(job) = self.jobs.lock().unwrap().active.as_mut() {
            job.control.take();
        }
    }
}
struct Permit(Arc<AtomicBool>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn helper() -> io::Result<PathBuf> {
    let name = format!("nfqws2-trace{}", std::env::consts::EXE_SUFFIX);
    #[cfg(not(feature = "compact"))]
    {
        let sibling = std::env::current_exe()?.with_file_name(&name);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    Ok(crate::assets::module_dir().join("trace").join(name))
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .merge(awg::routes())
        .route("/api/devices/{ip}/trace", post(start_trace))
        .route("/api/devices/{ip}/pcap", post(start_pcap))
        .route("/api/devices/{ip}/blobcap", post(start_hello))
        .route("/api/blobcap/{id}", get(hello))
        .route("/api/blobcap/{id}/save", post(captured::save))
        .route("/api/trace/{id}", get(trace))
        .route("/api/pcap/{id}", get(pcap))
        .route("/api/trace/{id}/cancel", post(cancel_trace))
        .route("/api/pcap/{id}/cancel", post(cancel_pcap))
        .route("/api/pcap/{id}/download", get(download))
}
async fn start_hello(
    State(s): State<Shared>,
    Path(ip): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    start(s, &ip, body, "hello").await
}
async fn hello(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    status(&s, "hello", &id)
}
async fn start_trace(
    State(s): State<Shared>,
    Path(ip): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    start(s, &ip, body, "trace").await
}
async fn start_pcap(
    State(s): State<Shared>,
    Path(ip): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    start(s, &ip, body, "pcap").await
}
fn bad(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}
async fn start(
    s: Shared,
    ip: &str,
    body: Bytes,
    mode: &'static str,
) -> Result<Json<Value>, ApiError> {
    let ip = ip.parse::<IpAddr>().map_err(|_| bad("неверный IP"))?;
    #[derive(Default, Deserialize)]
    struct Options {
        #[serde(default)]
        seconds: i64,
    }
    let opts: Options = if body.is_empty() {
        Options::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| bad(e.to_string()))?
    };
    let seconds = if (1..=120).contains(&opts.seconds) {
        opts.seconds as u64
    } else if mode == "hello" {
        20
    } else {
        30
    };
    let path = helper()?;
    if !path.is_file() {
        #[cfg(feature = "compact")]
        return Ok(Json(
            json!({"need_install":true,"package":"nfqws2-strategy-trace"}),
        ));
        #[cfg(not(feature = "compact"))]
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "установите модуль nfqws2-strategy-trace".into(),
        ));
    }
    let mut cmd = Command::new(path);
    cmd.arg(mode)
        .arg(ip.to_string())
        .arg(seconds.to_string())
        .args(&s.config.wan_ifaces);
    launch(&s.trace, cmd, ip, mode, seconds).await
}
async fn line(reader: &mut BufReader<tokio::process::ChildStderr>) -> io::Result<Option<Value>> {
    let mut buf = Vec::new();
    if reader.take(1024 * 1024).read_until(b'\n', &mut buf).await? == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        return Err(io::Error::other(
            "oversized or incomplete diagnostic message",
        ));
    }
    Ok(Some(serde_json::from_slice(&buf)?))
}
async fn launch(
    state: &TraceState,
    mut cmd: Command,
    ip: IpAddr,
    mode: &'static str,
    seconds: u64,
) -> Result<Json<Value>, ApiError> {
    state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| bad("диагностика устройства уже запущена"))?;
    let permit = Permit(state.busy.clone());
    // The last file handle is the lifetime of the capture. No named PCAP
    // survives process exit, eviction, cancellation, or a failed operation.
    let file = if matches!(mode, "hello" | "pcap") {
        let (pool, capacity) = if mode == "hello" {
            (&state.hello_files, HELLO_HISTORY)
        } else {
            (&state.captures, HISTORY)
        };
        let mut slots = pool.lock().unwrap();
        slots.retain(|f| f.strong_count() > 0);
        if slots.len() > capacity {
            return Err(bad("завершите текущие операции с захватами"));
        }
        let file = Arc::new(tempfile::tempfile()?);
        slots.push(Arc::downgrade(&file));
        Some(file)
    } else {
        None
    };
    cmd.kill_on_drop(true)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(match &file {
            Some(f) => Stdio::from(f.try_clone()?),
            None => Stdio::null(),
        });
    let mut child = cmd.spawn()?;
    let mut reader = BufReader::new(child.stderr.take().unwrap());
    let first = timeout(Duration::from_secs(5), line(&mut reader))
        .await
        .map_err(|_| bad("модуль диагностики не ответил"))??
        .ok_or_else(|| bad("модуль диагностики завершился"))?;
    if first["need_install"] == true && first["package"] == "tcpdump" {
        return Ok(Json(json!({"need_install":true,"package":"tcpdump"})));
    }
    if first["ready"] != true {
        return Err(bad(first["error"]
            .as_str()
            .unwrap_or("устройство недоступно")));
    }
    let id = nfqws2_store::new_id()?;
    let mut doc = json!({"id":id,"ip":ip.to_string(),"seconds":seconds,"status":"running","cancellable":true,"started_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),"elapsed_ms":0});
    if mode == "pcap" {
        doc["iface"] = first["iface"].clone();
        for name in ["packets", "dropped", "size_bytes"] {
            doc[name] = json!(0);
        }
    } else if mode == "hello" {
        doc["iface"] = first["iface"].clone();
        doc["candidates"] = json!([]);
        doc["observations"] = json!({});
        doc["metadata_only"] = json!(first["client_hello_records"] != true);
        doc["cancellable"] = json!(false);
    } else {
        doc["events"] = json!([]);
        doc["conns"] = json!([]);
    }
    state.jobs.lock().unwrap().active = Some(Record {
        id,
        mode,
        doc: doc.clone(),
        pending_candidates: None,
        file,
        control: child.stdin.take(),
    });
    let jobs = state.jobs.clone();
    tokio::spawn(async move {
        supervise(jobs, child, reader, seconds, permit).await;
    });
    Ok(Json(doc))
}
async fn updates(
    jobs: &Mutex<Book>,
    reader: &mut BufReader<tokio::process::ChildStderr>,
) -> io::Result<(String, String)> {
    let mut terminal = None;
    while let Some(mut update) = line(reader).await? {
        if !update.is_object() {
            return Err(io::Error::other("invalid diagnostic message"));
        }
        if terminal.is_some() {
            return Err(io::Error::other("extra diagnostic output"));
        }
        let mut mgr = jobs.lock().unwrap();
        let record = mgr
            .active
            .as_mut()
            .ok_or_else(|| io::Error::other("missing diagnostic job"))?;
        if let Some(n) = update["elapsed_ms"].as_u64() {
            record.doc["elapsed_ms"] = json!(n);
        }
        if record.mode == "pcap" {
            for name in ["size_bytes", "packets", "dropped"] {
                if let Some(n) = update[name].as_u64() {
                    record.doc[name] = json!(n);
                }
            }
            if record.doc["size_bytes"].as_u64().unwrap_or(0) > MAX_PCAP {
                return Err(io::Error::other("PCAP size limit exceeded"));
            }
        } else if record.mode == "hello" {
            if update.get("candidates").is_some() {
                if update["status"] != "done" && update["status"] != "cancelled" {
                    return Err(io::Error::other("unexpected TLS candidates"));
                }
                let rows = update["candidates"].take();
                captured::check(&rows, record)?;
                record.pending_candidates = Some(rows);
            }
            if let Some(observed) = update.get("observations") {
                let rows = observed
                    .as_object()
                    .ok_or_else(|| io::Error::other("invalid TLS summary"))?;
                if rows.len() > 128
                    || !rows.iter().all(|(ip, value)| {
                        ip.parse::<IpAddr>().is_ok()
                            && value.as_object().is_some_and(|obj| obj.len() == 2)
                            && value["headers"].as_u64().is_some_and(|n| n > 0)
                            && value["record_bytes"].is_u64()
                    })
                {
                    return Err(io::Error::other("invalid TLS destination counters"));
                }
                record.doc["observations"] = update["observations"].take();
            }
        } else {
            if let Some(events) = update["events"].as_array_mut() {
                let all = record.doc["events"].as_array_mut().unwrap();
                if events.len() + all.len() > 2048 {
                    return Err(io::Error::other("trace event limit exceeded"));
                }
                all.append(events);
            }
            if let Some(conns) = update["conns"].as_array_mut() {
                if conns.len() > 512 {
                    return Err(io::Error::other("trace flow limit exceeded"));
                }
                record.doc["conns"] = Value::Array(std::mem::take(conns));
            }
        }
        if let Some(v) = update["limited"].as_bool() {
            record.doc["limited"] = json!(v);
        }
        if let Some(status) = update["status"].as_str() {
            if !matches!(status, "done" | "cancelled" | "error") {
                return Err(io::Error::other("invalid diagnostic status"));
            }
            terminal = Some((
                status.into(),
                update["error"].as_str().unwrap_or_default().to_owned(),
            ));
        }
    }
    terminal.ok_or_else(|| io::Error::other("diagnostic helper exited before final status"))
}
async fn supervise(
    jobs: Arc<Mutex<Book>>,
    mut child: Child,
    mut reader: BufReader<tokio::process::ChildStderr>,
    seconds: u64,
    permit: Permit,
) {
    let result = timeout(
        Duration::from_secs(seconds + 4),
        updates(&jobs, &mut reader),
    )
    .await;
    if let Some(job) = jobs.lock().unwrap().active.as_mut() {
        job.control.take();
    }
    drop(reader);
    let mut outcome = result.unwrap_or_else(|_| Err(io::Error::other("trace timeout")));
    match timeout(Duration::from_secs(2), child.wait()).await {
        Ok(Ok(code)) if code.success() => (),
        Ok(Ok(_)) if outcome.as_ref().is_ok_and(|(s, _)| s == "error") => (),
        Ok(Ok(code)) => outcome = Err(io::Error::other(format!("diagnostic helper {code}"))),
        Ok(Err(e)) => outcome = Err(e),
        Err(_) => {
            let _ = child.kill().await;
            outcome = Err(io::Error::other("diagnostic helper did not stop"));
        }
    }
    let mut mgr = jobs.lock().unwrap();
    if let Some(mut job) = mgr.active.take() {
        let (mut status, mut err) = outcome.unwrap_or_else(|e| ("error".into(), e.to_string()));
        if status == "done" && job.mode == "pcap" {
            let size = job
                .file
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .map_or(0, |m| m.len());
            if !(24..=MAX_PCAP).contains(&size) || Some(size) != job.doc["size_bytes"].as_u64() {
                status = "error".into();
                err = "incomplete PCAP".into();
            }
        }
        if let Some(rows) = job.pending_candidates.take() {
            if status == "done" {
                job.doc["metadata_only"] = json!(false);
                job.doc["candidates"] = rows;
            }
        }
        if status != "done" || (job.mode == "hello" && job.doc["candidates"] == json!([])) {
            job.file.take();
        }
        job.doc["status"] = json!(status);
        if !err.is_empty() {
            job.doc["error"] = json!(err);
        }
        let is_hello = job.mode == "hello";
        let capacity = if is_hello { HELLO_HISTORY } else { HISTORY };
        let same_history = |r: &&Record| (r.mode == "hello") == is_hello;
        if mgr.finished.iter().filter(same_history).count() >= capacity {
            if let Some(i) = mgr.finished.iter().position(|r| same_history(&r)) {
                mgr.finished.remove(i);
            }
        }
        mgr.finished.push_back(job);
    }
    drop(permit);
}
#[cfg(test)]
mod tests;
fn status(s: &Shared, mode: &str, id: &str) -> Result<Json<Value>, ApiError> {
    s.trace
        .jobs
        .lock()
        .unwrap()
        .find(mode, id)
        .map(|r| Json(r.doc.clone()))
        .ok_or_else(missing)
}
fn missing() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "диагностика не найдена".into())
}
async fn trace(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    status(&s, "trace", &id)
}
async fn pcap(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    status(&s, "pcap", &id)
}
fn cancel(s: &Shared, mode: &str, id: &str) -> Result<Json<Value>, ApiError> {
    let mut jobs = s.trace.jobs.lock().unwrap();
    let r = jobs
        .active
        .as_mut()
        .filter(|r| r.id == id && r.mode == mode)
        .ok_or_else(|| bad("диагностика не активна"))?;
    r.control.take();
    Ok(Json(json!({"status":"cancelling"})))
}
async fn cancel_trace(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    cancel(&s, "trace", &id)
}
async fn cancel_pcap(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    cancel(&s, "pcap", &id)
}
async fn download(State(s): State<Shared>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let (file, size, ip) = {
        let jobs = s.trace.jobs.lock().unwrap();
        let r = jobs
            .find("pcap", &id)
            .filter(|r| r.doc["status"] == "done")
            .ok_or_else(missing)?;
        (
            r.file.clone().ok_or_else(missing)?,
            r.doc["size_bytes"].as_u64().unwrap_or(0),
            r.doc["ip"].as_str().unwrap().replace(':', "_"),
        )
    };
    let body = futures_util::stream::try_unfold((file, 0u64), move |(f, offset)| async move {
        if offset == size {
            return Ok(None);
        }
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; (size - offset).min(32768) as usize];
            let n = read_at(&f, &mut buf, offset)?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            buf.truncate(n);
            Ok(Some((Bytes::from(buf), (f, offset + n as u64))))
        })
        .await
        .map_err(io::Error::other)?
    });
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/vnd.tcpdump.pcap")
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"pcap-{ip}-{id}.pcap\""),
        )
        .header(header::CONTENT_LENGTH, size)
        .body(Body::from_stream(body))
        .unwrap())
}
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}
