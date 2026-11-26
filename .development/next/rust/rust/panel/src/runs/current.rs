use crate::{
    blockcheck::Permit,
    http::{ApiError, ApiJson, Shared},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io, process::Stdio, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{ChildStdin, Command},
    sync::{watch, Mutex},
    time::timeout,
};

struct Active {
    id: String,
    dir: Arc<TempDir>,
    control: Option<ChildStdin>,
    cancel: watch::Sender<bool>,
}
#[derive(Default, Clone)]
pub(crate) struct RunsState {
    active: Arc<Mutex<Option<Active>>>,
}
impl RunsState {
    pub(crate) async fn live(&self) -> Option<super::Live> {
        self.active
            .lock()
            .await
            .as_ref()
            .map(|a| (a.id.clone(), a.dir.clone()))
    }
    pub(crate) async fn shutdown(&self) {
        let mut slot = self.active.lock().await;
        if let Some(a) = slot.as_mut() {
            a.control.take();
            a.cancel.send_replace(true);
            let signal = a.cancel.clone();
            drop(slot);
            signal.closed().await;
        }
    }
}

fn command(matrix: bool) -> io::Result<Command> {
    worker_command(
        if matrix {
            "measure-matrix"
        } else {
            "measure-current"
        },
        if matrix { "measure-matrix" } else { "measure" },
    )
}
fn worker_command(embedded_verb: &str, helper_verb: &str) -> io::Result<Command> {
    #[cfg(all(feature = "embedded-runs", not(feature = "compact")))]
    {
        let mut cmd = Command::new(std::env::current_exe()?);
        let _ = helper_verb;
        cmd.arg(embedded_verb);
        Ok(cmd)
    }
    #[cfg(any(not(feature = "embedded-runs"), feature = "compact"))]
    {
        let path = super::executable();
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Установите пакет nfqws2-strategy-runs",
            ));
        }
        let mut cmd = Command::new(path);
        let _ = embedded_verb;
        cmd.arg(helper_verb);
        Ok(cmd)
    }
}
pub(crate) async fn recover_matrix() -> io::Result<()> {
    let mut cmd = worker_command("recover-matrix", "recover-matrix")?;
    let status = timeout(
        Duration::from_secs(60),
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| io::Error::other("истекло время очистки тестовой матрицы"))??;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "не удалось очистить правила тестовой матрицы",
        ))
    }
}
pub(crate) fn matrix_available() -> bool {
    cfg!(target_os = "linux") && command(true).is_ok()
}
pub(super) async fn capabilities() -> Json<Value> {
    let mut modes = vec!["current_https"];
    if matrix_available() {
        modes.push("strategy_matrix");
    }
    Json(json!({"modes":modes,"max_targets":64,"max_threads":8,"installed":command(false).is_ok()}))
}
fn bad(e: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, e.to_string())
}

pub(super) async fn start(
    State(s): State<Shared>,
    ApiJson(req): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    match req.get("mode") {
        Some(mode) if mode == "current_https" => launch(s, req, false, None, false).await.map(Json),
        None | Some(Value::Null) if req.is_object() => {
            let input = serde_json::from_value(req).map_err(bad)?;
            let state = s.clone();
            let plan = crate::http::blocking(move || super::legacy::prepare(&state, input))
                .await
                .map_err(|err| bad(err.1))?;
            let permit = Arc::new(Permit::acquire(&s.active_test).map_err(bad)?);
            // Once accepted, a disconnected HTTP client does not abandon a
            // half-started matrix or its exact queue recovery.
            tokio::spawn(launch(s, plan, true, Some(permit), true))
                .await
                .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "worker stopped".into()))?
                .map(Json)
        }
        _ => Err(bad("Неизвестный режим прогона.")),
    }
}
pub(crate) async fn start_matrix(
    s: Shared,
    req: Value,
    permit: Arc<Permit>,
) -> Result<Value, ApiError> {
    launch(s, req, true, Some(permit), false).await
}
async fn launch(
    s: Shared,
    req: Value,
    matrix: bool,
    permit: Option<Arc<Permit>>,
    pause_acceleration: bool,
) -> Result<Value, ApiError> {
    let mut cmd =
        command(matrix).map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let mut data = serde_json::to_vec(&req).map_err(bad)?;
    if data.len() >= 1 << 20 {
        return Err(bad("Запрос прогона превышает 1 МиБ."));
    }
    data.push(b'\n');
    let permit = match permit {
        Some(permit) => permit,
        None => Arc::new(Permit::acquire(&s.active_test).map_err(bad)?),
    };
    let acceleration = if pause_acceleration {
        let state = s.clone();
        Some(
            crate::http::blocking(move || {
                crate::engine::pause_acceleration(&state.store, &state.config)
            })
            .await?,
        )
    } else {
        None
    };
    let id = nfqws2_store::new_id()?;
    let dir = Arc::new(tempfile::Builder::new().prefix("n2s-runs-").tempdir()?);
    let mut child = cmd
        .arg(&s.config.data_dir)
        .arg(&id)
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut control = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap()).take(64 << 10);
    let mut response = Vec::new();
    let handshake: Result<Value, ApiError> = async {
        timeout(Duration::from_secs(8), async {
            control.write_all(&data).await?;
            reader.read_until(b'\n', &mut response).await?;
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| bad("Исполнитель не подтвердил запуск за 8 секунд."))??;
        let reply: Value = serde_json::from_slice(&response)
            .map_err(|_| bad("Исполнитель не вернул начальное состояние."))?;
        reply
            .get("started")
            .filter(|r| {
                r["id"] == id
                    && r["status"] == "running"
                    && r["mode"]
                        == if matrix {
                            "strategy_matrix"
                        } else {
                            "current_https"
                        }
            })
            .cloned()
            .ok_or_else(|| {
                bad(reply["error"]
                    .as_str()
                    .unwrap_or("Неверный ответ исполнителя."))
            })
    }
    .await;
    let initial = match handshake {
        Ok(initial) => initial,
        Err(error) => {
            drop(control);
            if timeout(Duration::from_secs(30), child.wait())
                .await
                .is_err()
            {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            if matrix {
                if let Err(e) = recover_matrix().await {
                    return Err(ApiError(error.0, format!("{}; очистка: {e}", error.1)));
                }
            }
            return Err(error);
        }
    };
    let (signal, mut cancelled) = watch::channel(false);
    let state = s.runs.clone();
    let report_id = id.clone();
    *state.active.lock().await = Some(Active {
        id,
        dir,
        control: Some(control),
        cancel: signal,
    });
    tokio::spawn(async move {
        let _permit = permit;
        let _acceleration = acceleration;
        let exit = tokio::select! {
            result=child.wait()=>result,
            _=cancelled.changed()=>{
                // Matrix workers remove their owned rules before exiting.
                match timeout(Duration::from_secs(30),child.wait()).await {
                    Ok(result) => result,
                    Err(_) => { let _=child.kill().await; child.wait().await },
                }
            }
        };
        if matrix && !exit.is_ok_and(|status| status.success()) {
            let mut message = "исполнитель матрицы завершился с ошибкой".to_owned();
            if let Err(e) = recover_matrix().await {
                message.push_str(&format!("; очистка: {e}"));
            }
            s.logs.append("automation", "warn", &message);
            // Never apply a persisted 'done' report from a failed child.
            let _ = crate::http::blocking(move || {
                s.store.transaction(|tx| {
                    let file = format!("runs/{report_id}.json");
                    let mut report = s
                        .store
                        .read_limited::<Value>(&file, 16 << 20)
                        .unwrap_or_else(
                            |_| json!({"id":report_id,"mode":"strategy_matrix","results":[]}),
                        );
                    report["status"] = json!("error");
                    report["error"] = json!(message);
                    tx.save(&file, &report)
                })
            })
            .await;
        }
        state.active.lock().await.take();
    });
    Ok(initial)
}
pub(crate) async fn cancel_matching(s: &Shared, id: &str) {
    let mut slot = s.runs.active.lock().await;
    if let Some(a) = slot.as_mut().filter(|a| a.id == id) {
        a.control.take();
        a.cancel.send_replace(true);
    }
}
pub(super) async fn cancel(
    State(s): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut slot = s.runs.active.lock().await;
    let a = slot
        .as_mut()
        .filter(|a| a.id == id)
        .ok_or_else(|| bad("Прогон не выполняется."))?;
    a.control.take();
    a.cancel.send_replace(true);
    Ok(Json(json!({"status":"cancelling"})))
}
#[derive(Deserialize)]
pub(super) struct Threads {
    threads: usize,
}
pub(super) async fn threads(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Threads>,
) -> Result<Json<Value>, ApiError> {
    if !(1..=8).contains(&input.threads) {
        return Err(bad("Выберите от 1 до 8 потоков."));
    }
    let mut slot = s.runs.active.lock().await;
    let stdin = slot
        .as_mut()
        .filter(|a| a.id == id)
        .and_then(|a| a.control.as_mut())
        .ok_or_else(|| bad("Прогон не выполняется."))?;
    timeout(
        Duration::from_secs(1),
        stdin.write_all(format!("{}\n", input.threads).as_bytes()),
    )
    .await
    .map_err(|_| bad("Исполнитель занят."))??;
    Ok(Json(json!({"threads":input.threads})))
}
