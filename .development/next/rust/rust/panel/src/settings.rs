use crate::{
    data::or_default,
    http::{blocking, ApiError, ApiJson, Shared},
};
use axum::{
    extract::{Query, Request, State},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use nfqws2_monitor::{LogBuffer, Logs};
use nfqws2_store::Store;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Instant,
};

const FILE: &str = "settings.json";
pub struct Settings {
    http_logs: AtomicBool,
    trace: Mutex<String>,
}
impl Settings {
    pub(crate) fn trace_mode(&self) -> String {
        self.trace.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn reload(&self, store: &Store, logs: &LogBuffer) -> io::Result<()> {
        let current = Self::load(store, logs)?;
        self.http_logs
            .store(current.http_logs.load(Ordering::Acquire), Ordering::Release);
        *self.trace.lock().unwrap_or_else(|e| e.into_inner()) = current
            .trace
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        Ok(())
    }
    pub fn load(store: &Store, logs: &LogBuffer) -> io::Result<Self> {
        let map: Map<String, Value> = or_default(store, FILE)?;
        logs.set_enabled(map.get("logging_disabled").and_then(Value::as_bool) != Some(true));
        let trace = map
            .get("trace_mode")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("auto");
        Ok(Self {
            trace: Mutex::new(trace.into()),
            http_logs: AtomicBool::new(
                map.get("http_logs_disabled").and_then(Value::as_bool) != Some(true),
            ),
        })
    }
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/system/settings", get(get_settings).post(set_settings))
        .route("/api/logs", get(logs))
        .route("/api/logs/clear", post(clear))
}
pub async fn access_log(State(s): State<Shared>, req: Request, next: Next) -> Response {
    if !s.settings.http_logs.load(Ordering::Relaxed)
        || !s.logs.enabled()
        || !req.uri().path().starts_with("/api/")
    {
        return next.run(req).await;
    }
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let start = Instant::now();
    let res = next.run(req).await;
    s.logs.append(
        "http",
        "info",
        &format!("{method} {path} {}ms", start.elapsed().as_millis()),
    );
    res
}
fn view(s: &Shared) -> Json<Value> {
    Json(
        json!({"auth_enabled":s.auth.enabled(),"auth_forced_off":s.auth.forced_off(),"logging_enabled":s.logs.enabled(),
        "http_logs_enabled":s.settings.http_logs.load(Ordering::Acquire),"trace_mode":*s.settings.trace.lock().unwrap_or_else(|e|e.into_inner())}),
    )
}
async fn get_settings(State(s): State<Shared>) -> Json<Value> {
    view(&s)
}
#[derive(Deserialize)]
struct Input {
    auth_enabled: Option<bool>,
    logging_enabled: Option<bool>,
    http_logs_enabled: Option<bool>,
    trace_mode: Option<String>,
}
async fn set_settings(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Input>,
) -> Result<Json<Value>, ApiError> {
    let apply_trace = v.trace_mode.is_some();
    let current = s.clone();
    let result = blocking(move || {
        if let Some(enabled) = v.auth_enabled {
            s.auth.set_enabled(enabled)?;
        }
        if v.logging_enabled.is_some() || v.http_logs_enabled.is_some() || v.trace_mode.is_some() {
            s.store.transaction(|tx| {
                let mut map: Map<String, Value> = or_default(&s.store, FILE)?;
                if let Some(on) = v.logging_enabled {
                    map.insert("logging_disabled".into(), json!(!on));
                }
                if let Some(on) = v.http_logs_enabled {
                    map.insert("http_logs_disabled".into(), json!(!on));
                }
                let mode = v.trace_mode.as_deref().map(|m| match m {
                    "off" | "always" => m,
                    _ => "auto",
                });
                if let Some(m) = mode {
                    map.insert("trace_mode".into(), json!(m));
                }
                tx.save(FILE, &map)?;
                if let Some(on) = v.logging_enabled {
                    s.logs.set_enabled(on);
                }
                if let Some(on) = v.http_logs_enabled {
                    s.settings.http_logs.store(on, Ordering::Release);
                }
                if let Some(m) = mode {
                    *s.settings.trace.lock().unwrap_or_else(|e| e.into_inner()) = m.into();
                }
                Ok(())
            })?;
        }
        Ok(view(&s))
    })
    .await?;
    if apply_trace {
        crate::trace::awg::apply_policy(&current).await?;
    }
    Ok(result)
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct LogQuery {
    module: String,
    limit: String,
}
async fn logs(State(s): State<Shared>, Query(q): Query<LogQuery>) -> Json<Logs> {
    Json(
        s.logs
            .snapshot(&q.module, q.limit.parse().unwrap_or_default()),
    )
}
async fn clear(State(s): State<Shared>) -> Json<Value> {
    s.logs.clear();
    Json(json!({"status":"ok"}))
}
