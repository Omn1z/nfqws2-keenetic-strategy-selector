use crate::http::{blocking, ApiError, ApiJson, AppState, Shared};
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use nfqws2_awg_profile::fallback_servers;
use nfqws2_store::Store;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io,
    sync::Weak,
    time::{Duration, Instant},
};
const FILE: &str = "tgproxy.json";
#[derive(Default)]
pub(crate) struct Cache(tokio::sync::Mutex<Option<(Instant, Option<String>)>>);
fn preference(raw: &str) -> io::Result<&str> {
    let v = raw.trim();
    match v {
        "" | "off" => Ok("off"),
        "warp" | "auto" => Ok("auto"),
        _ => {
            let id = v.strip_prefix("awg:").unwrap_or(v);
            if id.is_empty()
                || id.len() > 96
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "некорректный идентификатор профиля VPN",
                ));
            }
            Ok(v)
        }
    }
}
fn document(db: &Store) -> io::Result<Value> {
    match db.read::<Value>(FILE) {
        Ok(v)
            if v.is_object()
                && (v
                    .get("awg_fallback")
                    .is_none_or(|s| s.is_null() || s.is_string())) =>
        {
            Ok(v)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "не удалось прочитать tgproxy.json",
        )),
    }
}
fn value(doc: &Value) -> io::Result<&str> {
    preference(doc["awg_fallback"].as_str().unwrap_or(""))
}
pub(crate) async fn selected(owner: &Weak<AppState>) -> io::Result<Option<String>> {
    let s = owner.upgrade().ok_or(io::ErrorKind::Interrupted)?;
    let requested = Instant::now();
    let mut lock = s.proxy_fallback.0.lock().await;
    if let Some((_, iface)) = lock.as_ref().filter(|(t, iface)| {
        *t >= requested || iface.is_none() && t.elapsed() < Duration::from_secs(1)
    }) {
        return Ok(iface.clone());
    }
    let shared = s.clone();
    let iface = tokio::task::spawn_blocking(move || {
        let cfg = document(&shared.store)?;
        let sel = value(&cfg)?;
        if sel == "off" {
            return Ok::<_, io::Error>(None);
        }
        let id = (sel != "auto").then(|| sel.strip_prefix("awg:").unwrap_or(sel));
        Ok(fallback_servers(&shared.store, &shared.awg_runtime, id)?
            .into_iter()
            .find(|p| p.connected)
            .map(|p| p.client_iface))
    })
    .await
    .map_err(io::Error::other)??;
    *lock = Some((Instant::now(), iface.clone()));
    Ok(iface)
}
pub(super) fn routes() -> Router<Shared> {
    Router::new().route("/api/proxy/awg-fallback", get(show).post(save))
}
async fn show(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let doc = document(&s.store)?;
        Ok(Json(
            json!({"value":value(&doc)?,"servers":fallback_servers(&s.store,&s.awg_runtime,None)?}),
        ))
    })
    .await
}
#[derive(Deserialize)]
struct Set {
    value: String,
}
async fn save(
    State(s): State<Shared>,
    ApiJson(form): ApiJson<Set>,
) -> Result<Json<Value>, ApiError> {
    let value = preference(&form.value)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?
        .to_owned();
    tokio::spawn(async move {
        let mut cache = s.proxy_fallback.0.lock().await;
        let shared = s.clone();
        let view = blocking(move || {
            let servers = fallback_servers(&shared.store, &shared.awg_runtime, None)?;
            shared.store.transaction(|tx| {
                let mut doc = document(&shared.store)?;
                doc["awg_fallback"] = json!(value);
                tx.save(FILE, &doc)
            })?;
            Ok(Json(json!({"value":value,"servers":servers})))
        })
        .await?;
        *cache = None;
        Ok(view)
    })
    .await
    .map_err(io::Error::other)?
}
// The optional worker gets only a private local channel returning an AWG
// interface name. The panel keeps profile credentials and validates its UAPI.
pub(super) struct Bridge {
    #[cfg(target_os = "linux")]
    _dir: tempfile::TempDir,
    #[cfg(target_os = "linux")]
    task: tokio::task::JoinHandle<()>,
    pub path: Option<std::path::PathBuf>,
}
impl Bridge {
    pub fn start(owner: Weak<AppState>) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            use tokio::io::AsyncWriteExt;
            let dir = tempfile::Builder::new()
                .prefix("nfq-tg-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?;
            let path = dir.path().join("route");
            let socket = tokio::net::UnixListener::bind(&path)?;
            let task = tokio::spawn(async move {
                while let Ok((mut client, _)) = socket.accept().await {
                    let iface = selected(&owner).await.ok().flatten().unwrap_or_default();
                    let _ = tokio::time::timeout(
                        Duration::from_millis(300),
                        client.write_all(iface.as_bytes()),
                    )
                    .await;
                }
            });
            Ok(Self {
                _dir: dir,
                task,
                path: Some(path),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = owner;
            Ok(Self { path: None })
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
