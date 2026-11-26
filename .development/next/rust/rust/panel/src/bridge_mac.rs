//! Local administration of the router's own LAN bridge address.
mod device;
mod journal;
#[cfg(test)]
mod tests;
mod vendors;

use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::header,
    routing::{get, post},
    Json, Router,
};
use nfqws2_router_command::{Runner, System};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const FILE: &str = "arp_spoofing.json";
const RECEIPT: &str = "lan_bridge_mac.json";
const LIMIT: u64 = 64 * 1024;
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn default_on_missing<T: Default>(result: io::Result<T>) -> io::Result<T> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        other => other,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
struct Config {
    enabled: bool,
    mac: String,
    vendor_id: String,
    prefix: String,
    #[serde(deserialize_with = "null_ifaces")]
    ifaces: Vec<String>,
    updated_at: i64,
}
fn null_ifaces<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            mac: String::new(),
            vendor_id: "huawei".into(),
            prefix: "00:18:82".into(),
            ifaces: Vec::new(),
            updated_at: 0,
        }
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    config: Config,
    applied_at: i64,
    last_error: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    original_macs: BTreeMap<String, String>,
}
fn saved(store: &Store) -> io::Result<Saved> {
    default_on_missing(store.read_limited(FILE, LIMIT))
        .map_err(|_| io::Error::other("Повреждено сохранённое состояние LAN-моста"))
}
fn receipt(store: &Store) -> io::Result<journal::Receipt> {
    default_on_missing(store.read_runtime(RECEIPT, LIMIT))
        .map_err(|_| io::Error::other("Повреждён локальный журнал LAN-моста"))
}
pub struct Service<R = System> {
    device: device::Device<R>,
}
impl Service {
    pub fn new(root: &Path) -> Self {
        Self {
            device: device::Device::new(root, System),
        }
    }
}
impl<R: Runner> Service<R> {
    pub(crate) fn same_ipv6_lan(
        &self,
        wan: &[String],
        local: std::net::Ipv6Addr,
        peer: std::net::Ipv6Addr,
    ) -> bool {
        self.device.same_ipv6_lan(wan, local, peer).unwrap_or(false)
    }

    fn view(&self, store: &Store, wan: &[String]) -> io::Result<Value> {
        let state = saved(store)?;
        let local = receipt(store)?;
        let interfaces = self.device.interfaces(wan)?;
        let suggested: Vec<_> = interfaces
            .iter()
            .filter(|i| i.suggested)
            .map(|i| i.name.as_str())
            .collect();
        let (effective, diagnostic) = if local.pending.is_some() {
            ("unknown", "Требуется восстановить незавершённую операцию")
        } else if !state.config.enabled {
            ("disabled", "")
        } else {
            let names: Vec<_> = if state.config.ifaces.is_empty() {
                suggested.clone()
            } else {
                state.config.ifaces.iter().map(String::as_str).collect()
            };
            let mut status = ("matches", "");
            if names.is_empty() {
                status = ("unknown", "Действующий LAN-мост не определён");
            }
            for name in names {
                let Ok(iface) = self.device.selected(&interfaces, name) else {
                    status = ("unknown", "LAN-мост недоступен для проверки");
                    break;
                };
                match self.device.current(iface) {
                    Ok(mac) if mac.eq_ignore_ascii_case(&state.config.mac) => (),
                    Ok(_) => {
                        status = ("mismatch", "Текущий MAC моста отличается от сохранённого");
                        break;
                    }
                    Err(_) => {
                        status = ("unknown", "Не удалось подтвердить текущий MAC моста");
                        break;
                    }
                }
            }
            status
        };
        // Only public config and the observed interface fields enter the reply.
        // Legacy command errors may contain raw firmware output.
        let last_error = if !diagnostic.is_empty() {
            diagnostic
        } else if !state.last_error.is_empty() {
            "Предыдущее применение адреса завершилось ошибкой"
        } else {
            ""
        };
        Ok(
            json!({"config":state.config,"vendors":vendors::CATALOG,"ifaces":interfaces,"suggested_ifaces":suggested,"tools":self.device.tools(),"hook_path":"","active":effective=="matches","effective":effective,"last_error":last_error,"applied_at":state.applied_at}),
        )
    }
}
fn prefix_bytes(prefix: &str) -> io::Result<Vec<u8>> {
    let raw = prefix.trim();
    if raw.is_empty() {
        return Ok(vec![]);
    }
    let mut rest = raw.as_bytes();
    let mut bytes = Vec::with_capacity(3);
    while !rest.is_empty() {
        let pair = rest
            .get(..2)
            .filter(|p| p.iter().all(u8::is_ascii_hexdigit))
            .ok_or_else(|| invalid("Неверный префикс MAC"))?;
        if bytes.len() == 3 {
            return Err(invalid("Префикс MAC должен содержать 1–3 октета"));
        }
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        rest = &rest[2..];
        if matches!(rest.first(), Some(b':' | b'-')) {
            rest = &rest[1..];
            if rest.is_empty() {
                return Err(invalid("Неверный префикс MAC"));
            }
        }
    }
    if bytes[0] & 1 != 0 {
        return Err(invalid("Префикс должен быть unicast"));
    }
    Ok(bytes)
}
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn random_mac(prefix: &str) -> io::Result<String> {
    let prefix = prefix_bytes(prefix)?;
    let mut bytes = [0; 6];
    let id = nfqws2_store::new_id()?;
    for (byte, pair) in bytes.iter_mut().zip(id.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    if prefix.is_empty() {
        bytes[0] = (bytes[0] & !1) | 2;
    } else {
        bytes[..prefix.len()].copy_from_slice(&prefix);
    }
    if bytes == [0; 6] {
        bytes[5] = 1;
    }
    Ok(format_mac(&bytes))
}
#[derive(Deserialize)]
struct Generate {
    #[serde(default)]
    prefix: String,
}
#[derive(Deserialize)]
struct Enable {
    enabled: bool,
}
async fn view(State(s): State<Shared>) -> Result<impl axum::response::IntoResponse, ApiError> {
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(blocking(move || s.bridge_mac.view(&s.store, &s.config.wan_ifaces)).await?),
    ))
}
async fn edit(s: Shared, change: journal::Change) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.bridge_mac
            .change(&s.store, &s.config.wan_ifaces, change)?;
        s.bridge_mac.view(&s.store, &s.config.wan_ifaces)
    })
    .await
    .map(Json)
}
async fn save(
    State(s): State<Shared>,
    ApiJson(cfg): ApiJson<Config>,
) -> Result<Json<Value>, ApiError> {
    edit(s, journal::Change::Config(cfg)).await
}
async fn enabled(
    State(s): State<Shared>,
    ApiJson(cfg): ApiJson<Enable>,
) -> Result<Json<Value>, ApiError> {
    edit(s, journal::Change::Enable(cfg.enabled)).await
}
async fn generate(ApiJson(cfg): ApiJson<Generate>) -> Result<Json<Value>, ApiError> {
    let mac = blocking(move || random_mac(&cfg.prefix)).await?;
    Ok(Json(json!({"mac":mac})))
}
async fn reconcile(s: &Shared) -> Result<(), ApiError> {
    let state = s.clone();
    blocking(move || {
        state
            .bridge_mac
            .restore(&state.store, &state.config.wan_ifaces)
    })
    .await
}
pub async fn restore(s: &Shared) {
    if let Err(e) = reconcile(s).await {
        s.logs.append("arp-spoofing", "warn", &e.1);
    }
}
pub fn start_refresh(state: &Shared) {
    let weak = std::sync::Arc::downgrade(state);
    tokio::spawn(async move {
        let mut last_error = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let Some(state) = weak.upgrade() else {
                break;
            };
            let error = reconcile(&state).await.err().map(|e| e.1);
            if error != last_error {
                if let Some(message) = &error {
                    state.logs.append("arp-spoofing", "warn", message);
                }
                last_error = error;
            }
        }
    });
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/arp-spoofing", get(view))
        .route("/api/arp-spoofing/config", post(save))
        .route("/api/arp-spoofing/enabled", post(enabled))
        .route("/api/arp-spoofing/generate", post(generate))
        .layer(DefaultBodyLimit::max(4096))
}
