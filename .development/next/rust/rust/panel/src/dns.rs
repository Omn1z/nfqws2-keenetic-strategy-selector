use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{Path, State},
    http::{StatusCode, Uri},
    routing::{delete, get, post},
    Json, Router,
};
use nfqws2_store::{new_id, ConfigFile};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, io};

#[derive(Default, Clone, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct Server {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) transport: String,
    pub(crate) addr: String,
}
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
impl Server {
    fn normalize(&mut self) {
        self.name = self.name.trim().into();
        self.transport = self.transport.trim().to_lowercase();
        self.addr = self.addr.trim().into();
    }
    fn validate(&self) -> io::Result<()> {
        if self.name.trim().is_empty() {
            return Err(invalid("укажите название DNS"));
        }
        let addr = self.addr.trim();
        match self.transport.trim().to_ascii_lowercase().as_str() {
            "doh"
                if addr.parse::<Uri>().is_ok_and(|uri| {
                    uri.scheme_str() == Some("https") && uri.host().is_some_and(|v| !v.is_empty())
                }) =>
            {
                Ok(())
            }
            "dot" if !addr.is_empty() && !addr.contains(['/', ' ']) => Ok(()),
            "doh" => Err(invalid("DoH-адрес должен быть https://… ссылкой")),
            "dot" => Err(invalid("DoT-адрес должен быть host или host:port")),
            _ => Err(invalid("тип DNS должен быть doh или dot")),
        }
    }
}
fn defaults() -> Vec<Server> {
    let providers = [
        ("google", "Google", "dns.google", Some("dns.google")),
        (
            "cloudflare",
            "Cloudflare",
            "cloudflare-dns.com",
            Some("one.one.one.one"),
        ),
        ("comss", "Comss", "dns.comss.one", None),
        (
            "yandex",
            "Yandex",
            "common.dot.dns.yandex.net",
            Some("common.dot.dns.yandex.net"),
        ),
        ("xboxdns", "xbox-dns", "xbox-dns.ru", Some("xbox-dns.ru")),
        (
            "geohide",
            "GeoHide",
            "dns.geohide.ru:8443",
            Some("dns.geohide.ru"),
        ),
        (
            "adguard",
            "AdGuard",
            "dns.adguard-dns.com",
            Some("dns.adguard-dns.com"),
        ),
    ];
    let mut all = Vec::with_capacity(13);
    for (id, name, https, tls) in providers {
        all.push(Server {
            id: format!("{id}-doh"),
            name: format!("{name} · DoH"),
            transport: "doh".into(),
            addr: format!("https://{https}/dns-query"),
        });
        if let Some(host) = tls {
            all.push(Server {
                id: format!("{id}-dot"),
                name: format!("{name} · DoT"),
                transport: "dot".into(),
                addr: host.into(),
            });
        }
    }
    all
}
fn validate_list(servers: &[Server]) -> io::Result<()> {
    let mut ids = HashSet::new();
    for server in servers {
        server.validate()?;
        if server.id.is_empty() || !ids.insert(&server.id) {
            return Err(invalid("список DNS содержит пустой или повторяющийся ID"));
        }
    }
    Ok(())
}
const DNS: ConfigFile<Vec<Server>> = ConfigFile::new("dns.json", defaults, |v| validate_list(v));
pub(crate) fn servers(store: &nfqws2_store::Store) -> io::Result<Vec<Server>> {
    DNS.read(store)
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/dns", get(list).post(save))
        .route("/api/dns/{id}", delete(remove))
        .route("/api/dns/reset", post(reset))
}
async fn list(State(s): State<Shared>) -> Result<Json<Vec<Server>>, ApiError> {
    blocking(move || DNS.read(&s.store).map(Json))
        .await
        .map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, e.1))
}
async fn save(
    State(s): State<Shared>,
    ApiJson(mut server): ApiJson<Server>,
) -> Result<Json<Server>, ApiError> {
    server.normalize();
    server.validate()?;
    blocking(move || {
        DNS.edit(&s.store, |all| {
            if server.id.is_empty() {
                server.id = format!("user-{}", new_id()?);
            }
            if let Some(item) = all.iter_mut().find(|item| item.id == server.id) {
                *item = server.clone();
            } else {
                all.push(server.clone());
            }
            Ok(Json(server))
        })
    })
    .await
}
async fn remove(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        DNS.edit(&s.store, |all| {
            all.retain(|s| s.id != id);
            Ok(Json(json!({"status":"ok"})))
        })
    })
    .await
}
async fn reset(State(s): State<Shared>) -> Result<Json<Vec<Server>>, ApiError> {
    blocking(move || DNS.reset(&s.store).map(Json)).await
}
