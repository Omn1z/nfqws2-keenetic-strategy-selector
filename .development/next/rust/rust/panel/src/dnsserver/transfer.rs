use super::{config, lan, Edit, Shared};
use crate::http::{blocking, ApiError};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use nfqws2_awg_rules::{decode, public_refs, Ref};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
};
const LIMIT: usize = 16 << 20;
const FORMAT: &str = "nfqws2-strategy-dnsserver";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    document: Value,
    mapping: Option<String>,
    #[serde(default)]
    mapping_fingerprint: String,
    #[serde(default)]
    base_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    version: u32,
    exported_at: String,
    config: Value,
    #[serde(default)]
    connections: Option<Vec<Ref>>,
}
fn bad(s: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, s.to_string())
}
fn shape_template() -> Value {
    let mut template = config::defaults();
    let upstream = json!({"address":"","bootstrap_ips":[""]});
    template["default_upstream"] = upstream.clone();
    template["default_pool"] = json!([upstream]);
    template["rules"] = json!([{"id":"","domain":"","enabled":true,"include_subdomains":false,"upstream":upstream,"pool":[upstream]}]);
    template["disabled_methods"] = json!([{"upstream":"","route":""}]);
    template["shadow_dns"]["servers"] = json!([""]);
    template["filtering"]["allowlist"] = json!([""]);
    template
}
fn shape(v: &Value, template: &Value, root: bool) -> io::Result<()> {
    match template {
        Value::Object(fields) => {
            let actual = v
                .as_object()
                .ok_or_else(|| config::invalid("ожидается объект настроек DNS"))?;
            if let Some(k) = actual.keys().find(|k| !fields.contains_key(k.as_str())) {
                return Err(config::invalid(format!("неизвестное поле {k}")));
            }
            for (k, t) in fields {
                match actual.get(k) {
                    None if root
                        && matches!(
                            k.as_str(),
                            "shadow_dns" | "filtering" | "scheduler_enabled"
                        ) => {}
                    Some(item)
                        if root
                            && item.is_null()
                            && matches!(k.as_str(), "shadow_dns" | "filtering") => {}
                    Some(item) => shape(item, t, false)?,
                    None => return Err(config::invalid(format!("отсутствует поле {k}"))),
                }
            }
        }
        Value::Array(items) if !v.is_null() => {
            let a = v
                .as_array()
                .ok_or_else(|| config::invalid("ожидается список"))?;
            if let Some(t) = items.first() {
                for item in a {
                    shape(item, t, false)?;
                }
            }
        }
        Value::Number(_) if !v.is_number() => return Err(config::invalid("ожидается число")),
        Value::String(_) if !v.is_string() => return Err(config::invalid("ожидается строка")),
        Value::Bool(_) if !v.is_boolean() => {
            return Err(config::invalid("ожидается логическое значение"))
        }
        _ => {}
    }
    Ok(())
}
fn decode_request(bytes: &[u8]) -> Result<(Request, Document), ApiError> {
    let mut req: Request = decode(bytes, 64 << 20).map_err(bad)?;
    let encoded = match req.document.take() {
        Value::String(s) => s.into_bytes(),
        v => serde_json::to_vec(&v).map_err(bad)?,
    };
    if encoded.len() > LIMIT {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "документ превышает 16 МиБ".into(),
        ));
    }
    let doc: Document = decode(
        encoded
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(&encoded),
        LIMIT,
    )
    .map_err(bad)?;
    if doc.format != FORMAT
        || doc.version != 1
        || time::OffsetDateTime::parse(
            &doc.exported_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_or(true, |t| t.year() <= 1)
    {
        return Err(bad("неверный формат, версия или дата экспорта DNS"));
    }
    shape(&doc.config, &shape_template(), true).map_err(bad)?;
    let rows = doc.connections.as_deref().unwrap_or_default();
    let mut seen = BTreeSet::new();
    if rows.len() > 2049 {
        return Err(bad("слишком много подключений VPN"));
    }
    for r in rows {
        if !seen.insert(&r.id) {
            return Err(bad("повтор ссылки VPN"));
        }
        r.validate().map_err(bad)?;
    }
    Ok((req, doc))
}
fn ids(cfg: &Value) -> BTreeSet<&str> {
    let mut ids = BTreeSet::new();
    if let Some(id) = cfg["awg_fallback"]
        .as_str()
        .filter(|v| !matches!(*v, "" | "auto" | "off"))
    {
        ids.insert(id.trim_start_matches("awg:"));
    }
    for row in cfg["disabled_methods"].as_array().into_iter().flatten() {
        if let Some(id) = row["route"].as_str().and_then(|r| r.strip_prefix("awg:")) {
            ids.insert(id);
        }
    }
    ids
}
fn refs(s: &Shared) -> io::Result<Vec<Ref>> {
    Ok(public_refs(&nfqws2_awg_profile::read(&s.store)?))
}
fn normalized(v: &Value) -> io::Result<Value> {
    let mut cfg = config::Config::from_value(v)?;
    cfg.extra.clear();
    serde_json::to_value(cfg).map_err(io::Error::other)
}
async fn export(State(s): State<Shared>) -> Result<Response, ApiError> {
    let raw = {
        let guard = s.dnsserver.state.lock().await;
        if !guard.config_error.is_empty() {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                guard.config_error.clone(),
            ));
        }
        guard.raw.clone()
    };
    let wire = blocking(move || {
        let cfg = normalized(&raw)?;
        let ids = ids(&cfg);
        let mut selected = vec![];
        if !ids.is_empty() {
            let by_id: BTreeMap<_, _> = refs(&s)?.into_iter().map(|r| (r.id.clone(), r)).collect();
            for id in ids {
                selected.push(by_id.get(id).cloned().unwrap_or_else(|| Ref {
                    id: id.into(),
                    label: id.into(),
                    ..Default::default()
                }));
            }
        }
        let now = time::OffsetDateTime::now_utc();
        let exported = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(io::Error::other)?;
        let mut doc = json!({"format":FORMAT,"version":1,"exported_at":exported,"config":cfg});
        if !selected.is_empty() {
            doc["connections"] = serde_json::to_value(selected)?;
        }
        let bytes = serde_json::to_vec_pretty(&doc)?;
        let name = format!(
            "attachment; filename=\"dns-server-settings-{:04}{:02}{:02}-{:02}{:02}{:02}.json\"",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        Ok((bytes, name))
    })
    .await?;
    if wire.0.len() > LIMIT {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "документ превышает 16 МиБ".into(),
        ));
    }
    Ok((
        [
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CONTENT_DISPOSITION, wire.1),
        ],
        wire.0,
    )
        .into_response())
}
fn mapped(
    raw: &mut Value,
    doc: &[Ref],
    candidates: &[Ref],
    req: &Request,
) -> io::Result<(Value, Vec<String>)> {
    let by_source: BTreeMap<_, _> = doc
        .iter()
        .map(|r| (r.id.as_str(), r.fingerprint.as_str()))
        .collect();
    let matches = |id: &str| {
        let fp = by_source.get(id).copied().unwrap_or("");
        candidates
            .iter()
            .filter(|r| !fp.is_empty() && r.fingerprint == fp)
            .collect::<Vec<_>>()
    };
    let source = raw["awg_fallback"].as_str().unwrap_or("auto").to_owned();
    let mut selected = source.clone();
    let mut state = source.clone();
    let mut resolution = "";
    if !matches!(source.as_str(), "auto" | "off") {
        let targets = matches(&source);
        if let [only] = targets.as_slice() {
            selected.clone_from(&only.id);
            state = "matched".into();
        } else {
            selected = "auto".into();
            state = "auto".into();
            resolution = if targets.len() > 1 {
                "ambiguous"
            } else if by_source
                .get(source.as_str())
                .is_none_or(|fp| fp.is_empty())
            {
                "selection_required"
            } else {
                "missing"
            };
        }
    }
    if let Some(target) = &req.mapping {
        if matches!(target.as_str(), "auto" | "off") {
            state.clone_from(target);
        } else {
            if !candidates.iter().any(|r| {
                r.id == *target
                    && !r.fingerprint.is_empty()
                    && r.fingerprint == req.mapping_fingerprint
            }) {
                return Err(config::invalid("выбранный VPN изменился"));
            }
            state = "matched".into();
        }
        selected.clone_from(target);
        resolution = "";
    }
    let mut vpn = json!({"source_id":source,"state":state,"candidates":candidates});
    let mut warnings = vec![];
    if state == "matched" {
        vpn["matched_id"] = json!(selected);
    }
    if !resolution.is_empty() {
        vpn["resolution"] = json!(resolution);
        warnings.push("Подключение VPN из файла не удалось однозначно сопоставить. Выбран автоматический поиск локального VPN.".into());
    }
    if raw["route_mode"] == "vpn_only" && selected == "auto" && candidates.is_empty() {
        warnings.push("Нет локальных VPN. Режим «только VPN» сохранён.".into());
    }
    raw["awg_fallback"] = json!(selected);
    let mut removed = 0;
    if let Some(methods) = raw["disabled_methods"].as_array_mut() {
        methods.retain_mut(|m| {
            let Some(id) = m["route"].as_str().and_then(|r| r.strip_prefix("awg:")) else {
                return true;
            };
            let targets = matches(id);
            let mapped = if id == source && req.mapping.is_some() {
                (state == "matched").then_some(selected.as_str())
            } else if let [r] = targets.as_slice() {
                Some(r.id.as_str())
            } else {
                None
            };
            if let Some(id) = mapped {
                m["route"] = json!(format!("awg:{id}"));
                true
            } else {
                removed += 1;
                false
            }
        });
    }
    if removed > 0 {
        warnings.push(format!(
            "Пропущено выключателей методов для неподтверждённых VPN: {removed}"
        ));
    }
    Ok((vpn, warnings))
}
async fn process(s: Shared, bytes: Bytes, commit: bool) -> Result<Json<Value>, ApiError> {
    let work = s.clone();
    let (req, doc, live) = tokio::task::spawn_blocking(move || {
        let (req, doc) = decode_request(&bytes)?;
        let live = refs(&work)?
            .into_iter()
            .filter(|r| !r.fingerprint.is_empty())
            .collect::<Vec<_>>();
        Ok::<_, ApiError>((req, doc, live))
    })
    .await
    .map_err(super::worker_err)??;
    let _lock = s.ports.change.lock().await;
    let (previous, base) = {
        let st = s.dnsserver.state.lock().await;
        (st.raw.clone(), config::document_hash(&st.raw, false))
    };
    let mut raw = normalized(&doc.config)?;
    let (vpn, mut warnings) = mapped(
        &mut raw,
        doc.connections.as_deref().unwrap_or_default(),
        &live,
        &req,
    )?;
    let mut cfg = config::Config::from_value(&raw)?;
    if cfg.dns_port == s.ports.port(&s.config.listen_addr)? {
        return Err(bad("панели и DNS нужны разные порты"));
    }
    let host = match lan::host(&cfg.listen_host, &s.dnsserver.wan) {
        Ok(ip) => ip,
        Err(e) => {
            let Some((alias, ip)) = [previous["listen_host"].as_str().unwrap_or("auto"), "auto"]
                .into_iter()
                .find_map(|v| lan::host(v, &s.dnsserver.wan).ok().map(|ip| (v, ip)))
            else {
                return Err(bad(e));
            };
            warnings.push(format!(
                "Адрес DNS из файла недоступен, выбран локальный адрес {ip}."
            ));
            cfg.listen_host = alias.into();
            raw["listen_host"] = json!(alias);
            ip
        }
    };
    if commit {
        s.dnsserver
            .change(Edit::Import {
                raw,
                revision: req.base_hash,
                verify: live,
            })
            .await?;
        return Ok(Json(s.dnsserver.status().await));
    }
    Ok(Json(
        json!({"config":raw,"base_hash":base,"listener":{"host":host,"port":cfg.dns_port,"address":SocketAddr::new(host,cfg.dns_port).to_string(),"enabled":cfg.enabled},"vpn":vpn,"warnings":warnings}),
    ))
}
async fn preview(State(s): State<Shared>, b: Bytes) -> Result<Json<Value>, ApiError> {
    process(s, b, false).await
}
async fn import(State(s): State<Shared>, b: Bytes) -> Result<Json<Value>, ApiError> {
    tokio::spawn(process(s, b, true))
        .await
        .map_err(super::worker_err)?
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/dnsserver/export", get(export))
        .route("/api/dnsserver/import/preview", post(preview))
        .route("/api/dnsserver/import", post(import))
        .layer(DefaultBodyLimit::max(64 << 20))
}
