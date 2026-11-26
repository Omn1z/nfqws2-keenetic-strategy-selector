use crate::http::{ApiError, Shared};
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use nfqws2_awg_rules as rules;
pub mod kernel;
pub(crate) mod resolve;
#[cfg(test)]
mod tests;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, value::RawValue, Value};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub fn routes() -> Router<Shared> {
    Router::new()
        .merge(kernel::routes())
        .route("/api/awg2/routing/discovered", get(discovered))
        .route("/api/awg2/routing/config", post(config))
        .route("/api/awg2/routing/rules", post(save))
        .route(
            "/api/awg2/routing/rules/export",
            get(export).post(export_draft),
        )
        .route("/api/awg2/routing/rules/import/preview", post(preview))
        .route("/api/awg2/routing/rules/import", post(import))
        .route("/api/awg2/routing/rules/insert-top", post(insert))
        .route("/api/awg2/routing/rules/copy", post(copy))
}
async fn payload<T: DeserializeOwned, R: Send + 'static>(
    body: Bytes,
    f: impl FnOnce(T) -> io::Result<R> + Send + 'static,
) -> Result<Json<R>, ApiError> {
    task(move || f(rules::decode(&body, 8 << 20)?)).await
}
async fn task<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<Json<T>, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?
        .map(Json)
        .map_err(|e| {
            ApiError(
                if e.kind() == io::ErrorKind::AlreadyExists {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                },
                e.to_string(),
            )
        })
}
fn status(s: &Shared) -> io::Result<Value> {
    crate::awg_profiles::profile_status(s)
}
async fn config(State(s): State<Shared>, bytes: Bytes) -> Result<Json<Value>, ApiError> {
    payload(bytes, move |rc| {
        rules::save_settings(&s.store, rc)?;
        status(&s)
    })
    .await
}
async fn save(State(s): State<Shared>, bytes: Bytes) -> Result<Json<Value>, ApiError> {
    payload(bytes, move |rc| {
        rules::save(&s.store, rc)?;
        status(&s)
    })
    .await
}
async fn discovered(State(s): State<Shared>) -> Result<Response, ApiError> {
    stream(move || {
        let applied = rules::kernel::inspect(&s.store, &nfqws2_router_command::System)?;
        rules::discoveries::snapshot(
            &s.store,
            |kind, name| dependency(&s, kind, name),
            applied.active,
            applied.ready,
            applied.revision,
            &s.dnsserver.routing_history,
        )
    })
    .await
}
pub(crate) async fn flush_history(s: &Shared) {
    let state = s.clone();
    let result = tokio::task::spawn_blocking(move || {
        let history = state.dnsserver.routing_history.flush(&state.store);
        history.and(state.dnsserver.flush_recent_routes())
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => s.logs.append(
            "awg2",
            "warn",
            &format!("сохранение истории маршрутов: {e}"),
        ),
        Err(e) => s.logs.append("awg2", "warn", &e.to_string()),
    }
}
pub(crate) fn start_history_writer(s: &Shared) -> tokio::task::JoinHandle<()> {
    let state = std::sync::Arc::downgrade(s);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let Some(s) = state.upgrade() else { return };
            flush_history(&s).await;
        }
    })
}
fn dependency(s: &Shared, kind: &str, name: &str) -> io::Result<Vec<String>> {
    dependency_for(&s.config, kind, name)
}
pub(crate) fn stage_sources(
    cfg: &nfqws2_config::Config,
    store: &nfqws2_store::Store,
) -> io::Result<()> {
    rules::sources::stage(store, |kind, name| dependency_for(cfg, kind, name))
}
fn dependency_for(cfg: &nfqws2_config::Config, kind: &str, name: &str) -> io::Result<Vec<String>> {
    if kind != "list" {
        return crate::geo::routing_entries(&cfg.data_dir, kind, name);
    }
    if !nfqws2_store::valid_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "неверное имя списка",
        ));
    }
    let root = Path::new(&cfg.nfqws2_conf)
        .parent()
        .ok_or_else(|| io::Error::other("не задан путь к спискам"))?
        .join("lists");
    if !root.symlink_metadata()?.is_dir() {
        return Err(io::Error::other("каталог списков недоступен"));
    }
    let name = if name.ends_with(".list") || name.ends_with(".gz") {
        name.to_owned()
    } else {
        format!("{name}.list")
    };
    for file in [&name, &format!("{name}.gz")] {
        let path = root.join(file);
        match path.symlink_metadata() {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(io::Error::other("ожидался обычный файл списка")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        let data = File::open(path)?;
        let reader: Box<dyn Read> = if file.ends_with(".gz") {
            Box::new(flate2::read::MultiGzDecoder::new(data))
        } else {
            Box::new(data)
        };
        let mut raw = String::new();
        let limit = rules::sources::MAX_SOURCE_BYTES;
        reader.take(limit as u64 + 1).read_to_string(&mut raw)?;
        if raw.len() > limit {
            return Err(io::Error::other("список превышает 4 МиБ"));
        }
        return Ok(raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(['#', ';']))
            .map(str::to_owned)
            .collect());
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "список не найден"))
}
async fn stream<T: serde::Serialize>(
    build: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> Result<Response, ApiError> {
    crate::http::json_stream(move |out| {
        let value =
            build().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        serde_json::to_writer(out, &value).map_err(io::Error::other)
    })
    .await
}
async fn export(State(s): State<Shared>) -> Result<Response, ApiError> {
    stream(move || rules::export(&s.store, None, |kind, name| dependency(&s, kind, name))).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    routing: rules::Routing,
}
async fn export_draft(State(s): State<Shared>, bytes: Bytes) -> Result<Response, ApiError> {
    stream(move || {
        let v: Draft = rules::decode(&bytes, 8 << 20)?;
        rules::export(&s.store, Some(v.routing), |kind, name| {
            dependency(&s, kind, name)
        })
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInput {
    document: Box<RawValue>,
}
async fn preview(State(s): State<Shared>, bytes: Bytes) -> Result<Response, ApiError> {
    stream(move || {
        let v: FileInput = rules::decode(&bytes, 8 << 20)?;
        rules::preview(&s.store, &v.document)
    })
    .await
}
async fn import(State(s): State<Shared>, bytes: Bytes) -> Result<Json<Value>, ApiError> {
    payload(bytes, move |v| rules::import(&s.store, v)).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Top {
    domain: String,
    route: String,
    #[serde(default)]
    name: String,
}
async fn insert(State(s): State<Shared>, bytes: Bytes) -> Result<Json<Value>, ApiError> {
    payload(bytes, move |v: Top| {
        rules::insert_top(&s.store, &v.name, &v.domain, &v.route)?;
        status(&s)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyFrom {
    from_server_id: String,
}
async fn copy(State(s): State<Shared>, bytes: Bytes) -> Result<Json<Value>, ApiError> {
    payload(bytes, move |v: CopyFrom| {
        let n = rules::copy(&s.store, &v.from_server_id)?;
        Ok(json!({"copied":n,"status":status(&s)?}))
    })
    .await
}
