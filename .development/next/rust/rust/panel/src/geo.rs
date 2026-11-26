mod backend;
#[cfg(test)]
mod tests;
mod update;

pub use update::{start_auto, GeoState};

use crate::{
    data,
    http::{blocking, ApiError, ApiJson, Shared},
};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use nfqws2_store::{valid_name, Store};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs, io,
    net::IpAddr,
    path::{Path as FsPath, PathBuf},
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;

const META: &str = "geo_meta.json";
const MAX_FILE: u64 = 128 * 1024 * 1024;
type Metadata = BTreeMap<String, String>;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn bad_request(message: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.to_string())
}
fn kind(value: &str) -> &'static str {
    match value {
        "geosite" => "geosite",
        "geoip" => "geoip",
        _ => "text",
    }
}
fn dir(root: &str) -> io::Result<PathBuf> {
    let path = FsPath::new(root).join("geo");
    fs::create_dir_all(&path)?;
    if !fs::symlink_metadata(&path)?.is_dir() {
        return Err(invalid("invalid geo directory"));
    }
    Ok(path)
}
fn file_path(root: &str, name: &str) -> io::Result<PathBuf> {
    if !valid_name(name) {
        return Err(invalid("invalid geo filename"));
    }
    let path = dir(root)?.join(name);
    if !fs::symlink_metadata(&path)?.is_file() {
        return Err(invalid("expected a regular geo file"));
    }
    Ok(path)
}
#[cfg(unix)]
fn sync_dir(path: &FsPath) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}
#[cfg(not(unix))]
fn sync_dir(_: &FsPath) -> io::Result<()> {
    Ok(())
}

fn commit(
    db: &Store,
    root: &str,
    file: NamedTempFile,
    name: &str,
    file_kind: &str,
) -> io::Result<()> {
    if !valid_name(name) {
        return Err(invalid("invalid geo filename"));
    }
    file.as_file().sync_all()?;
    let dir = dir(root)?;
    db.transaction(|tx| {
        let mut meta: Metadata = data::or_default(db, META)?;
        let previous = meta.insert(name.into(), kind(file_kind).into());
        let changed = previous.as_deref() != Some(kind(file_kind));
        if changed {
            tx.save(META, &meta)?;
        }
        if let Err(err) = file.persist(dir.join(name)) {
            if changed {
                match previous {
                    Some(previous) => {
                        meta.insert(name.into(), previous);
                    }
                    None => {
                        meta.remove(name);
                    }
                }
                tx.save(META, &meta)?;
            }
            return Err(err.error);
        }
        sync_dir(&dir)
    })
}

#[derive(Deserialize, Serialize)]
struct Category {
    name: String,
    count: u64,
}
#[derive(Serialize)]
struct GeoFile {
    name: String,
    kind: String,
    categories: Option<Vec<Category>>,
}

async fn files(State(state): State<Shared>) -> Result<Json<Vec<GeoFile>>, ApiError> {
    blocking(move || {
        let meta: Metadata = data::or_default(&state.store, META)?;
        let available = backend::available();
        Ok(Json(
            meta.into_iter()
                .map(|(name, k)| {
                    let categories = available
                        .then(|| {
                            file_path(&state.config.data_dir, &name)
                                .and_then(|p| backend::categories(&p, kind(&k)))
                                .ok()
                        })
                        .flatten();
                    GeoFile {
                        name,
                        kind: k,
                        categories,
                    }
                })
                .collect(),
        ))
    })
    .await
}

#[derive(Default, Deserialize)]
struct UploadQuery {
    kind: Option<String>,
}
async fn upload(
    State(s): State<Shared>,
    Query(q): Query<UploadQuery>,
    mut form: Multipart,
) -> Result<Json<Value>, ApiError> {
    let mut file = None;
    let mut name = String::new();
    let mut file_kind = q.kind.filter(|value| !value.is_empty());
    while let Some(mut part) = form.next_field().await.map_err(bad_request)? {
        match part.name() {
            Some("file") if file.is_none() => {
                name = part
                    .file_name()
                    .filter(|s| valid_name(s))
                    .ok_or_else(|| bad_request("invalid geo filename"))?
                    .into();
                let tmp = NamedTempFile::new_in(dir(&s.config.data_dir)?)?;
                let mut writer = tokio::fs::File::from_std(tmp.reopen()?);
                let mut len = 0;
                while let Some(chunk) = part.chunk().await.map_err(bad_request)? {
                    len += chunk.len() as u64;
                    if len > MAX_FILE {
                        return Err(ApiError(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "geo file exceeds 128 MiB".into(),
                        ));
                    }
                    writer.write_all(&chunk).await?;
                }
                writer.flush().await?;
                file = Some(tmp);
            }
            Some("kind") if file_kind.is_none() && part.file_name().is_none_or(str::is_empty) => {
                let mut value = Vec::new();
                while let Some(chunk) = part.chunk().await.map_err(bad_request)? {
                    if value.len() + chunk.len() > 64 {
                        return Err(bad_request("invalid geo kind"));
                    }
                    value.extend_from_slice(&chunk);
                }
                file_kind = Some(String::from_utf8(value).map_err(bad_request)?);
            }
            _ => {}
        }
    }
    let file = file.ok_or_else(|| bad_request("missing file"))?;
    let file_kind = file_kind.unwrap_or_default();
    blocking(move || {
        commit(&s.store, &s.config.data_dir, file, &name, &file_kind)?;
        Ok(Json(json!({"name":name, "kind":file_kind})))
    })
    .await
}

async fn remove(
    State(s): State<Shared>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !valid_name(&name) {
        return Err(bad_request("invalid geo filename"));
    }
    blocking(move || {
        s.store.transaction(|tx| {
            let mut meta: Metadata = data::or_default(&s.store, META)?;
            dir(&s.config.data_dir)?;
            let previous = meta.remove(&name);
            tx.save(META, &meta)?;
            if let Err(error) = tx.delete(&format!("geo/{name}")) {
                if let Some(previous) = previous {
                    meta.insert(name, previous);
                    tx.save(META, &meta)?;
                }
                return Err(error);
            }
            Ok(Json(json!({"status":"ok"})))
        })
    })
    .await
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Selection {
    geo: String,
    category: String,
    limit: i64,
    list_id: String,
    list_name: String,
}
fn entries(s: &Shared, input: &Selection) -> io::Result<Vec<String>> {
    let path = file_path(&s.config.data_dir, &input.geo)?;
    let meta: Metadata = data::or_default(&s.store, META)?;
    let k = meta.get(&input.geo).map_or("text", |k| kind(k));
    backend::extract(&path, k, &input.category, input.limit.max(0) as u64)
}
pub(crate) fn routing_entries(root: &str, k: &str, name: &str) -> io::Result<Vec<String>> {
    use nfqws2_awg_rules::sources::{MAX_SOURCE_BYTES, MAX_SOURCE_ENTRIES};
    use std::{collections::HashSet, io::Read};
    let mut raw = Vec::new();
    fs::File::open(FsPath::new(root).join(META))?
        .take(65537)
        .read_to_end(&mut raw)?;
    let meta: Metadata = nfqws2_awg_rules::decode(&raw, 65536)?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut bytes = 0usize;
    for (file, kind) in meta {
        if k != kind {
            continue;
        }
        let path = file_path(root, &file)?;
        if path.metadata()?.len() > 64 << 20 {
            return Err(invalid("Geo-файл превышает 64 МиБ"));
        }
        let Some(entries) =
            backend::bounded_extract(&path, k, name, MAX_SOURCE_ENTRIES as u64, MAX_SOURCE_BYTES)?
        else {
            continue;
        };
        for value in entries {
            if seen.insert(value.clone()) {
                bytes += value.len();
                if seen.len() > MAX_SOURCE_ENTRIES || bytes > MAX_SOURCE_BYTES {
                    return Err(invalid("снимок Geo превышает допустимый размер"));
                }
                out.push(value);
            }
        }
    }
    Ok(out)
}
#[derive(Serialize)]
struct Targets {
    targets: Vec<String>,
}
async fn resolve(
    State(s): State<Shared>,
    ApiJson(input): ApiJson<Selection>,
) -> Result<Json<Targets>, ApiError> {
    blocking(move || {
        Ok(Json(Targets {
            targets: entries(&s, &input)?,
        }))
    })
    .await
}
fn ip_entry(text: &str) -> bool {
    let (addr, bits) = match text.split_once('/') {
        None => return text.parse::<IpAddr>().is_ok(),
        Some(pair) => pair,
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    bits.bytes().all(|c| c.is_ascii_digit())
        && bits
            .parse::<u8>()
            .is_ok_and(|b| b <= if ip.is_ipv4() { 32 } else { 128 })
}
async fn import(
    State(s): State<Shared>,
    ApiJson(input): ApiJson<Selection>,
) -> Result<Json<data::List>, ApiError> {
    blocking(move || {
        let (ips, domains) = entries(&s, &input)?
            .into_iter()
            .partition(|entry| ip_entry(entry));
        let name = if input.list_name.is_empty() {
            format!("{}:{}", input.geo, input.category)
        } else {
            input.list_name
        };
        data::append_geo(&s.store, &input.list_id, &name, domains, ips).map(Json)
    })
    .await
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/api/geo",
            get(files)
                .post(upload)
                .layer(DefaultBodyLimit::max(MAX_FILE as usize + 64 * 1024)),
        )
        .route("/api/geo/{name}", delete(remove))
        .route("/api/geo/resolve", post(resolve))
        .route("/api/geo/import", post(import))
        .merge(update::routes())
}
