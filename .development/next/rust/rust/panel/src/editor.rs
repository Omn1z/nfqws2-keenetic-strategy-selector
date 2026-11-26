mod apply;
pub(crate) use apply::save as save_strategy;
mod explorer;
mod files;
mod import;
mod owner;
mod services;
pub(crate) use services::{mark_engine_applied, normalize_wan, prepare_for_engine};
mod snapshots;
use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use files::{list, Entry};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;

#[derive(Deserialize)]
struct Selection {
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    content: String,
}
fn bad(e: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, e.to_string())
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .merge(apply::routes())
        .merge(explorer::routes())
        .merge(import::routes())
        .merge(snapshots::routes())
        .merge(services::routes())
        .route("/api/nfqws2/files", get(index))
        .route("/api/nfqws2/file", get(read).post(save).delete(delete))
        .route("/api/nfqws2/file/create", post(create))
        .route("/api/nfqws2/file/download", get(download))
        .route(
            "/api/nfqws2/file/upload",
            post(upload).layer(DefaultBodyLimit::max(17 << 20)),
        )
}
async fn index(
    State(s): State<Shared>,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || Ok(Json(json!({"files":list(&s.config,&q.kind)?}))))
        .await
        .map_err(|e| bad(e.1))
}
async fn read(
    State(s): State<Shared>,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let content = Entry::new(&s.config, &q.kind, &q.name)?.read()?;
        Ok(Json(json!({"kind":q.kind,"name":q.name,"content":content})))
    })
    .await
    .map_err(|e| bad(e.1))
}
enum Change {
    Create,
    Save,
    Delete,
}
async fn change(s: Shared, q: Selection, op: Change) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.store.transaction(|_| {
            let file = Entry::new(&s.config, &q.kind, &q.name)?;
            let status = match op {
                Change::Create => {
                    file.write("", true)?;
                    "created"
                }
                Change::Save => {
                    file.write(&q.content, false)?;
                    "saved"
                }
                Change::Delete => {
                    file.delete()?;
                    "ok"
                }
            };
            Ok(Json(json!({"status":status})))
        })
    })
    .await
    .map_err(|e| bad(e.1))
}
async fn create(
    State(s): State<Shared>,
    ApiJson(q): ApiJson<Selection>,
) -> Result<Json<Value>, ApiError> {
    change(s, q, Change::Create).await
}
async fn save(
    State(s): State<Shared>,
    ApiJson(q): ApiJson<Selection>,
) -> Result<Json<Value>, ApiError> {
    change(s, q, Change::Save).await
}
async fn delete(
    State(s): State<Shared>,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, ApiError> {
    change(s, q, Change::Delete).await
}
async fn download(
    State(s): State<Shared>,
    Query(q): Query<Selection>,
) -> Result<Response, ApiError> {
    let (bytes, name) = blocking(move || Entry::new(&s.config, &q.kind, &q.name)?.download())
        .await
        .map_err(|e| bad(e.1))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}
fn decode(file: File) -> io::Result<String> {
    let mut input = BufReader::new(file);
    let bytes = if input.fill_buf()?.starts_with(&[0x1f, 0x8b]) {
        files::bounded(flate2::read::MultiGzDecoder::new(input))?
    } else {
        files::bounded(input)?
    };
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ожидается текст UTF-8"))
}
async fn upload(State(s): State<Shared>, mut form: Multipart) -> Result<Json<Value>, ApiError> {
    let mut kind = String::new();
    let mut upload = None;
    while let Some(mut part) = form.next_field().await.map_err(bad)? {
        match part.name() {
            Some("kind") => {
                let mut data = Vec::new();
                while let Some(chunk) = part.chunk().await.map_err(bad)? {
                    if data.len() + chunk.len() > 32 {
                        return Err(bad("неверный тип файла"));
                    }
                    data.extend_from_slice(&chunk);
                }
                kind = String::from_utf8(data).map_err(bad)?;
            }
            Some("file") if upload.is_none() => {
                let name = part
                    .file_name()
                    .ok_or_else(|| bad("не задано имя"))?
                    .to_owned();
                let temp =
                    NamedTempFile::new_in(std::path::Path::new(&s.config.data_dir).join(".store"))?;
                let mut out = tokio::fs::File::from_std(temp.reopen()?);
                let mut len = 0;
                while let Some(chunk) = part.chunk().await.map_err(bad)? {
                    len += chunk.len();
                    if len > 16 << 20 {
                        return Err(ApiError(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "файл больше 16 МиБ".into(),
                        ));
                    }
                    out.write_all(&chunk).await?;
                }
                out.flush().await?;
                upload = Some((name, temp));
            }
            _ => {}
        }
    }
    let (name, file) = upload.ok_or_else(|| bad("файл отсутствует"))?;
    blocking(move || {
        let content = decode(file.reopen()?)?;
        s.store
            .transaction(|_| Entry::new(&s.config, &kind, &name)?.write(&content, false))?;
        Ok(Json(json!({"kind":kind,"name":name})))
    })
    .await
    .map_err(|e| bad(e.1))
}
