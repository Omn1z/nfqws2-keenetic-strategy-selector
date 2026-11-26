mod strategy;
#[cfg(test)]
mod tests;
use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::stream;
use nfqws2_blobs::{blob_name, Blobs, Catalog, MAX_UPLOAD, MAX_ZIP};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{self, BufWriter, Write},
    path::Path as FsPath,
};
use tempfile::NamedTempFile;
use tokio::{io::AsyncWriteExt, sync::mpsc};

pub(crate) fn service(s: &Shared) -> Blobs<'_> {
    Blobs::new(
        &s.store,
        FsPath::new(&s.config.data_dir),
        FsPath::new(&s.config.system_blobs_dir),
    )
}
fn bad(e: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, e.to_string())
}

async fn list(State(s): State<Shared>) -> Result<Json<Catalog>, ApiError> {
    blocking(move || service(&s).list().map(Json)).await
}

async fn uploaded(
    s: &Shared,
    mut form: Multipart,
    limit: u64,
    require_name: bool,
) -> Result<(String, NamedTempFile), ApiError> {
    let mut uploaded = None;
    while let Some(mut field) = form
        .next_field()
        .await
        .map_err(|e| ApiError(e.status(), e.to_string()))?
    {
        if field.name() != Some("file") || uploaded.is_some() {
            continue;
        }
        let filename = field.file_name().unwrap_or_default().to_owned();
        if require_name {
            blob_name(&filename).map_err(bad)?;
        }
        let file = service(s).temporary()?;
        let mut out = tokio::fs::File::from_std(file.reopen()?);
        let mut size = 0;
        while let Some(bytes) = field
            .chunk()
            .await
            .map_err(|e| ApiError(e.status(), e.to_string()))?
        {
            size += bytes.len() as u64;
            if size > limit {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("file exceeds {limit} bytes"),
                ));
            }
            out.write_all(&bytes).await?;
        }
        out.flush().await?;
        uploaded = Some((filename, file));
    }
    uploaded.ok_or_else(|| bad("missing file"))
}
async fn upload(State(s): State<Shared>, form: Multipart) -> Result<Json<Value>, ApiError> {
    let (name, file) = uploaded(&s, form, MAX_UPLOAD, true).await?;
    blocking(move || {
        let path = service(&s).commit(&name, file)?;
        Ok(Json(json!({"name": name,"path":path})))
    })
    .await
}
async fn import(State(s): State<Shared>, form: Multipart) -> Result<Json<Value>, ApiError> {
    let (_, file) = uploaded(&s, form, MAX_ZIP, false).await?;
    blocking(move || {
        Ok(Json(
            json!({"imported":service(&s).import(file.as_file())?}),
        ))
    })
    .await
}

struct Pipe(mpsc::Sender<io::Result<Bytes>>);
impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .blocking_send(Ok(Bytes::copy_from_slice(bytes)))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn export(s: Shared, names: Vec<String>) -> Result<Response, ApiError> {
    for name in &names {
        blob_name(name).map_err(bad)?;
    }
    Ok(stream_zip("blobs.zip", move |out| {
        service(&s).export(&names, None, out)
    }))
}
fn stream_zip(
    filename: &str,
    write: impl FnOnce(BufWriter<Pipe>) -> io::Result<()> + Send + 'static,
) -> Response {
    let (tx, rx) = mpsc::channel(2);
    tokio::task::spawn_blocking(move || {
        let out = BufWriter::with_capacity(32 * 1024, Pipe(tx.clone()));
        if let Err(e) = write(out) {
            let _ = tx.blocking_send(Err(e));
        }
    });
    let body = Body::from_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }));
    (
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}
async fn export_all(State(s): State<Shared>) -> Result<Response, ApiError> {
    export(s, Vec::new())
}
#[derive(Deserialize)]
struct Selection {
    #[serde(default)]
    names: Option<Vec<String>>,
}
async fn export_selected(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Selection>,
) -> Result<Response, ApiError> {
    export(s, v.names.unwrap_or_default())
}
#[derive(Deserialize)]
struct Generate {
    #[serde(default)]
    name: String,
    #[serde(default)]
    sni: String,
    alpn: Option<Vec<String>>,
    #[serde(default)]
    min_version: u16,
}
async fn generate(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Generate>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        blob_name(&v.name)?;
        let bytes = nfqws2_blobs::generate(&v.sni, &v.alpn.unwrap_or_default(), v.min_version)?;
        let blobs = service(&s);
        let mut file = blobs.temporary()?;
        file.write_all(&bytes)?;
        let path = blobs.commit(&v.name, file)?;
        Ok(Json(json!({"name":v.name,"path":path})))
    })
    .await
}
async fn validate(
    State(s): State<Shared>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        let (valid, detail) = service(&s).validate(&name)?;
        Ok(Json(json!({"valid":valid,"detail":detail})))
    })
    .await
}
fn ok() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
async fn remove(
    State(s): State<Shared>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || service(&s).remove(&name)).await?;
    Ok(ok())
}
async fn restore(
    State(s): State<Shared>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    blocking(move || service(&s).restore(&name)).await?;
    Ok(ok())
}
async fn purge(State(s): State<Shared>, Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    blocking(move || service(&s).purge(&name)).await?;
    Ok(ok())
}
async fn empty(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || service(&s).empty()).await?;
    Ok(ok())
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/api/blobs",
            get(list)
                .post(upload)
                .layer(DefaultBodyLimit::max(MAX_UPLOAD as usize + 64 * 1024)),
        )
        .merge(strategy::routes())
        .route(
            "/api/blobs/zip",
            post(import).layer(DefaultBodyLimit::max(MAX_ZIP as usize + 64 * 1024)),
        )
        .route("/api/blobs/export", get(export_all).post(export_selected))
        .route("/api/blobs/generate", post(generate))
        .route("/api/blobs/{name}/validate", get(validate))
        .route("/api/blobs/{name}", delete(remove))
        .route("/api/blobs/{name}/restore", post(restore))
        .route("/api/blobs/trash/{name}", delete(purge))
        .route("/api/blobs/trash/empty", post(empty))
}
