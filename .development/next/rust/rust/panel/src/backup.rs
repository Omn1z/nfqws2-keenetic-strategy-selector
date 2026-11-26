use crate::http::{blocking, ApiError, Shared};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, StatusCode},
    response::Response,
    routing::post,
    Json, Router,
};
use nfqws2_config::{Key, Platform, Resolver};
use serde_json::{json, Value};
use std::{
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::{io::AsyncReadExt, sync::mpsc};
pub fn system_paths(root: &Path) -> Vec<PathBuf> {
    let layout = Resolver::new_at(root);
    let mut keys = vec![Key::AwgConfigDir, Key::AwgHook];
    if layout.platform() == Platform::OpenWrt {
        keys.extend([
            Key::AwgMultiHook,
            Key::AwgFw4Hook,
            Key::PortForwardHook,
            Key::DnsHook,
        ]);
    }
    keys.into_iter()
        .map(|k| layout.path(k).to_owned())
        .collect()
}
fn roots(s: &Shared) -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(&s.config.data_dir)];
    for p in &s.backup_paths {
        if p.exists() && !paths.iter().any(|r| p.starts_with(r)) {
            paths.push(p.clone());
        }
    }
    paths
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/system/backup", post(download))
        .route(
            "/api/system/restore",
            post(restore).layer(DefaultBodyLimit::max(300 << 20)),
        )
}
fn filename(time: SystemTime) -> String {
    let rfc = httpdate::fmt_http_date(time);
    let parts: Vec<_> = rfc.split_ascii_whitespace().collect();
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == parts[2])
    .unwrap()
        + 1;
    format!(
        "selector-{}{:02}{}-{}.bak",
        parts[3],
        month,
        parts[1],
        parts[4].replace(':', "")
    )
}
async fn download(State(s): State<Shared>) -> Result<Response, ApiError> {
    let archive = blocking(move || {
        s.store.transaction(|tx| {
            s.dnsserver.routing_history.flush_locked(&s.store, tx)?;
            nfqws2_backup::build(&roots(&s), &Path::new(&s.config.data_dir).join(".store"))
        })
    })
    .await?;
    let len = archive.file.metadata()?.len() + archive.header.len() as u64;
    let head = Bytes::copy_from_slice(&archive.header);
    let file = tokio::fs::File::from_std(archive.file);
    let stream =
        futures_util::stream::try_unfold((Some(head), file), |(head, mut file)| async move {
            if let Some(h) = head {
                return Ok(Some((h, (None, file))));
            }
            let mut block = vec![0; 32 * 1024];
            let n = file.read(&mut block).await?;
            block.truncate(n);
            Ok::<_, io::Error>((n != 0).then_some((Bytes::from(block), (None, file))))
        });
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename(SystemTime::now())),
        )
        .body(Body::from_stream(stream))
        .expect("fixed backup response headers"))
}
fn invalid(s: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, s.to_string())
}
async fn restore(
    State(s): State<Shared>,
    mut multipart: Multipart,
) -> Result<Json<Value>, ApiError> {
    let meta = Path::new(&s.config.data_dir).join(".store");
    let mut upload = None;
    while let Some(mut field) = multipart.next_field().await.map_err(invalid)? {
        if field.name() != Some("archive") {
            continue;
        }
        if upload.is_some() {
            return Err(invalid("duplicate archive field"));
        }
        let (sender, mut receiver) = mpsc::channel::<Bytes>(2);
        let dir = meta.clone();
        let writer = tokio::task::spawn_blocking(move || {
            let mut upload = nfqws2_backup::Upload::new(&dir)?;
            while let Some(chunk) = receiver.blocking_recv() {
                upload.append(&chunk)?;
            }
            Ok::<_, io::Error>(upload)
        });
        while let Some(bytes) = field.chunk().await.map_err(invalid)? {
            if sender.send(bytes).await.is_err() {
                break;
            }
        }
        drop(sender);
        upload = Some(writer.await.map_err(invalid)?.map_err(invalid)?);
    }
    let file = upload.ok_or_else(|| invalid("missing archive"))?;
    // Finish reloading if the client disconnects after its upload committed.
    tokio::spawn(async move {
        let disk = s.clone();
        let outcome = s
            .dnsserver
            .with_config_restore(move || {
                let _vpn = disk.awg_runtime.deployment_guard()?;
                disk.store.transaction(|_| {
                    use nfqws2_awg_rules::discoveries;
                    let history = std::path::absolute(
                        Path::new(&disk.config.data_dir).join(discoveries::FILE),
                    )?;
                    let outcome = file.restore_checked_last(
                        &roots(&disk),
                        &history,
                        discoveries::validate_file,
                    );
                    if outcome.is_ok() {
                        disk.dnsserver.routing_history.reset_after_restore();
                    }
                    // A rename can fail after earlier files have committed.
                    let reload = if outcome.as_ref().is_ok_and(|&n| n > 0)
                        || outcome
                            .as_ref()
                            .is_err_and(|e| e.kind() != io::ErrorKind::InvalidData)
                    {
                        disk.auth
                            .reload_after_restore()
                            .and_then(|()| disk.settings.reload(&disk.store, &disk.logs))
                    } else {
                        Ok(())
                    };
                    let count = outcome?;
                    reload?;
                    Ok(Json(json!({"restored":count})))
                })
            })
            .await
            .map_err(|e| invalid(e.1));
        if outcome.is_ok() {
            crate::bridge_mac::restore(&s).await;
        }
        crate::trace::awg::restore(&s).await;
        outcome
    })
    .await
    .map_err(invalid)?
}
