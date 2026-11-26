use crate::http::{ApiError, Shared};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::Response,
    routing::get,
    Router,
};
use std::io::{self, Write};
mod current;
mod legacy;
pub(crate) use current::RunsState;
pub(crate) use current::{cancel_matching, matrix_available, recover_matrix, start_matrix};
type Live = (String, std::sync::Arc<tempfile::TempDir>);

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/runs", get(history).post(current::start))
        .route("/api/runs/capabilities", get(current::capabilities))
        .route(
            "/api/runs/{id}/cancel",
            axum::routing::post(current::cancel),
        )
        .route(
            "/api/runs/{id}/threads",
            axum::routing::post(current::threads),
        )
        .route("/api/runs/{id}", get(one))
        .layer(DefaultBodyLimit::max(32 << 10))
}
async fn history(State(s): State<Shared>) -> Result<Response, ApiError> {
    serve(s, None).await
}
async fn one(State(s): State<Shared>, Path(id): Path<String>) -> Result<Response, ApiError> {
    if !nfqws2_store::valid_name(&id) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid ID".into()));
    }
    serve(s, Some(id)).await
}

#[cfg(all(feature = "embedded-runs", not(feature = "compact")))]
fn write(out: &mut dyn Write, s: &Shared, id: Option<&str>, live: Option<&Live>) -> io::Result<()> {
    let live = live.map(|(id, dir)| (id.as_str(), dir.path()));
    if let Some(id) = id {
        serde_json::to_writer(out, &nfqws2_runs::get_with_live(&s.store, id, live)?)?;
    } else {
        nfqws2_runs::write_history_with_live(&s.store, out, live)?;
    }
    Ok(())
}

#[cfg(any(not(feature = "embedded-runs"), feature = "compact"))]
fn executable() -> std::path::PathBuf {
    crate::assets::module_dir()
        .join("runs")
        .join(format!("nfqws2-runs{}", std::env::consts::EXE_SUFFIX))
}
#[cfg(any(not(feature = "embedded-runs"), feature = "compact"))]
fn write(out: &mut dyn Write, s: &Shared, id: Option<&str>, live: Option<&Live>) -> io::Result<()> {
    helper(out, &executable(), &s.config.data_dir, id, live)
}

#[cfg(any(not(feature = "embedded-runs"), feature = "compact", test))]
fn helper(
    out: &mut dyn Write,
    program: &std::path::Path,
    data_dir: &str,
    id: Option<&str>,
    live: Option<&Live>,
) -> io::Result<()> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(program);
    cmd.arg(if id.is_some() { "get" } else { "history" })
        .arg(data_dir)
        .args(id);
    if let Some((active, dir)) = live {
        cmd.arg(active).arg(dir.path());
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Установите пакет nfqws2-strategy-runs",
                )
            } else {
                e
            }
        })?;
    let copied = io::copy(&mut child.stdout.take().expect("piped stdout"), out);
    if copied.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    copied?;
    if status.success() {
        return Ok(());
    }
    Err(match status.code() {
        Some(2) => io::Error::new(io::ErrorKind::InvalidInput, "invalid run request"),
        Some(4) => io::Error::new(io::ErrorKind::NotFound, "run not found"),
        _ => io::Error::other("could not read run reports"),
    })
}

async fn serve(s: Shared, id: Option<String>) -> Result<Response, ApiError> {
    let live = s.runs.live().await;
    crate::http::json_stream(move |out| write(out, &s, id.as_deref(), live.as_ref())).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_helper_identifies_the_optional_package() {
        let dir = tempfile::tempdir().unwrap();
        let e = helper(
            &mut Vec::new(),
            &dir.path().join("missing"),
            "ignored",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("nfqws2-strategy-runs"));
    }
}
