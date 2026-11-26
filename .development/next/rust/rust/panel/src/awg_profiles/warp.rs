use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{extract::State, http::StatusCode, Json};
use nfqws2_awg_profile::WarpEnrollment;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io, process::Stdio, time::Duration};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex, time::timeout};

static REGISTRATION: Mutex<()> = Mutex::const_new(());
const LIMIT: usize = 128 * 1024;
#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Request {
    name: String,
    endpoint: String,
    accept_tos: bool,
}
fn registration_body(public: &str, at: OffsetDateTime) -> io::Result<String> {
    let tos = at.format(&Rfc3339).map_err(io::Error::other)?;
    Ok(json!({"key":public,"tos":tos,"locale":"en_US","model":"Keenetic","type":"Android","fcm_token":"","install_id":""}).to_string())
}
async fn register(body: String) -> io::Result<Vec<u8>> {
    let mut child = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--fail",
            "--http1.1",
            "--tlsv1.2",
            "--tls-max",
            "1.2",
            "--proto",
            "=https",
            "--max-time",
            "25",
            "--connect-timeout",
            "8",
            "--user-agent",
            "okhttp/3.12.1",
            "-H",
            "CF-Client-Version: a-6.3-1922",
            "-H",
            "Accept: application/json",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &body,
            "--",
            "https://api.cloudflareclient.com/v0a1922/reg",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = Vec::new();
    let result = timeout(Duration::from_secs(27), async {
        child
            .stdout
            .take()
            .unwrap()
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() > LIMIT {
            return Err(io::Error::other("ответ регистрации WARP превышает лимит"));
        }
        if !child.wait().await?.success() {
            return Err(io::Error::other(
                "не удалось зарегистрировать устройство в Cloudflare WARP",
            ));
        }
        Ok(output)
    })
    .await
    .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}
pub(super) async fn handle(
    State(s): State<Shared>,
    ApiJson(v): ApiJson<Request>,
) -> Result<Json<Value>, ApiError> {
    create(s, v, register).await
}
async fn create<F, Fut>(s: Shared, v: Request, request: F) -> Result<Json<Value>, ApiError>
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = io::Result<Vec<u8>>> + Send + 'static,
{
    let enrollment = WarpEnrollment::new(&v.name, &v.endpoint, v.accept_tos)?;
    let permit = REGISTRATION.try_lock().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "регистрация WARP уже выполняется".into(),
        )
    })?;
    let db = s.store.clone();
    blocking(move || nfqws2_awg_profile::read(&db).map(drop)).await?;
    let body = registration_body(enrollment.public_key(), OffsetDateTime::now_utc())?;
    tokio::spawn(async move {
        let _permit = permit;
        let response = request(body)
            .await
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
        blocking(move || {
            enrollment.finish(&s.store, &response)?;
            super::profile_status(&s).map(Json)
        })
        .await
    })
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "регистрация WARP прервана".into(),
        )
    })?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_contains_only_public_identity_and_explicit_consent_time() {
        let e = WarpEnrollment::new("test", "", true).unwrap();
        let body: Value = serde_json::from_str(
            &registration_body(e.public_key(), OffsetDateTime::UNIX_EPOCH).unwrap(),
        )
        .unwrap();
        assert_eq!(body["key"], e.public_key());
        assert_eq!(body["tos"], "1970-01-01T00:00:00Z");
        assert_eq!(body.as_object().unwrap().len(), 7);
    }
    #[tokio::test]
    async fn reported_registration_failures_preserve_store_and_success_returns_redacted_status() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::http::AppState::open(
            nfqws2_config::Config {
                data_dir: dir.path().display().to_string(),
                ..Default::default()
            },
            dir.path(),
            true,
        )
        .unwrap();
        let request = || Request {
            name: "test".into(),
            endpoint: "192.0.2.1:2408".into(),
            accept_tos: true,
        };
        let failed = create(s.clone(), request(), |_| async {
            Err(io::Error::other("fixture offline"))
        })
        .await;
        assert_eq!(failed.err().unwrap().0, StatusCode::BAD_GATEWAY);
        assert!(!dir.path().join("awg.json").exists());
        let v=create(s.clone(),request(),|body|async move{
            let body:Value=serde_json::from_str(&body)?;
            assert_eq!(body["key"].as_str().unwrap().len(),44);
            Ok(serde_json::to_vec(&json!({"token":"private fixture", "config":{"interface":{"addresses":{"v4":"172.16.0.3"}},"peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}]}}))?)
        }).await.unwrap_or_else(|e|panic!("{}",e.1)).0;
        assert_eq!(v["config"]["protocol"], "wireguard");
        assert_eq!(v["config"]["peers"][0]["private_key"], "");
        assert!(!v.to_string().contains("private fixture"));
        assert_eq!(v["servers"][1]["is_warp"], true);
    }
}
