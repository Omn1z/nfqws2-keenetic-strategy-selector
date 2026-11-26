use crate::http::{ApiError, ApiJson};
use axum::Json;
use futures_util::{stream, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::Semaphore};
static CHECKS: Semaphore = Semaphore::const_new(4);
#[derive(Deserialize)]
pub(super) struct Targets {
    domains: Vec<String>,
}
fn names(input: Vec<String>) -> io::Result<Vec<String>> {
    if !(1..=64).contains(&input.len()) {
        return Err(super::explorer::invalid(
            "проверка принимает от 1 до 64 доменов",
        ));
    }
    let mut seen = HashSet::new();
    let mut unique = vec![];
    for s in input {
        let d = nfqws2_config::service_profiles::domain(&s)?;
        if seen.insert(d.clone()) {
            unique.push(d);
        }
    }
    Ok(unique)
}
fn status(exit: Option<i32>, raw: &[u8]) -> io::Result<u16> {
    // CURLE_FILESIZE_EXCEEDED is expected when the response exceeds the read budget.
    let code = std::str::from_utf8(raw)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok());
    if let (Some(0 | 63), Some(code @ 100..=599)) = (exit, code) {
        Ok(code)
    } else {
        Err(io::Error::other(format!(
            "проверка HTTPS не прошла (curl {})",
            exit.unwrap_or(-1)
        )))
    }
}
async fn fetch(domain: &str) -> io::Result<u16> {
    let _slot = CHECKS.acquire().await.map_err(io::Error::other)?;
    let url = format!("https://{domain}/");
    let output = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--proto",
            "=https",
            "--noproxy",
            "*",
            "--max-time",
            "10",
            "--connect-timeout",
            "6",
            "--max-filesize",
            "65536",
            "--range",
            "0-65535",
            "--user-agent",
            "nfqws2-strategy/service-check",
            "--output",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
            "--write-out",
            "%{http_code}",
            "--",
            &url,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await?;
    status(output.status.code(), &output.stdout)
}
pub(super) async fn check(ApiJson(input): ApiJson<Targets>) -> Result<Json<Value>, ApiError> {
    let names = names(input.domains)?;
    #[cfg(any(feature = "compact", not(feature = "embedded-strategies")))]
    if !crate::assets::module_dir()
        .join("strategies")
        .join(format!("nfqws2-strategies{}", std::env::consts::EXE_SUFFIX))
        .is_file()
    {
        return Err(ApiError(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "установите nfqws2-strategy-strategies".into(),
        ));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let rows: Vec<_> = stream::iter(names.into_iter().map(|domain| async move {
        let now = Instant::now();
        let result = tokio::time::timeout_at(deadline, fetch(&domain))
            .await
            .map_err(io::Error::other)
            .and_then(|r| r);
        let ok = result.is_ok();
        let detail = result
            .map(|v| format!("HTTPS: HTTP {v}"))
            .unwrap_or_else(|e| e.to_string());
        json!({"domain":domain,"ok":ok,"detail":detail,"ms":now.elapsed().as_millis()})
    }))
    .buffered(4)
    .collect()
    .await;
    Ok(Json(json!({"results":rows})))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_and_server_responses_follow_the_http_contract() {
        assert_eq!(
            names(vec!["*.Example.test".into(), "example.test.".into()]).unwrap(),
            ["example.test"]
        );
        for bad in [
            "127.0.0.1",
            "https://host.test",
            "file:/etc/file",
            "example.test/a",
            "localhost",
        ] {
            assert!(names(vec![bad.into()]).is_err());
        }
        assert!(names(vec![]).is_err());
        assert_eq!(status(Some(0), b"403").unwrap(), 403);
        assert_eq!(status(Some(63), b"200").unwrap(), 200);
        assert!(status(Some(60), b"000").is_err());
    }
}
