use super::{backend, commit, dir, invalid, ApiError, ApiJson, Shared, MAX_FILE};
use crate::{data, http::blocking};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;

const AUTO: &str = "geo_auto.json";
const SITE_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
const IP_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
const FETCH_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Default)]
pub struct GeoState {
    last_start: Mutex<Option<Instant>>,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Auto {
    enabled: bool,
    geosite_url: String,
    geoip_url: String,
    interval_hours: i64,
    last_fetched_at: i64,
    last_error: String,
    last_geosite_at: i64,
    last_geoip_at: i64,
    last_geosite_len: u64,
    last_geoip_len: u64,
}
impl Default for Auto {
    fn default() -> Self {
        Self {
            enabled: false,
            geosite_url: SITE_URL.into(),
            geoip_url: IP_URL.into(),
            interval_hours: 24,
            last_fetched_at: 0,
            last_error: String::new(),
            last_geosite_at: 0,
            last_geoip_at: 0,
            last_geosite_len: 0,
            last_geoip_len: 0,
        }
    }
}
impl Auto {
    fn normalize(&mut self) {
        if self.geosite_url.trim().is_empty() {
            self.geosite_url = SITE_URL.into();
        }
        if self.geoip_url.trim().is_empty() {
            self.geoip_url = IP_URL.into();
        }
        if self.interval_hours <= 0 {
            self.interval_hours = 24;
        }
    }
}
fn load(state: &Shared) -> io::Result<Auto> {
    let mut config: Auto = data::or_default(&state.store, AUTO)?;
    config.normalize();
    Ok(config)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn get_config(State(s): State<Shared>) -> Result<Json<Auto>, ApiError> {
    blocking(move || load(&s).map(Json)).await
}
async fn save(
    State(s): State<Shared>,
    ApiJson(mut update): ApiJson<Auto>,
) -> Result<Json<Auto>, ApiError> {
    update.normalize();
    blocking(move || {
        s.store.transaction(|tx| {
            let mut config = load(&s)?;
            config.enabled = update.enabled;
            config.geosite_url = update.geosite_url;
            config.geoip_url = update.geoip_url;
            config.interval_hours = update.interval_hours;
            tx.save(AUTO, &config)?;
            Ok(Json(config))
        })
    })
    .await
}

// curl writes one header block per redirect/CONNECT. Check the final response
// before publishing and reject byte-range responses even without a length.
fn completed_response(headers: impl Read, size: u64) -> io::Result<()> {
    let mut status = 0;
    let mut partial = false;
    let mut length = None;
    for line in BufReader::new(headers).lines() {
        let line = line?;
        if line.starts_with("HTTP/") {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            partial = false;
            length = None;
        } else if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-range") {
                partial = true;
            }
            if name.eq_ignore_ascii_case("content-length") {
                let n = value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| invalid("invalid HTTP content length"))?;
                if length.is_some_and(|v| v != n) {
                    return Err(invalid("conflicting content lengths"));
                }
                length = Some(n);
            }
        }
    }
    if !(200..300).contains(&status)
        || status == 206
        || partial
        || size == 0
        || length.is_some_and(|v| v != size)
    {
        return Err(invalid("incomplete Geo download"));
    }
    Ok(())
}

fn download(root: &Path, url: &str) -> io::Result<(NamedTempFile, u64)> {
    let headers = NamedTempFile::new_in(root)?;
    let mut file = NamedTempFile::new_in(root)?;
    let mut child = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--fail",
            "--globoff",
            "--location",
            "--max-redirs",
            "8",
            "--proto",
            "=http,https",
            "--proto-redir",
            "=http,https",
            "--max-time",
            "300",
            "--user-agent",
            "nfqws2-strategy/geo-auto",
            "--dump-header",
        ])
        .arg(headers.path())
        .arg("--")
        .arg(url.trim())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("curl для загрузки Geo недоступен: {e}")))?;
    let src = child.stdout.take().expect("piped stdout");
    let copied = io::copy(&mut src.take(MAX_FILE + 1), file.as_file_mut());
    if !matches!(&copied, Ok(len) if *len <= MAX_FILE) {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let size = copied?;
    if size > MAX_FILE {
        return Err(invalid("geo file exceeds 128 MiB"));
    }
    if !status.success() {
        return Err(io::Error::other(format!(
            "curl завершился с кодом {}",
            status
        )));
    }
    completed_response(fs::File::open(headers.path())?, size)?;
    Ok((file, size))
}

fn fetch(s: &Shared) -> io::Result<Auto> {
    fetch_with(s, download)
}

fn fetch_with(
    s: &Shared,
    mut download: impl FnMut(&Path, &str) -> io::Result<(NamedTempFile, u64)>,
) -> io::Result<Auto> {
    let mut config = load(s)?;
    if !backend::available() {
        config.last_error = "модуль GeoSite/GeoIP не установлен".into();
        return Ok(config);
    }
    {
        let mut last = s.geo.last_start.lock().unwrap();
        if last.is_some_and(|t| t.elapsed() < FETCH_INTERVAL) {
            config.last_error = "слишком часто: подождите 15 минут между запросами".into();
            return Ok(config);
        }
        *last = Some(Instant::now());
    }
    let directory = dir(&s.config.data_dir)?;
    let mut errors = Vec::new();
    for (k, name, url) in [
        ("geosite", "geosite.dat", &config.geosite_url),
        ("geoip", "geoip.dat", &config.geoip_url),
    ] {
        let result = download(&directory, url).and_then(|(file, size)| {
            commit(&s.store, &s.config.data_dir, file, name, k)?;
            Ok(size)
        });
        match result {
            Ok(size) if k == "geosite" => {
                config.last_geosite_len = size;
                config.last_geosite_at = now();
            }
            Ok(size) => {
                config.last_geoip_len = size;
                config.last_geoip_at = now();
            }
            Err(error) => errors.push(format!("{k}: {error}")),
        }
    }
    s.store.transaction(|tx| {
        let mut current = load(s)?;
        current.last_geosite_at = config.last_geosite_at;
        current.last_geosite_len = config.last_geosite_len;
        current.last_geoip_at = config.last_geoip_at;
        current.last_geoip_len = config.last_geoip_len;
        current.last_fetched_at = now();
        current.last_error = errors.join("; ");
        tx.save(AUTO, &current)?;
        Ok(current)
    })
}
async fn fetch_now(State(s): State<Shared>) -> Result<Json<Auto>, ApiError> {
    blocking(move || fetch(&s).map(Json)).await
}
pub fn start_auto(state: &Shared) {
    let weak = Arc::downgrade(state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let Some(state) = weak.upgrade() else { break };
            let _ = blocking(move || {
                if backend::available() {
                    let config = load(&state)?;
                    let elapsed = now().saturating_sub(config.last_fetched_at);
                    if config.enabled
                        && (config.last_fetched_at == 0
                            || elapsed >= config.interval_hours.saturating_mul(3600))
                    {
                        fetch(&state)?;
                    }
                }
                Ok(())
            })
            .await;
        }
    });
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/geo/auto", get(get_config).post(save))
        .route("/api/geo/fetch-now", post(fetch_now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn fetch_preserves_config_edits_and_failed_database_then_throttles() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let config = nfqws2_config::Config {
            data_dir: root.to_string_lossy().into(),
            ..nfqws2_config::Config::from_resolver(&nfqws2_config::Resolver::new_at(root))
        };
        let state = crate::http::AppState::open(config, root, true).unwrap();
        let directory = dir(&state.config.data_dir).unwrap();
        fs::write(directory.join("geoip.dat"), b"original").unwrap();
        let mut n = 0;
        let result = fetch_with(&state, |path, _| {
            n += 1;
            if n == 1 {
                state.store.transaction(|tx| {
                    tx.save(
                        AUTO,
                        &Auto {
                            enabled: true,
                            interval_hours: 36,
                            ..Default::default()
                        },
                    )
                })?;
                let mut file = NamedTempFile::new_in(path)?;
                file.write_all(b"new")?;
                Ok((file, 3))
            } else {
                Err(invalid("truncated response"))
            }
        })
        .unwrap();
        if !backend::available() {
            assert_eq!(n, 0);
            assert!(result.last_error.contains("не установлен"));
            assert!(!root.join(AUTO).exists());
            return;
        }
        assert_eq!(n, 2);
        assert!(result.enabled);
        assert_eq!(result.interval_hours, 36);
        assert_eq!(result.last_geosite_len, 3);
        assert!(result.last_error.contains("truncated response"));
        assert_eq!(fs::read(directory.join("geoip.dat")).unwrap(), b"original");
        assert_eq!(fs::read(directory.join("geosite.dat")).unwrap(), b"new");
        assert!(
            fetch_with(&state, |_, _| panic!("download should be throttled"))
                .unwrap()
                .last_error
                .contains("часто")
        );
    }
    #[test]
    fn rejects_partial_responses_and_checks_final_redirect_headers() {
        for headers in [
            "HTTP/1.1 206 Partial Content\r\n",
            "HTTP/2 200\r\ncontent-range: bytes 0-1/5\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n",
            "HTTP/2 200\r\nContent-Length: 2\r\nContent-Length: 4\r\n",
            "HTTP/2 403\r\n",
        ] {
            assert!(completed_response(headers.as_bytes(), 2).is_err());
        }
        assert!(completed_response(
            b"HTTP/2 301\r\nContent-Length: 0\r\n\r\nHTTP/2 200\r\nContent-Length: 2\r\n"
                .as_slice(),
            2
        )
        .is_ok());
    }
}
