//! Release metadata and standalone executable updates.
use crate::http::{ApiError, Shared};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{io, sync::Mutex};
#[cfg(all(target_os = "linux", feature = "compact"))]
mod compact;
#[cfg(all(feature = "compact", any(test, target_os = "linux")))]
mod compact_version;
#[cfg(not(feature = "compact"))]
mod release;
#[cfg(feature = "compact")]
fn update_help() -> &'static str {
    use nfqws2_config::{Platform, Resolver};
    match Resolver::current().platform() {
        Platform::OpenWrt => {
            "Обновите компактную панель и её модули через пакетный менеджер OpenWrt (apk или opkg)"
        }
        Platform::Entware => "Обновите компактную панель и её модули через Entware (opkg)",
    }
}
#[cfg(all(not(feature = "compact"), not(target_os = "linux")))]
fn update_help() -> &'static str {
    "установка обновления доступна в Linux"
}
pub struct Pending {
    #[cfg(all(target_os = "linux", not(feature = "compact")))]
    binary: release::Binary,
}
impl Pending {
    pub fn activate(self) -> io::Result<()> {
        #[cfg(all(target_os = "linux", not(feature = "compact")))]
        {
            self.binary.activate()
        }
        #[cfg(any(not(target_os = "linux"), feature = "compact"))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}
#[derive(Default)]
pub struct Updater {
    state: Mutex<Job>,
    ready: Mutex<Option<Pending>>,
}
#[derive(Default, Clone, Serialize, serde::Deserialize)]
struct Job {
    running: bool,
    current: String,
    latest: String,
    stage: String,
    started_at: u64,
    finished_at: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
}
impl Updater {
    pub fn take_binary(&self) -> Option<Pending> {
        self.ready.lock().unwrap().take()
    }
    pub fn running(&self) -> bool {
        self.state.lock().unwrap().running
    }
    fn view(&self, current: &str) -> Job {
        let mut st = self.state.lock().unwrap().clone();
        if st.stage.is_empty() {
            st.current = current.into();
            st.stage = "idle".into();
        }
        st
    }
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/update/check", get(check))
        .route("/api/update/status", get(status))
        .route("/api/update", post(start))
}
async fn status(State(s): State<Shared>) -> Json<Job> {
    let job = s.update.view(&s.config.version);
    #[cfg(all(target_os = "linux", feature = "compact"))]
    let job = compact::status(&s, job);
    Json(job)
}
async fn check(State(s): State<Shared>) -> Json<Value> {
    let response = check_version(&s.config).await.unwrap_or_else(
        |e| json!({"current":s.config.version,"latest":"","available":false,"error":e.to_string()}),
    );
    Json(response)
}
pub(crate) async fn check_version(config: &nfqws2_config::Config) -> io::Result<Value> {
    #[cfg(all(feature = "compact", target_os = "linux"))]
    {
        compact::check(config).await
    }
    #[cfg(all(feature = "compact", not(target_os = "linux")))]
    {
        let _ = config;
        Err(io::Error::new(io::ErrorKind::Unsupported, update_help()))
    }
    #[cfg(not(feature = "compact"))]
    {
        release::latest(&config.repo, &config.version)
            .await
            .map(|r| r.view(&config.version))
    }
}
pub(crate) async fn install_cli(config: &nfqws2_config::Config) -> io::Result<String> {
    #[cfg(all(target_os = "linux", not(feature = "compact")))]
    {
        release::install_cli(config).await
    }
    #[cfg(all(feature = "compact", target_os = "linux"))]
    {
        compact::install_cli(config).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(io::Error::new(io::ErrorKind::Unsupported, update_help()))
    }
}
async fn start(State(s): State<Shared>) -> Result<(StatusCode, Json<Job>), ApiError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = s;
        Err(ApiError(StatusCode::BAD_REQUEST, update_help().into()))
    }
    #[cfg(target_os = "linux")]
    {
        let mut st = s.update.state.lock().unwrap();
        if !st.running {
            *st = Job {
                running: true,
                current: s.config.version.clone(),
                stage: "queued".into(),
                started_at: now(),
                ..Default::default()
            };
            #[cfg(not(feature = "compact"))]
            tokio::spawn(release::update(s.clone()));
            #[cfg(feature = "compact")]
            tokio::spawn(compact::update(s.clone()));
        }
        Ok((StatusCode::ACCEPTED, Json(st.clone())))
    }
}

#[cfg(target_os = "linux")]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
