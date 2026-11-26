use crate::http::{blocking, ApiError, Shared};
use axum::{extract::State, http::HeaderMap, response::Response, routing::get, Json, Router};
use nfqws2_monitor::{Devices, Monitor, NetworkDashboard, NetworkMonitor, SystemInfo};
use serde::Serialize;
use std::{path::Path, sync::Mutex};

pub struct MonitorState {
    system: Mutex<Monitor>,
    net: Mutex<NetworkMonitor>,
}
impl MonitorState {
    pub fn new(root: &Path, wan_ifaces: &[String]) -> Self {
        let proc = root.join("proc");
        Self {
            system: Mutex::new(Monitor::new(&proc, root.join("sys/class/thermal"))),
            net: Mutex::new(NetworkMonitor::new(proc, root).with_wan_ifaces(wan_ifaces)),
        }
    }
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/dashboard", get(dashboard))
        .route("/api/connections", get(connections))
        .route("/api/devices", get(devices))
}
#[derive(Serialize)]
struct Dashboard {
    #[serde(flatten)]
    network: NetworkDashboard,
    system: SystemInfo,
    dnsserver: serde_json::Value,
    tgws: serde_json::Value,
    socks5: serde_json::Value,
    trace_counters: crate::trace::awg::TraceCounters,
    #[serde(skip_serializing_if = "Option::is_none")]
    awg: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    awg_error: Option<String>,
}
async fn dashboard(
    State(s): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<Dashboard>, ApiError> {
    let (dnsserver, socks5, Json(tgws)) = tokio::join!(
        s.dnsserver.dashboard(),
        s.socks5.dashboard(),
        crate::tgws::snapshot(&s, &headers),
    );
    blocking(move || {
        let network = s
            .monitor
            .net
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dashboard(
                &s.config.wan_ifaces,
                s.config.main_queue,
                Path::new(&s.config.data_dir),
            );
        let system = s
            .monitor
            .system
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot();
        let (awg, awg_error) = match nfqws2_awg_profile::dashboard(
            &s.store,
            Path::new(&s.config.data_dir),
            &s.awg_runtime,
        ) {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Ok(Json(Dashboard {
            awg,
            awg_error,
            network,
            system,
            dnsserver,
            tgws,
            socks5,
            trace_counters: s.trace.awg.counters(),
        }))
    })
    .await
}
async fn connections(State(s): State<Shared>) -> Result<Response, ApiError> {
    crate::http::json_stream(move |out| {
        let reader = s
            .monitor
            .net
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .connection_reader()
            .map_err(std::io::Error::other)?;
        out.write_all(br#"{"items":["#)?;
        let mut count = 0usize;
        reader.visit(|row| {
            if count > 0 {
                out.write_all(b",")?;
            }
            serde_json::to_writer(&mut *out, &row)?;
            count += 1;
            Ok(())
        })?;
        write!(out, "],\"count\":{count}}}")
    })
    .await
}
async fn devices(State(s): State<Shared>) -> Result<Json<Devices>, ApiError> {
    blocking(move || {
        s.monitor
            .net
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .devices()
            .map(Json)
    })
    .await
}
