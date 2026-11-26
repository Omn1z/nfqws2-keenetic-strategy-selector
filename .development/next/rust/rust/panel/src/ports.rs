use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::State,
    http::{header, uri::Authority, HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, Mutex},
};

#[derive(Default)]
pub struct Ports {
    listener: OnceLock<watch::Sender<Arc<TcpListener>>>,
    pub(crate) change: Mutex<()>,
}
pub struct LiveListener(watch::Receiver<Arc<TcpListener>>);
impl axum::serve::Listener for LiveListener {
    type Io = TcpStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (TcpStream, SocketAddr) {
        let mut listening_for_changes = true;
        loop {
            let current = self.0.borrow_and_update().clone();
            tokio::select! {
                biased;
                changed=self.0.changed(), if listening_for_changes=>{listening_for_changes=changed.is_ok();}
                conn=current.accept()=>match conn{Ok(p)=>return p,Err(_)=>tokio::time::sleep(Duration::from_millis(200)).await}
            }
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.borrow().local_addr()
    }
}
impl Ports {
    pub fn attach(&self, socket: Arc<TcpListener>) -> io::Result<LiveListener> {
        let (tx, rx) = watch::channel(socket);
        self.listener
            .set(tx)
            .map_err(|_| io::Error::other("HTTP listener already initialized"))?;
        Ok(LiveListener(rx))
    }
    fn address(&self) -> Option<SocketAddr> {
        self.listener.get()?.borrow().local_addr().ok()
    }
    pub fn socket(&self) -> io::Result<Arc<TcpListener>> {
        self.listener
            .get()
            .map(|tx| tx.borrow().clone())
            .ok_or_else(|| io::Error::other("HTTP listener unavailable"))
    }
    pub(crate) fn port(&self, fallback: &str) -> io::Result<u16> {
        self.address()
            .map(|v| v.port())
            .or_else(|| fallback.rsplit_once(':')?.1.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "неизвестен порт панели"))
    }
}
pub fn routes() -> Router<Shared> {
    Router::new().route("/api/system/ports", get(status).post(update))
}
async fn status(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    let _lock = s.ports.change.lock().await;
    Ok(Json(
        json!({"panel_port":s.ports.port(&s.config.listen_addr)?,"dns_port":s.dnsserver.port().await}),
    ))
}
#[derive(Deserialize)]
struct Change {
    panel_port: Option<u16>,
    dns_port: Option<u16>,
}
fn bad(e: impl ToString) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, e.to_string())
}
fn url(h: &HeaderMap, port: u16) -> Option<String> {
    let a = h
        .get(header::HOST)?
        .to_str()
        .ok()?
        .parse::<Authority>()
        .ok()?;
    if a.as_str().contains('@') || a.host().is_empty() {
        return None;
    }
    Some(format!("http://{}:{port}", a.host()))
}
async fn update(
    State(s): State<Shared>,
    headers: HeaderMap,
    ApiJson(edit): ApiJson<Change>,
) -> Result<Json<Value>, ApiError> {
    // Finish the transaction even if the client disconnects mid-save.
    tokio::spawn(async move {
        let _lock = s.ports.change.lock().await;
        let old = s.ports.port(&s.config.listen_addr)?;
        let old_dns = s.dnsserver.port().await;
        let port = edit.panel_port.unwrap_or(old);
        let dns = edit.dns_port.unwrap_or(old_dns);
        if port == 0 || dns == 0 || port == dns {
            return Err(bad("панели и DNS нужны разные порты в диапазоне 1–65535"));
        }
        let reserved = if port != old {
            let mut addr = s
                .ports
                .address()
                .ok_or_else(|| bad("HTTP listener не запущен"))?;
            addr.set_port(port);
            Some(TcpListener::bind(addr).await.map_err(bad)?)
        } else {
            None
        };
        if dns != old_dns {
            s.dnsserver.change_port(dns).await?;
        }
        let mut out = json!({"panel_port":port,"dns_port":dns});
        if let Some(socket) = reserved {
            let store = s.store.clone();
            if let Err(e) = blocking(move || {
                store.transaction(|tx| tx.save("ports.json", &json!({"panel_port":port})))
            })
            .await
            {
                if dns != old_dns {
                    if let Err(rollback) = s.dnsserver.change_port(old_dns).await {
                        return Err(bad(format!("{}; восстановление DNS: {}", e.1, rollback.1)));
                    }
                }
                return Err(bad(e.1));
            }
            s.ports
                .listener
                .get()
                .expect("bound listener")
                .send_replace(Arc::new(socket));
            if let Some(address) = url(&headers, port) {
                out["panel_url"] = address.into();
            }
        }
        Ok(Json(out))
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}
