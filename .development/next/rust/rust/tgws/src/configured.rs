//! Verified TLS relays selected by the operator's saved TG WS configuration.
use crate::{
    diagnostics::Event,
    handshakes::Handshakes,
    legacy::tcp_destination,
    pool,
    relay::{self, Ws},
    Stats,
};
use futures_util::SinkExt;
use nfqws2_tgws_config::{fallback::connect_named, Config};
use nfqws2_tgws_transport::active;
use rand::seq::SliceRandom;
use std::{
    collections::BTreeMap,
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone)]
struct Connector {
    tls: TlsConnector,
    slots: Handshakes,
    legacy: bool,
    #[cfg(test)]
    peer: Option<std::net::SocketAddr>,
}
impl Connector {
    async fn open(
        &self,
        host: &str,
        path: &str,
        warm_buffer: Option<i64>,
        plain: bool,
    ) -> io::Result<Ws> {
        let _permit = self.slots.acquire().await?;
        // The Go pool reserves for eight seconds using its configured buffers.
        // Foreground fallbacks use the OS window and a ten-second setup.
        let deadline =
            Instant::now() + Duration::from_secs(if warm_buffer.is_some() { 8 } else { 10 });
        timeout_at(deadline, async {
            let port = if plain { 80 } else { 443 };
            #[cfg(test)]
            let socket = match self.peer {
                Some(peer) => TcpStream::connect(peer).await?,
                None => connect_named(host, port, deadline).await?,
            };
            #[cfg(not(test))]
            let socket = connect_named(host, port, deadline).await?;
            if self.legacy {
                nfqws2_tgws_transport::configure_tcp_fallback(&socket);
            }
            if let Some(buffer) = warm_buffer {
                relay::configure_socket(&socket, buffer);
            } else if !self.legacy {
                let _ = socket.set_nodelay(true);
            }
            if plain {
                nfqws2_tgws_transport::upgrade_plain(socket, host, path).await
            } else {
                relay::upgrade(socket, host, path, &self.tls).await
            }
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }
    async fn worker(
        &self,
        dc: u16,
        dst: Ipv4Addr,
        domains: &[String],
        warm_buffer: Option<i64>,
        plain: bool,
        report_failure: impl Fn(u16),
    ) -> Option<Ws> {
        let path = format!("/apiws?dc={dc}&dst={dst}");
        let mut ordered: Vec<_> = domains.iter().collect();
        ordered.shuffle(&mut rand::rng());
        for host in ordered {
            match self.open(host, &path, warm_buffer, plain).await {
                Ok(ws) => return Some(ws),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    if let Some(status) = nfqws2_tgws_transport::ws_rejection_status(&error) {
                        report_failure(status);
                    }
                }
            }
        }
        None
    }
}
struct Slot {
    ready: Arc<AtomicBool>,
    checkout: Option<oneshot::Sender<()>>,
    task: JoinHandle<Option<Ws>>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) struct Relays {
    connector: Connector,
    workers: Mutex<BTreeMap<u16, Slot>>,
    h2: crate::media::Origins,
    catalog: crate::catalog::Catalog,
}
impl Relays {
    pub fn new(tls: TlsConnector, slots: Handshakes, legacy: bool) -> Self {
        Self {
            connector: Connector {
                tls,
                slots,
                legacy,
                #[cfg(test)]
                peer: None,
            },
            workers: Default::default(),
            h2: crate::media::Origins::for_profile(legacy),
            catalog: Default::default(),
        }
    }
    pub fn start_catalog(&self, cfg: &Config, report_failure: impl Fn() + Send + Sync + 'static) {
        if cfg.uses_upstream_catalog() {
            self.catalog
                .start(self.connector.tls.clone(), report_failure);
        }
    }
    pub fn warm_workers(&self, cfg: &Config) {
        if cfg.force_test_dc {
            return;
        }
        for dc in [1, 2, 3, 4, 5, 203] {
            if !cfg
                .dc_redirects
                .as_ref()
                .is_some_and(|r| r.contains_key(&dc))
            {
                self.warm(dc as u16, tcp_destination(dc as i16, false).unwrap(), cfg);
            }
        }
    }
    fn warm(&self, dc: u16, dst: Ipv4Addr, cfg: &Config) {
        let Some(domains) = cfg
            .cfproxy_worker_domains
            .as_ref()
            .filter(|list| !list.is_empty())
        else {
            return;
        };
        if cfg.pool_size == 0 {
            return;
        }
        let mut slots = self.workers.lock().unwrap();
        if slots.get(&dc).is_some_and(|s| !s.task.is_finished()) {
            return;
        }
        let ready = Arc::new(AtomicBool::new(false));
        let (send, mut recv) = oneshot::channel();
        let state = ready.clone();
        let connector = self.connector.clone();
        let domains = domains.clone();
        let buffer = cfg.buffer_size;
        let plain = cfg.disable_secure;
        let task = tokio::spawn(async move {
            let ws = connector
                .worker(dc, dst, &domains, Some(buffer), plain, |_| ())
                .await?;
            timeout(
                Duration::from_secs(100),
                pool::idle(ws, &state, &mut recv, false),
            )
            .await
            .ok()?
        });
        slots.insert(
            dc,
            Slot {
                ready,
                checkout: Some(send),
                task,
            },
        );
    }
    async fn take_worker(&self, dc: u16, dst: Ipv4Addr, cfg: &Config, stats: &Stats) -> Option<Ws> {
        let mut slot = {
            let mut slots = self.workers.lock().unwrap();
            if slots
                .get(&dc)
                .is_some_and(|s| s.ready.load(Ordering::Acquire) && !s.task.is_finished())
            {
                slots.remove(&dc)
            } else {
                None
            }
        };
        if let Some(s) = slot.as_mut() {
            let _ = s.checkout.take()?.send(());
            if let Ok(Ok(Some(ws))) = timeout(Duration::from_secs(3), &mut s.task).await {
                stats.cf_hits.fetch_add(1, Ordering::Relaxed);
                self.warm(dc, dst, cfg);
                return Some(ws);
            }
        }
        stats.cf_misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    pub async fn worker(
        &self,
        dc: i16,
        test: bool,
        cfg: &Config,
        stats: &Stats,
        init: &[u8; 64],
        report_failure: impl Fn(Event),
    ) -> Option<Ws> {
        let domains = cfg
            .cfproxy_worker_domains
            .as_ref()
            .filter(|d| !d.is_empty())?;
        let dst = tcp_destination(dc, test)?;
        let number = dc.unsigned_abs() % 10000;
        let cached = if !test {
            self.take_worker(number, dst, cfg, stats).await
        } else {
            None
        };
        let mut ws = match cached {
            Some(ws) => ws,
            None => {
                self.connector
                    .worker(number, dst, domains, None, cfg.disable_secure, |status| {
                        if self.connector.legacy {
                            report_failure(Event::WorkerUpgradeRejected { dc, test, status });
                        }
                    })
                    .await?
            }
        };
        stats.cf.fetch_add(1, Ordering::Relaxed);
        active::write(ws.send(Message::binary(init.to_vec())))
            .await
            .ok()?;
        Some(ws)
    }
    pub async fn web(
        &self,
        dc: i16,
        test: bool,
        cfg: &Config,
        stats: &Stats,
        init: &[u8; 64],
        report_failure: impl Fn(Event),
    ) -> Option<Ws> {
        if !cfg.cfproxy || test {
            return None;
        }
        let number = dc.unsigned_abs();
        for base in self.catalog.ordered(number, cfg) {
            let host = format!("kws{number}.{base}");
            let mut ws = match self
                .connector
                .open(&host, "/apiws", None, cfg.disable_secure)
                .await
            {
                Ok(ws) => ws,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    if let Some(status) = nfqws2_tgws_transport::ws_rejection_status(&error)
                        .filter(|_| self.connector.legacy)
                    {
                        report_failure(Event::WebUpgradeRejected { dc, status });
                    }
                    continue;
                }
            };
            self.catalog.promote(number, base, cfg);
            stats.cf.fetch_add(1, Ordering::Relaxed);
            active::write(ws.send(Message::binary(init.to_vec())))
                .await
                .ok()?;
            return Some(ws);
        }
        None
    }
    pub async fn media(
        &self,
        dc: i16,
        cfg: &Config,
        stats: &Stats,
    ) -> Option<Arc<crate::media::Lane>> {
        if dc >= 0 || dc.unsigned_abs() >= 10000 || !cfg.h2_media() {
            return None;
        }
        tcp_destination(dc, false)?;
        let number = dc.unsigned_abs();
        let attempt = |deadline, opening: Arc<AtomicBool>| async move {
            self.prune_media(cfg).await;
            for base in self.catalog.ordered(number, cfg) {
                let host = format!("kws{number}.{base}");
                let connect = async {
                    // `get` polls this after the origin lock and setup permit.
                    // The marker stays set while TLS and HEAD are in progress.
                    opening.store(true, Ordering::Relaxed);
                    #[cfg(test)]
                    if let Some(peer) = self.connector.peer {
                        return TcpStream::connect(peer).await;
                    }
                    connect_named(&host, 443, deadline).await
                };
                let result = self
                    .h2
                    .get(
                        &host,
                        &self.connector.tls,
                        &self.connector.slots,
                        connect,
                        stats,
                    )
                    .await;
                opening.store(false, Ordering::Relaxed);
                match result {
                    Ok(lane) => {
                        self.catalog.promote(number, base, cfg);
                        return Some(lane);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => continue,
                }
            }
            None
        };
        self.h2.setup(number, stats, attempt).await
    }
    pub async fn stop(&self) {
        self.catalog.stop().await;
        self.h2.stop().await;
        let slots = std::mem::take(&mut *self.workers.lock().unwrap());
        for s in slots.values() {
            s.task.abort();
        }
        for (_, mut s) in slots {
            let _ = (&mut s.task).await;
        }
    }
    pub async fn prune_media(&self, cfg: &Config) {
        self.h2.prune(|base| self.catalog.contains(base, cfg)).await;
    }
}
