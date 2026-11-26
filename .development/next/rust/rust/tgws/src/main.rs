mod catalog;
mod configured;
mod crypto;
mod diagnostics;
mod direct;
mod handshakes;
mod inbound;
mod legacy;
mod listener;
mod media;
mod pool;
mod relay;
#[cfg(test)]
mod tests;
use nfqws2_tgws_config::Config;
use portable_atomic::AtomicU64;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io,
    sync::{atomic::Ordering, Arc},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    task::JoinSet,
};

#[derive(Deserialize)]
struct Start {
    listen: String,
    config: Config,
    #[serde(default)]
    fallback_socket: Option<std::path::PathBuf>,
    #[serde(default)]
    handshake_runtime: Option<std::path::PathBuf>,
}
#[derive(Default)]
struct Stats {
    total: AtomicU64,
    active: AtomicU64,
    ws: AtomicU64,
    cf: AtomicU64,
    fronting: AtomicU64,
    masked: AtomicU64,
    cf_hits: AtomicU64,
    cf_misses: AtomicU64,
    h2: AtomicU64,
    h2_tcp: AtomicU64,
    h2_requests: AtomicU64,
    h2_errors: AtomicU64,
    h2_replays: AtomicU64,
    tcp: AtomicU64,
    vpn: AtomicU64,
    bad: AtomicU64,
    errors: AtomicU64,
    pool_hits: AtomicU64,
    pool_misses: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    started: AtomicU64,
}
impl Stats {
    fn json(&self) -> Value {
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let format = |a: &AtomicU64| nfqws2_tgws_config::human_bytes(n(a));
        json!({"connections":{"total":n(&self.total),"active":n(&self.active),"ws":n(&self.ws),"vpn":n(&self.vpn),"h2":n(&self.h2),"tcp_fallback":n(&self.tcp),"cfproxy":n(&self.cf),"fronting":n(&self.fronting),"bad":n(&self.bad),"masked":n(&self.masked)},
            "traffic":{"bytes_up":n(&self.up),"bytes_down":n(&self.down),"human_up":format(&self.up),"human_down":format(&self.down)},
            "ws":{"errors":n(&self.errors),"pool_hits":n(&self.pool_hits),"pool_misses":n(&self.pool_misses),"cf_pool_hits":n(&self.cf_hits),"cf_pool_misses":n(&self.cf_misses)},
            "h2":{"tcp_connections":n(&self.h2_tcp),"requests":n(&self.h2_requests),"errors":n(&self.h2_errors),"replays":n(&self.h2_replays)},"started_at":n(&self.started)})
    }
}
async fn print(v: &Value) -> io::Result<()> {
    let mut data = serde_json::to_vec(v)?;
    data.push(b'\n');
    let mut out = tokio::io::stdout();
    out.write_all(&data).await?;
    out.flush().await
}
async fn run() -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut input = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    (&mut input).take(65537).read_line(&mut line).await?;
    if line.len() > 65536 {
        return Err(io::Error::other("TG WS config exceeds limit"));
    }
    let Start {
        listen,
        mut config,
        fallback_socket,
        handshake_runtime,
    } = serde_json::from_str(&line)?;
    let fallback_socket = fallback_socket.map(Arc::<std::path::Path>::from);
    drop(line);
    config.normalize()?;
    if !config.requires_go().is_empty() {
        return Err(io::Error::other("TG WS config requires Go transport"));
    }
    let roots = match nfqws2_tls_roots::load() {
        Err(error) if config.transport.is_empty() && error.kind() == io::ErrorKind::NotFound => {
            // The legacy proxy can still use its TCP and explicitly enabled
            // plaintext WS paths. The empty TLS trust store rejects every peer.
            tokio_rustls::rustls::RootCertStore::empty()
        }
        result => result?,
    };
    let connector = nfqws2_tgws_transport::tls_config(roots.clone())?;
    let mut listener = listener::Listener::bind(&listen).await?;
    let stats = Arc::new(Stats::default());
    let limit = usize::try_from(config.pool_size).unwrap_or(usize::MAX);
    let shared_handshakes = handshake_runtime.is_some();
    let handshakes = handshake_runtime
        .as_deref()
        .map(handshakes::Handshakes::adopt)
        .transpose()?
        .unwrap_or_default();
    let mut pool = pool::Pool::with_handshakes(
        limit,
        connector,
        config.buffer_size,
        config.transport.is_empty(),
        handshakes,
    );
    pool.direct
        .identities(roots, config.uses_alternate_sni().then(|| stats.clone()))?;
    if config.transport.is_empty() {
        pool.direct.report_legacy_errors(stats.clone());
    }
    if config.transport.is_empty() {
        pool.enable_diagnostics();
        if config.pool_size > 0 {
            legacy::warm_routes(&pool, &config);
        }
    }
    let pool = Arc::new(pool);
    pool.relays.warm_workers(&config);
    let catalog_pool = Arc::downgrade(&pool);
    pool.relays.start_catalog(&config, move || {
        if let Some(pool) = catalog_pool.upgrade() {
            pool.report_diagnostic(diagnostics::Event::CatalogRefreshFailed);
        }
    });
    let cfg = Arc::new(config);
    let mut clients = JoinSet::new();
    stats.started.store(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        Ordering::Relaxed,
    );
    print(&json!({"ready":true,"shared_handshakes":shared_handshakes,"final_stats":true,"vpn_fallback":true,"legacy_direct":true,"configured_tls_relays":true,"configured_h2_media":true,"legacy_large_pool":true,"native_large_pool":true,"upstream_cf_catalog":true,"upstream_catalog_plain_ws":true,"legacy_alternate_sni":true,"verified_alternate_sni":true,"authenticated_ee_https":true,"configured_plain_ws":true,"stats":stats.json()}))
        .await?;
    let mut commands = input.lines();
    let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let retry_legacy = cfg.transport.is_empty() && cfg.pool_size > 0;
    let maintain_routes = cfg.pool_size > 4 || retry_legacy;
    let report_final = loop {
        tokio::select! {
            _=maintenance.tick(), if maintain_routes || cfg.h2_media() => {
                if maintain_routes {pool.maintain();}
                if cfg.h2_media() {pool.relays.prune_media(&cfg).await;}
            }
            _=pool.wait_for_refill_retry(), if retry_legacy => pool.maintain(),
            command = commands.next_line() => match command?.as_deref() {
                Some("status") => print(&stats.json()).await?,
                Some("stop") => break true,
                None => break false,
                _ => return Err(io::Error::other("invalid TG WS control command")),
            },
            Some(_) = clients.join_next(), if !clients.is_empty() => {},
            stream = listener.accept(|event| pool.report_diagnostic(event)) => {
                clients.spawn(relay::client(stream, cfg.clone(), stats.clone(),fallback_socket.clone(),pool.clone()));
            },
        }
    };
    if report_final {
        pool.mark_planned_stop();
    }
    clients.shutdown().await;
    pool.stop().await;
    if report_final {
        pool.drain_diagnostics().await;
        print(&stats.json()).await?;
    }
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    if let Err(e) = run().await {
        let _ = print(&json!({"ready":false,"error":e.to_string()})).await;
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
