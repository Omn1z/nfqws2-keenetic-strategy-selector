use futures_util::{stream, StreamExt};
use std::{
    collections::BTreeSet,
    future::Future,
    io,
    net::{IpAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::time::{timeout, timeout_at, Instant};

pub(super) fn hosts(text: &str) -> io::Result<(BTreeSet<String>, usize)> {
    let mut hosts = BTreeSet::new();
    let mut invalid = 0;
    for line in text.lines() {
        let entry = line.split(['#', ';']).next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        let hostname = if entry.contains("://") {
            entry.parse::<axum::http::Uri>().ok().and_then(|u| {
                matches!(u.scheme_str(), Some("http" | "https"))
                    .then(|| u.host().map(str::to_owned))
                    .flatten()
            })
        } else {
            Some(entry.to_owned())
        };
        let hostname = hostname.unwrap_or_default();
        let host = hostname.strip_suffix('.').unwrap_or(&hostname);
        if host.len() <= 253
            && host.contains('.')
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            hosts.insert(host.to_ascii_lowercase());
        } else {
            invalid += 1;
        }
    }
    if hosts.is_empty() && invalid > 0 {
        return Err(io::Error::other(
            "NFQUEUE bypass domain list has no valid hostnames",
        ));
    }
    Ok((hosts, invalid))
}

pub(super) async fn system_lookup(host: String) -> io::Result<Vec<IpAddr>> {
    // libc DNS cannot be cancelled mid-call. Hold the permit in the worker so
    // timed-out lookups still count toward the router-wide limit of 16.
    static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
    let slot = SLOTS.acquire().await.map_err(io::Error::other)?;
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        (host.as_str(), 0)
            .to_socket_addrs()
            .map(|v| v.map(|a| a.ip().to_canonical()).collect())
    })
    .await
    .map_err(io::Error::other)?
}

pub(super) async fn resolve<F, Fut>(
    hosts: BTreeSet<String>,
    lookup: F,
) -> io::Result<(String, usize)>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = io::Result<Vec<IpAddr>>>,
{
    let count = hosts.len();
    let mut pending = stream::iter(hosts)
        .map(|h| timeout(Duration::from_secs(2), lookup(h)))
        .buffer_unordered(16);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ips = BTreeSet::new();
    let mut succeeded = 0;
    while let Ok(Some(result)) = timeout_at(deadline, pending.next()).await {
        if let Ok(Ok(addresses)) = result {
            if !addresses.is_empty() {
                succeeded += 1;
                ips.extend(addresses.into_iter().map(|i| i.to_canonical().to_string()));
            }
        }
        if ips.len() > 65536 {
            return Err(io::Error::other("NFQUEUE bypass: превышен предел кэша IP"));
        }
    }
    if count > 0 && ips.is_empty() {
        return Err(io::Error::other(format!(
            "none of {count} NFQUEUE bypass domains resolved"
        )));
    }
    let mut text = String::new();
    for ip in ips {
        text.push_str(&ip);
        text.push('\n');
    }
    Ok((text, count - succeeded))
}
