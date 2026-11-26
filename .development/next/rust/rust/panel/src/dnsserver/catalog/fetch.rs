use super::super::vpn::Route;
use super::{index::LIMIT, Engine};
use axum::{
    body::Bytes,
    http::{header, Request, StatusCode},
};
use http_body_util::{BodyExt, Full};
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use tempfile::{NamedTempFile, TempPath};
use tokio::{fs::File, io::AsyncWriteExt, time::timeout};

pub(super) const HOST: &str = "adguardteam.github.io";
const PATH: &str = "/AdGuardSDNSFilter/Filters/filter.txt";

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && b & 192 == 64)
                && !(a == 198 && matches!(b, 18 | 19))
                && !(a == 192 && b == 0 && c == 0)
        }
        IpAddr::V6(v) => {
            v.segments()[0] & 0xe000 == 0x2000
                && !(v.segments()[0] == 0x2001 && v.segments()[1] == 0xdb8)
        }
    }
}
pub(super) async fn download(e: &Engine, dir: &Path) -> io::Result<TempPath> {
    e.cfg.check_runtime()?;
    let routes = e.vpn.eligible(&e.cfg).await?;
    try_routes(routes, |route| async move {
        download_route(e, dir, &route).await
    })
    .await
}

async fn try_routes<T, F: Future<Output = io::Result<T>>>(
    mut routes: Vec<Route>,
    fetch: impl Fn(Route) -> F,
) -> io::Result<T> {
    routes.sort_by_key(|route| !route.id.starts_with("awg:"));
    let multiple = routes.len() > 1;
    let mut failures = Vec::new();
    for route in routes {
        let id = route.id.clone();
        let attempt = fetch(route);
        let result = if multiple {
            timeout(Duration::from_secs(45), attempt)
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        } else {
            attempt.await
        };
        match result {
            Ok(path) => return Ok(path),
            Err(error) => failures.push(format!("{id}: {error}")),
        }
    }
    Err(io::Error::other(format!(
        "не удалось скачать список DNS-блокировки: {}",
        failures.join(", ")
    )))
}

async fn download_route(e: &Engine, dir: &Path, route: &Route) -> io::Result<TempPath> {
    let addresses = e
        .transport
        .bootstrap_addresses(HOST, route, &e.methods)
        .await?;
    let mut last = io::Error::other("у издателя списка DNS нет публичных адресов");
    for ip in addresses.into_iter().filter(|ip| public(*ip)).take(4) {
        match timeout(
            Duration::from_secs(30),
            fetch_at(&e.transport, SocketAddr::new(ip, 443), dir, route),
        )
        .await
        {
            Ok(Ok(path)) => return Ok(path),
            Ok(Err(e)) => last = e,
            Err(_) => last = io::ErrorKind::TimedOut.into(),
        }
    }
    Err(last)
}
pub(super) async fn fetch_at(
    transport: &super::super::transport::Doh,
    addr: SocketAddr,
    dir: &Path,
    route: &Route,
) -> io::Result<TempPath> {
    let mut sender = transport.connect_pinned(HOST, vec![addr], route).await?;
    let req = Request::get(format!("https://{HOST}{PATH}"))
        .header(header::HOST, HOST)
        .header(header::CONNECTION, "close")
        .header(header::ACCEPT, "text/plain")
        .body(Full::new(Bytes::new()))
        .map_err(io::Error::other)?;
    let mut response = sender.send_request(req).await?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::other(format!("HTTP {}", response.status())));
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| {
            matches!(
                s.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "text/html" | "application/xhtml+xml"
            )
        })
    {
        return Err(io::Error::other("сервер вернул HTML вместо списка"));
    }
    if response
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v != "identity")
    {
        return Err(io::Error::other("неподдерживаемая кодировка списка"));
    }
    let expected = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|h| {
            h.to_str()
                .map_err(io::Error::other)?
                .parse::<u64>()
                .map_err(io::Error::other)
        })
        .transpose()?;
    if expected.is_some_and(|v| v > LIMIT as u64) {
        return Err(io::Error::other("список превышает 8 МиБ"));
    }
    let (file, path) = NamedTempFile::new_in(dir)?.into_parts();
    let mut file = tokio::io::BufWriter::with_capacity(32 * 1024, File::from_std(file));
    let mut written = 0;
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(io::Error::other)?;
        if let Some(data) = frame.data_ref() {
            written += data.len();
            if written > LIMIT {
                return Err(io::Error::other("список превышает 8 МиБ"));
            }
            file.write_all(data).await?;
        }
    }
    if written == 0 || expected.is_some_and(|n| n != written as u64) {
        return Err(io::Error::other("неполная загрузка списка DNS"));
    }
    file.flush().await?;
    file.get_ref().sync_all().await?;
    drop(file);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn catalog_download_prefers_awg_and_uses_only_policy_eligible_fallbacks() {
        use crate::dnsserver::{
            config::{defaults, Config},
            vpn::Source,
        };
        use std::sync::Mutex;

        let source = Source::with(|| {
            Ok([("first", true), ("down", false), ("second", true)]
                .map(|(id, available)| Route {
                    id: format!("awg:{id}"),
                    name: id.into(),
                    interface: "awg0".into(),
                    available,
                    index: 1,
                })
                .into())
        });
        let seen = &Mutex::new(Vec::new());
        let cfg = Config {
            awg_fallback: "auto".into(),
            ..Config::from_value(&defaults()).unwrap()
        };
        let routes = source.eligible(&cfg).await.unwrap();
        let winner = try_routes(routes.clone(), |route| async move {
            seen.lock().unwrap().push(route.id.clone());
            if route.id == "awg:first" {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            Ok(route.id.clone())
        })
        .await
        .unwrap();
        assert_eq!(winner, "awg:second");
        assert_eq!(
            std::mem::take(&mut *seen.lock().unwrap()),
            ["awg:first", "awg:second"]
        );
        let winner = try_routes(routes, |route| async move {
            seen.lock().unwrap().push(route.id.clone());
            if route.id == "nfqws" {
                return Ok(route.id.clone());
            }
            Err(io::ErrorKind::ConnectionRefused.into())
        })
        .await
        .unwrap();
        assert_eq!(winner, "nfqws");
        assert_eq!(
            &*seen.lock().unwrap(),
            &["awg:first", "awg:second", "nfqws"]
        );

        let strict = Config {
            route_mode: "vpn_only".into(),
            awg_fallback: "second".into(),
            ..cfg
        };
        let routes = source.eligible(&strict).await.unwrap();
        let failed = try_routes::<(), _>(routes, |route| async move {
            assert_eq!(route.id, "awg:second");
            Err(io::ErrorKind::ConnectionRefused.into())
        })
        .await
        .unwrap_err();
        assert!(failed.to_string().contains("awg:second"));
        assert!(!failed.to_string().contains("nfqws"));
    }

    #[test]
    fn rejects_private_and_special_addresses() {
        for ip in [
            "0.0.0.1",
            "10.0.0.1",
            "127.1.2.3",
            "100.96.1.1",
            "169.254.1.1",
            "192.168.0.1",
            "198.51.100.6",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["185.199.108.153", "2606:50c0:8000::153"] {
            assert!(public(ip.parse().unwrap()));
        }
    }
}
