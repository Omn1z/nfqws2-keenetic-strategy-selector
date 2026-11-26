use super::{cancelled, trace_ip, AtomicBool};
use crate::invalid;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, client::conn::http1, header, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpSocket, time::timeout};
use tokio_rustls::{rustls, TlsConnector};

mod routes;
const ADDRESS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const MARK: u32 = 0x60000000;
const MAX_BODY: usize = 4096;

async fn http(io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin) -> io::Result<IpAddr> {
    let (mut send, conn) = http1::Builder::new()
        .max_buf_size(16 * 1024)
        .handshake(TokioIo::new(io))
        .await
        .map_err(io::Error::other)?;
    let request = Request::get("/cdn-cgi/trace")
        .header(header::HOST, "1.1.1.1")
        .header(header::CONNECTION, "close")
        .header(header::USER_AGENT, "nfqws2-strategy/connection-test")
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    let response = async {
        let mut response = send.send_request(request).await.map_err(io::Error::other)?;
        if response.status() != StatusCode::OK {
            return Err(invalid(&format!(
                "HTTPS: статус {}",
                response.status().as_u16()
            )));
        }
        let mut body = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                if body.len() + data.len() > MAX_BODY {
                    return Err(invalid("слишком большой ответ HTTPS-проверки"));
                }
                body.extend_from_slice(&data);
            }
        }
        trace_ip(std::str::from_utf8(&body).map_err(io::Error::other)?)
    };
    // Keep the request and its driver inside the cancellation scope.
    tokio::pin!(response, conn);
    tokio::select! {
        result = &mut response => result,
        _ = &mut conn => response.await,
    }
}

async fn sample(iface: &str, config: Arc<rustls::ClientConfig>) -> io::Result<IpAddr> {
    let socket = TcpSocket::new_v4()?;
    let options = socket2::SockRef::from(&socket);
    options.bind_device(Some(iface.as_bytes()))?;
    options.set_mark(MARK)?;
    let stream = timeout(
        Duration::from_secs(4),
        socket.connect(SocketAddr::from((ADDRESS, 443))),
    )
    .await??;
    let server = rustls::pki_types::ServerName::IpAddress(IpAddr::V4(ADDRESS).into());
    let tls = TlsConnector::from(config).connect(server, stream).await?;
    http(tls).await
}

async fn wait_for_cancel(cancel: Option<&AtomicBool>) -> io::Result<IpAddr> {
    let Some(cancel) = cancel else {
        return std::future::pending().await;
    };
    loop {
        cancelled(cancel)?;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub(super) fn run(iface: &str, cancel: Option<&AtomicBool>) -> io::Result<IpAddr> {
    if let Some(cancel) = cancel {
        cancelled(cancel)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(nfqws2_tls_roots::load()?)
    .with_no_client_auth();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut routes = routes::Lease::install(iface)?;
    let result = runtime.block_on(async {
        tokio::select! {
            biased;
            result = wait_for_cancel(cancel) => result,
            result = timeout(Duration::from_secs(10), sample(iface, Arc::new(config))) => result?,
        }
    });
    match (result, routes.release()) {
        (Ok(ip), Ok(())) => Ok(ip),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
            "{error}. Снятие маршрутов проверки: {cleanup}"
        ))),
    }
}
