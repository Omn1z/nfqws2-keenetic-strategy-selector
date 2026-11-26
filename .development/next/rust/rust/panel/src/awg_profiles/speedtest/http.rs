use axum::http::{header, Request, Response, Uri};
use http_body_util::Empty;
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream},
    sync::OnceCell,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};

#[derive(Clone, Copy)]
pub(super) enum Binding<'a> {
    Device(&'a str),
    #[cfg(test)]
    Loopback,
}

pub(super) fn target(url: &str) -> io::Result<Uri> {
    let uri = url.parse::<Uri>().map_err(io::Error::other)?;
    if url.len() > 8192
        || !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.host().is_none_or(str::is_empty)
        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
        || url.contains(['\\', '#'])
    {
        return Err(io::Error::other(
            "укажите HTTP или HTTPS URL без логина и пароля",
        ));
    }
    Ok(uri)
}

fn resolve_redirect(base: &Uri, location: &str) -> io::Result<Uri> {
    let location = location.split('#').next().unwrap_or_default();
    if location.starts_with("//") {
        return target(&format!("{}:{location}", base.scheme_str().unwrap()));
    }
    if location
        .split(['/', '?'])
        .next()
        .is_some_and(|part| part.contains(':'))
    {
        return target(location);
    }
    let path = if location.is_empty() {
        return Ok(base.clone());
    } else if location.starts_with('/') {
        location.to_owned()
    } else if location.starts_with('?') {
        format!("{}{location}", base.path())
    } else {
        format!(
            "{}/{location}",
            base.path().rsplit_once('/').map_or("", |(dir, _)| dir)
        )
    };
    let (path, query) = path
        .find('?')
        .map_or((path.as_str(), ""), |i| path.split_at(i));
    let mut parts = Vec::new();
    for part in path.split('/').skip(1) {
        match part {
            "." => (),
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    if path.ends_with("/.") || path.ends_with("/..") {
        parts.push("");
    }
    target(&format!(
        "{}://{}/{}{query}",
        base.scheme_str().unwrap(),
        base.authority().unwrap(),
        parts.join("/")
    ))
}

fn socket(binding: Binding<'_>) -> io::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    match binding {
        Binding::Device(device) => bind_device(&socket, device)?,
        #[cfg(test)]
        Binding::Loopback => socket.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?,
    }
    Ok(socket)
}

#[cfg(target_os = "linux")]
fn bind_device(socket: &TcpSocket, device: &str) -> io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    socket.bind_device(Some(device.as_bytes()))?;
    // Both operations must succeed before the first SYN. The mark bypasses
    // only the AWG payload policy and the device still constrains routing.
    socket.set_mark(nfqws2_awg_profile::DIRECT_SOCKET_MARK)
}

#[cfg(not(target_os = "linux"))]
fn bind_device(_: &TcpSocket, _: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "замер AWG требует Linux",
    ))
}

async fn dial(host: &str, port: u16, binding: Binding<'_>) -> io::Result<TcpStream> {
    timeout(Duration::from_secs(4), async {
        let addresses = tokio::net::lookup_host((host, port)).await?;
        let mut last = io::Error::other("у источника нет адреса IPv4");
        for addr in addresses.filter(SocketAddr::is_ipv4) {
            match socket(binding)?.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last = err,
            }
        }
        Err(last)
    })
    .await?
}

pub(super) struct Exchange {
    pub response: Response<Incoming>,
    _driver: Driver,
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn request(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    uri: &Uri,
    max_bytes: i64,
) -> io::Result<Exchange> {
    let req = Request::get(uri.path_and_query().map_or("/", |p| p.as_str()))
        .header(header::HOST, uri.authority().unwrap().as_str())
        .header(header::CONNECTION, "close")
        .header(header::USER_AGENT, "nfqws2-strategy/speedtest")
        .header(header::RANGE, format!("bytes=0-{}", max_bytes - 1))
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    let (mut sender, conn) = http1::Builder::new()
        .max_buf_size(64 * 1024)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    // Keep cancellation scoped to this request, including a stalled header.
    let driver = Driver(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let response = timeout(Duration::from_secs(10), sender.send_request(req))
        .await?
        .map_err(io::Error::other)?;
    Ok(Exchange {
        response,
        _driver: driver,
    })
}

fn tls_config(roots: RootCertStore) -> io::Result<TlsConnector> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn open(uri: &Uri, binding: Binding<'_>, max_bytes: i64) -> io::Result<Exchange> {
    let host = uri.host().unwrap();
    let https = uri.scheme_str() == Some("https");
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let stream = dial(host, port, binding).await?;
    if https {
        static TLS: OnceCell<TlsConnector> = OnceCell::const_new();
        let tls = TLS
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(|| tls_config(nfqws2_tls_roots::load()?))
                    .await
                    .map_err(io::Error::other)?
            })
            .await?;
        let name = ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let stream = timeout(Duration::from_secs(8), tls.connect(name, stream)).await??;
        request(stream, uri, max_bytes).await
    } else {
        request(stream, uri, max_bytes).await
    }
}

pub(super) async fn get(url: &str, binding: Binding<'_>, max_bytes: i64) -> io::Result<Exchange> {
    let mut uri = target(url)?;
    for _ in 0..10 {
        let exchange = open(&uri, binding, max_bytes).await?;
        if let Some(location) = exchange
            .response
            .headers()
            .get(header::LOCATION)
            .filter(|_| {
                matches!(
                    exchange.response.status().as_u16(),
                    301 | 302 | 303 | 307 | 308
                )
            })
        {
            uri = resolve_redirect(&uri, location.to_str().map_err(io::Error::other)?)?;
        } else {
            return Ok(exchange);
        }
    }
    Err(io::Error::other("слишком много переадресаций HTTP"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };
    use tokio_rustls::{
        rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig},
        TlsAcceptor,
    };

    async fn headers(stream: &mut BufReader<impl AsyncRead + Unpin>) -> String {
        let mut headers = String::new();
        loop {
            let prior = headers.len();
            assert_ne!(stream.read_line(&mut headers).await.unwrap(), 0);
            if &headers[prior..] == "\r\n" {
                return headers;
            }
        }
    }

    #[tokio::test]
    async fn reads_body_over_verified_tls_and_rejects_a_wrong_name() {
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = local.local_addr().unwrap();
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = identity.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let tls = tls_config(roots).unwrap();
        let accept = TlsAcceptor::from(Arc::new(
            ServerConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key.into())
            .unwrap(),
        ));
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(
                accept
                    .accept(local.accept().await.unwrap().0)
                    .await
                    .unwrap(),
            );
            assert!(headers(&mut stream).await.contains("range: bytes=0-2"));
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\n\r\nabc")
                .await
                .unwrap();
            assert!(accept
                .accept(local.accept().await.unwrap().0)
                .await
                .is_err());
        });
        let uri = target("https://localhost/test").unwrap();
        let stream = dial("localhost", address.port(), Binding::Loopback)
            .await
            .unwrap();
        let stream = tls
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        let mut exchange = request(stream, &uri, 3).await.unwrap();
        assert_eq!(exchange.response.status().as_u16(), 206);
        let mut bytes = Vec::new();
        while let Some(frame) = exchange.response.body_mut().frame().await {
            bytes.extend_from_slice(&frame.unwrap().into_data().unwrap());
        }
        assert_eq!(bytes, b"abc");
        let stream = dial("localhost", address.port(), Binding::Loopback)
            .await
            .unwrap();
        assert!(tls
            .connect(ServerName::try_from("foreign.test").unwrap(), stream)
            .await
            .is_err());
        server.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a privileged isolated Linux test guest"]
    async fn marked_device_socket_uses_its_reserved_policy() {
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = socket(Binding::Device("lo")).unwrap();
        let options = socket2::SockRef::from(&socket);
        assert_eq!(options.device().unwrap().as_deref(), Some(b"lo".as_slice()));
        assert_eq!(
            options.mark().unwrap(),
            nfqws2_awg_profile::DIRECT_SOCKET_MARK
        );
        let stream = socket.connect(local.local_addr().unwrap()).await.unwrap();
        assert_eq!(
            socket2::SockRef::from(&stream).mark().unwrap(),
            nfqws2_awg_profile::DIRECT_SOCKET_MARK
        );
        assert_eq!(
            local.accept().await.unwrap().1,
            stream.local_addr().unwrap()
        );
        assert!(super::socket(Binding::Device("n2s-missing")).is_err());

        if let Ok(address) = std::env::var("N2S_SPEEDTEST_QA_ADDRESS") {
            let local = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let destination = SocketAddr::from((
                address.parse::<std::net::Ipv4Addr>().unwrap(),
                local.local_addr().unwrap().port(),
            ));
            for (mark, bind) in [(false, false), (true, false), (false, true)] {
                let socket = TcpSocket::new_v4().unwrap();
                let options = socket2::SockRef::from(&socket);
                if mark {
                    options
                        .set_mark(nfqws2_awg_profile::DIRECT_SOCKET_MARK)
                        .unwrap();
                }
                if bind {
                    options.bind_device(Some(b"lo")).unwrap();
                }
                let result = timeout(Duration::from_secs(1), socket.connect(destination)).await;
                assert!(
                    matches!(result, Ok(Err(_))),
                    "mark={mark} bind={bind} {result:?}"
                );
            }
            let server = tokio::spawn(async move {
                let mut stream = BufReader::new(local.accept().await.unwrap().0);
                assert!(headers(&mut stream).await.contains("range: bytes=0-2"));
                stream
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
                    .await
                    .unwrap();
            });
            let mut exchange = get(&format!("http://{destination}/"), Binding::Device("lo"), 3)
                .await
                .unwrap();
            assert_eq!(exchange.response.status().as_u16(), 200);
            assert_eq!(
                exchange
                    .response
                    .body_mut()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes(),
                b"abc".as_slice()
            );
            server.await.unwrap();
        }
    }
}
