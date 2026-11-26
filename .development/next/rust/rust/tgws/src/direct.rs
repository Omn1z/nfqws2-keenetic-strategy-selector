//! Telegram direct WebSocket transport and the opt-in legacy SNI front.
use crate::{relay, Stats};
use nfqws2_tgws_config::fallback::Telegram;
use std::{
    future::Future,
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    time::{timeout_at, Instant},
};
use tokio_rustls::{
    rustls::{
        client::{
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            Resumption, WebPkiServerVerifier,
        },
        crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    },
    TlsConnector,
};

const GO_SNI: &str = "sprinthost.ru";
const TELEGRAM_SUFFIX: &str = ".web.telegram.org";

fn stock_service(domain: &str, path: &str) -> Option<i16> {
    if !matches!(path, "/apiws" | "/apiws_test") {
        return None;
    }
    let dc = domain.strip_prefix("kws")?.strip_suffix(TELEGRAM_SUFFIX)?;
    let dc = dc.strip_suffix("-1").unwrap_or(dc);
    if !matches!(dc, "1" | "2" | "3" | "4" | "5") {
        return None;
    }
    dc.parse().ok()
}

fn sibling_authority(domain: &str, dc: i16) -> io::Result<ServerName<'static>> {
    let sibling = if domain.ends_with("-1.web.telegram.org") {
        ""
    } else {
        "-1"
    };
    ServerName::try_from(format!("kws{dc}{sibling}{TELEGRAM_SUFFIX}")).map_err(io::Error::other)
}

fn redirect_identity(
    redirect: Option<IpAddr>,
    peer: IpAddr,
    fronted_service: Option<i16>,
) -> io::Result<Option<IpAddr>> {
    let stock = IpAddr::from([149, 154, 167, 220]);
    let peer = peer.to_canonical();
    let Some(ip) = redirect.map(|ip| ip.to_canonical()) else {
        let stock_peer = match fronted_service {
            Some(2 | 4) => peer == stock,
            Some(dc) => Telegram::web(dc, false)
                .is_some_and(|front| Telegram::address(peer, 443) == Some(front)),
            None => false,
        };
        return Ok(stock_peer.then_some(peer));
    };
    if ip != peer {
        return Err(io::Error::other("unexpected configured DC peer"));
    }
    // Go materializes the default DC2/4 redirects in its saved file. The
    // stock IP can prove its identity only on an opted-in, fronted attempt.
    if ip == stock && !matches!(fronted_service, Some(2 | 4)) {
        return Ok(None);
    }
    Ok(Some(ip))
}
#[derive(Debug)]
struct VerifyAuthority {
    pki: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
    managed_ip: Option<IpAddr>,
    fronted_sibling: Option<ServerName<'static>>,
}
#[cfg(test)]
mod tests;
impl ServerCertVerifier for VerifyAuthority {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        sni: &ServerName<'_>,
        ocsp: &[u8],
        time: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verify = |name: &ServerName<'_>| {
            self.pki
                .verify_server_cert(cert, intermediates, name, ocsp, time)
        };
        verify(&self.name)
            .or_else(|first| {
                let ip = self.managed_ip.ok_or(first)?;
                verify(&ServerName::IpAddress(ip.into()))
            })
            .or_else(|first| verify(self.fronted_sibling.as_ref().ok_or(first)?))
            .or_else(|first| {
                if self.fronted_sibling.is_some()
                    && matches!(sni, ServerName::DnsName(n) if n.as_ref() == GO_SNI)
                {
                    verify(sni)
                } else {
                    Err(first)
                }
            })
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.pki.verify_tls12_signature(msg, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.pki.verify_tls13_signature(msg, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.pki.supported_verify_schemes()
    }
}
struct Alternate {
    preferred: AtomicBool,
    stats: Arc<Stats>,
    legacy_tls: Option<TlsConnector>,
}

#[derive(Debug)]
struct LegacyFront(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for LegacyFront {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // The legacy Go path deliberately sends a different TLS SNI and
        // HTTP Host. Match its certificate policy for this connection only.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(msg, cert, sig, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(msg, cert, sig, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[derive(Clone)]
pub(super) struct Direct {
    tls: TlsConnector,
    handshakes: crate::handshakes::Handshakes,
    pki: Option<Arc<WebPkiServerVerifier>>,
    alternate: Option<Arc<Alternate>>,
    legacy: bool,
    legacy_errors: Option<Arc<Stats>>,
}
impl Direct {
    pub fn new(tls: TlsConnector, handshakes: crate::handshakes::Handshakes, legacy: bool) -> Self {
        Self {
            tls,
            handshakes,
            pki: None,
            alternate: None,
            legacy,
            legacy_errors: None,
        }
    }
    pub fn report_legacy_errors(&mut self, stats: Arc<Stats>) {
        self.legacy_errors = Some(stats);
    }
    pub fn identities(
        &mut self,
        roots: RootCertStore,
        stats: Option<Arc<Stats>>,
    ) -> io::Result<()> {
        self.pki = if self.legacy || roots.is_empty() {
            None
        } else {
            Some(
                WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    self.tls.config().crypto_provider().clone(),
                )
                .build()
                .map_err(io::Error::other)?,
            )
        };
        self.alternate = stats
            .filter(|_| self.legacy || self.pki.is_some())
            .map(|stats| {
                let legacy_tls = self.legacy.then(|| {
                    let mut cfg = self.tls.config().as_ref().clone();
                    let algs = cfg.crypto_provider().signature_verification_algorithms;
                    cfg.dangerous()
                        .set_certificate_verifier(Arc::new(LegacyFront(algs)));
                    // Keep front tickets separate from ordinary, authenticated TLS.
                    cfg.resumption = Resumption::in_memory_sessions(8);
                    cfg.enable_early_data = false;
                    TlsConnector::from(Arc::new(cfg))
                });
                Arc::new(Alternate {
                    preferred: AtomicBool::new(false),
                    stats,
                    legacy_tls,
                })
            });
        Ok(())
    }
    async fn upgrade(
        &self,
        tcp: TcpStream,
        domain: &str,
        path: &str,
        alternate: bool,
        managed_ip: Option<IpAddr>,
    ) -> io::Result<relay::Ws> {
        let fronted_service =
            stock_service(domain, path).filter(|_| alternate && self.alternate.is_some());
        let managed_ip = redirect_identity(managed_ip, tcp.peer_addr()?.ip(), fronted_service)?;
        if self.legacy {
            let Some(tls) = self
                .alternate
                .as_ref()
                .filter(|_| fronted_service.is_some())
                .and_then(|front| front.legacy_tls.as_ref())
            else {
                return relay::upgrade(tcp, domain, path, &self.tls).await;
            };
            let name = ServerName::try_from(GO_SNI).map_err(io::Error::other)?;
            let secure = tls.connect(name, tcp).await?;
            return nfqws2_tgws_transport::upgrade_tls(secure, domain, path).await;
        }
        let fronted_sibling = fronted_service
            .map(|dc| sibling_authority(domain, dc))
            .transpose()?;
        let Some(pki) = self
            .pki
            .as_ref()
            .filter(|_| alternate || managed_ip.is_some())
        else {
            return relay::upgrade(tcp, domain, path, &self.tls).await;
        };
        let mut config = self.tls.config().as_ref().clone();
        // A ticket keyed by the alternative SNI must never authorize a
        // connection to a different Telegram DC authority.
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        let name = ServerName::try_from(domain.to_owned()).map_err(io::Error::other)?;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(VerifyAuthority {
                pki: pki.clone(),
                name: name.clone(),
                managed_ip,
                fronted_sibling,
            }));
        let sni = if alternate {
            ServerName::try_from(GO_SNI).map_err(io::Error::other)?
        } else {
            name
        };
        let secure = TlsConnector::from(Arc::new(config))
            .connect(sni, tcp)
            .await?;
        nfqws2_tgws_transport::upgrade_tls(secure, domain, path).await
    }
    pub async fn dial<F: Future<Output = io::Result<TcpStream>>>(
        &self,
        domain: &str,
        path: &str,
        buffer: i64,
        managed_ip: Option<IpAddr>,
        socket: impl FnMut(Instant) -> F,
    ) -> io::Result<relay::Ws> {
        self.dial_domains(domain, None, path, buffer, managed_ip, socket)
            .await
    }
    pub async fn dial_domains<F: Future<Output = io::Result<TcpStream>>>(
        &self,
        domain: &str,
        fallback: Option<&str>,
        path: &str,
        buffer: i64,
        managed_ip: Option<IpAddr>,
        mut socket: impl FnMut(Instant) -> F,
    ) -> io::Result<relay::Ws> {
        let mut last_failure = None;
        for domain in std::iter::once(domain).chain(fallback) {
            let enabled =
                self.alternate.is_some() && (!self.legacy || stock_service(domain, path).is_some());
            let first = self
                .alternate
                .as_ref()
                .is_some_and(|s| enabled && s.preferred.load(Ordering::Relaxed));
            for alt in [first, !first]
                .into_iter()
                .take(if enabled { 2 } else { 1 })
            {
                // A full local queue ends this refill across all hostnames.
                // An earlier network failure still determines its backoff.
                let _permit = match self.handshakes.acquire().await {
                    Ok(permit) => permit,
                    Err(e) => return Err(last_failure.unwrap_or(e)),
                };
                let setup_time = if alt { 7 } else { 8 };
                let deadline = Instant::now() + Duration::from_secs(setup_time);
                let run = async {
                    let tcp = socket(deadline).await?;
                    relay::configure_socket(&tcp, buffer);
                    self.upgrade(tcp, domain, path, alt, managed_ip).await
                };
                last_failure = Some(match timeout_at(deadline, run).await {
                    Ok(Ok(ws)) => {
                        if let Some(s) = self.alternate.as_ref().filter(|_| enabled) {
                            s.preferred.store(alt, Ordering::Relaxed);
                            if alt {
                                s.stats.fronting.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        return Ok(ws);
                    }
                    Ok(Err(e)) => e,
                    Err(_) => io::ErrorKind::TimedOut.into(),
                });
                if let Some(stats) = &self.legacy_errors {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Err(last_failure.unwrap_or_else(|| io::Error::other("Telegram TLS WebSocket unavailable")))
    }
}
