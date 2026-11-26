//! Ordinary TLS passthrough to the profile's single configured HTTPS origin.
//! The end client performs the HTTPS handshake and verifies the certificate.
use super::invalid;
use nfqws2_tgws_config::{fallback::connect_public, valid_domain, Config};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Semaphore,
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::rustls::server::Acceptor;

pub(crate) struct Request {
    domain: String,
    hello: Vec<u8>,
    legacy: bool,
}
impl Request {
    pub(super) fn parse(hello: Vec<u8>, cfg: &Config) -> io::Result<Self> {
        if !valid_domain(&cfg.fake_tls_domain) {
            return Err(invalid());
        }
        let mut accept = Acceptor::default();
        let mut src = hello.as_slice();
        let parsed = loop {
            if src.is_empty() || accept.read_tls(&mut src)? == 0 {
                return Err(invalid());
            }
            if let Some(hello) = accept.accept().map_err(|_| invalid())? {
                if !src.is_empty() {
                    return Err(invalid());
                }
                break hello;
            }
        };
        // Legacy profiles also serve ordinary HTTPS for aliases or clients
        // without SNI. Only the configured domain can select the TCP peer.
        let legacy = cfg.transport.is_empty();
        if !legacy
            && !parsed
                .client_hello()
                .server_name()
                .is_some_and(|sni| sni.eq_ignore_ascii_case(&cfg.fake_tls_domain))
        {
            return Err(invalid());
        }
        Ok(Self {
            domain: cfg.fake_tls_domain.clone(),
            hello,
            legacy,
        })
    }
    pub(super) fn destination(&self) -> (&str, u16) {
        (&self.domain, 443)
    }
    pub(super) fn dial_timeout(&self) -> Duration {
        Duration::from_secs(if self.legacy { 10 } else { 5 })
    }
    pub(super) async fn relay_to(
        &self,
        source: impl AsyncRead + AsyncWrite + Unpin,
        mut target: impl AsyncRead + AsyncWrite + Unpin,
    ) -> io::Result<()> {
        timeout(Duration::from_secs(3), target.write_all(&self.hello))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        transfer(source, target, self.legacy).await
    }
}
pub(crate) struct Origin {
    slots: Semaphore,
}
impl Default for Origin {
    fn default() -> Self {
        Self {
            slots: Semaphore::new(4),
        }
    }
}
impl Origin {
    pub async fn serve(&self, source: BufReader<TcpStream>, request: &Request) -> io::Result<()> {
        let _slot = self
            .slots
            .try_acquire()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let (host, port) = request.destination();
        let deadline = Instant::now() + request.dial_timeout();
        let target = timeout_at(deadline, connect_public(host, port, deadline))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        request.relay_to(source, target).await
    }
}
async fn transfer(
    source: impl AsyncRead + AsyncWrite + Unpin,
    target: impl AsyncRead + AsyncWrite + Unpin,
    legacy: bool,
) -> io::Result<()> {
    use tokio::time::{sleep_until, Instant};
    let last = std::sync::Mutex::new(Instant::now());
    let (r, w) = tokio::io::split(source);
    let (or, ow) = tokio::io::split(target);
    let activity = || *last.lock().unwrap() = Instant::now();
    let idle = async {
        let interval = Duration::from_secs(30);
        loop {
            let deadline = *last.lock().unwrap() + interval;
            sleep_until(deadline).await;
            if last.lock().unwrap().elapsed() >= interval {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
        }
    };
    let upload = copy_records(r, ow, &activity, !legacy);
    let download = copy_records(or, w, &activity, !legacy);
    let relay = async {
        if legacy {
            tokio::select! { result = upload => result, result = download => result }
        } else {
            tokio::try_join!(upload, download)?;
            Ok(())
        }
    };
    tokio::select! { result = relay => result, result = idle => result }
}
async fn copy_records(
    mut r: impl AsyncRead + Unpin,
    mut w: impl AsyncWrite + Unpin,
    activity: &impl Fn(),
    half_close: bool,
) -> io::Result<()> {
    let mut header = [0; 5];
    let mut buf = [0; 4096];
    loop {
        if r.read(&mut header[..1]).await? == 0 {
            if half_close {
                w.shutdown().await?;
            }
            return Ok(());
        }
        r.read_exact(&mut header[1..]).await?;
        let mut count = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if !matches!(header[0], 20..=23)
            || header[1] != 3
            || !(1..=3).contains(&header[2])
            || count > 16384 + 2048
        {
            return Err(invalid());
        }
        w.write_all(&header).await?;
        activity();
        while count > 0 {
            let size = count.min(buf.len());
            let n = r.read(&mut buf[..size]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            w.write_all(&buf[..n]).await?;
            activity();
            count -= n;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use nfqws2_tgws_config::fallback::public_relay_ip as public;
    #[test]
    fn passthrough_rejects_loopback_private_mapped_and_non_unicast_addresses() {
        for ip in [
            "127.0.0.1",
            "::ffff:127.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "ff01::1",
            "fd00::3",
            "2002:7f00:1::",
            "2001:db8::5",
            "3fff:fff::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        assert!(public("93.184.216.34".parse().unwrap()));
        assert!(public("2606:4700:4700::1111".parse().unwrap()));
    }
    #[tokio::test]
    async fn passthrough_drops_arbitrary_bytes_after_allowed_tls_records() {
        let data = [&[22, 3, 3, 0, 2, 1, 2][..], b"GET /private\r\n"].concat();
        let mut result = vec![];
        assert!(copy_records(&data[..], &mut result, &|| {}, false)
            .await
            .is_err());
        assert_eq!(result, &data[..7]);
        let mut out = vec![];
        assert!(
            copy_records(&[23, 3, 3, 0xff, 0xff][..], &mut out, &|| {}, false)
                .await
                .is_err()
        );
        assert!(out.is_empty());
    }
    #[tokio::test(start_paused = true)]
    async fn one_active_direction_can_transfer_five_mebibytes_for_longer_than_two_minutes() {
        let (mut external, source) = tokio::io::duplex(32768);
        let (target, mut site) = tokio::io::duplex(32768);
        let task = tokio::spawn(transfer(source, target, false));
        let mut record = vec![1; 16384 + 5];
        record[..5].copy_from_slice(&[23, 3, 3, 64, 0]);
        let mut received = vec![0; record.len()];
        for i in 0..320 {
            site.write_all(&record).await.unwrap();
            external.read_exact(&mut received).await.unwrap();
            assert!(received == record);
            if i % 20 == 0 {
                tokio::time::advance(Duration::from_secs(15)).await;
            }
        }
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
