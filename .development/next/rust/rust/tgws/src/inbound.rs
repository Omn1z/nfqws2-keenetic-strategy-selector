//! The three client entry points used by a saved MTProxy configuration.
//! Authenticated EE sessions still pass through the normal keyed MTProto
//! handshake, independently of the optional ordinary HTTPS listener.
use crate::{crypto::Transport, relay};
use nfqws2_tgws_config::Config;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_util::either::Either;
mod ee;
mod origin;
mod records;
pub(super) use origin::Origin;
#[cfg(test)]
mod tests;

pub(super) struct Pump(JoinHandle<()>);
impl Pump {
    pub async fn finish(mut self) {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut self.0).await;
    }
}
impl Drop for Pump {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) enum Handshake {
    Session {
        io: Either<TcpStream, DuplexStream>,
        session: Box<Transport>,
        pump: Option<Pump>,
    },
    Redirected,
    Rejected,
    Https(BufReader<TcpStream>, origin::Request),
}
fn session(
    stream: Either<TcpStream, DuplexStream>,
    init: [u8; 64],
    key: &[u8; 16],
    pump: Option<Pump>,
) -> io::Result<Handshake> {
    match Transport::client(init, key) {
        Ok(session) => Ok(Handshake::Session {
            io: stream,
            session: Box::new(session),
            pump,
        }),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(Handshake::Rejected),
        Err(e) => Err(e),
    }
}
pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid MTProxy handshake")
}
pub(super) async fn receive(mut tcp: TcpStream, cfg: &Config) -> io::Result<Handshake> {
    let key = cfg.key()?;
    if cfg.fake_tls_domain.is_empty() {
        let init = relay::read_init(&mut tcp, cfg.proxy_protocol).await?;
        return session(Either::Left(tcp), init, &key, None);
    }
    let mut tcp = BufReader::with_capacity(4096, tcp);
    if cfg.proxy_protocol {
        relay::proxy_line(&mut tcp).await?;
    }
    if tcp.read_u8().await? != 22 {
        let redirect=format!("HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",cfg.fake_tls_domain);
        tcp.write_all(redirect.as_bytes()).await?;
        tcp.shutdown().await?;
        return Ok(Handshake::Redirected);
    }
    let legacy = cfg.transport.is_empty();
    let hello = read_hello(&mut tcp, legacy).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    // Go authenticates only the first complete TLS record as EE. A standard
    // HTTPS client can split its ClientHello across any record boundary.
    let single = hello.len() == 5 + usize::from(u16::from_be_bytes([hello[3], hello[4]]));
    let auth = if single {
        ee::reply(&hello, &key, now)?
    } else {
        ee::Reply::Unauthenticated
    };
    let reply = match auth {
        ee::Reply::Authenticated(reply) => reply,
        ee::Reply::Expired if !legacy => return Err(invalid()),
        _ => return Ok(Handshake::Https(tcp, origin::Request::parse(hello, cfg)?)),
    };
    tcp.write_all(&reply).await?;
    let (mut stream, framed) = tokio::io::duplex(16 << 10);
    let pump = Pump(tokio::spawn(records::bridge(tcp, framed, legacy)));
    let mut init = [0; 64];
    stream.read_exact(&mut init).await?;
    session(Either::Right(stream), init, &key, Some(pump))
}

async fn read_hello(
    source: &mut (impl AsyncRead + Unpin),
    allow_fragments: bool,
) -> io::Result<Vec<u8>> {
    // Match rustls' 64 KiB handshake limit, counting the saved wire headers
    // as well so one-byte fragments cannot grow the buffer without bound.
    const MAX_WIRE: usize = 65535;
    let mut wire = Vec::new();
    let mut handshake = Vec::with_capacity(4);
    let mut received = 0;
    let mut header = [22, 0, 0, 0, 0];
    loop {
        source.read_exact(&mut header[1..]).await?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[1] != 3
            || header[2] > 3
            || !(1..=16384).contains(&size)
            || wire.len() + size + 5 > MAX_WIRE
        {
            return Err(invalid());
        }
        wire.extend_from_slice(&header);
        let start = wire.len();
        wire.resize(start + size, 0);
        source.read_exact(&mut wire[start..]).await?;
        handshake.extend_from_slice(&wire[start..start + size.min(4 - handshake.len())]);
        received += size;
        if handshake[0] != 1 {
            return Err(invalid());
        }
        if let [_, a, b, c] = handshake[..] {
            let expected = 4 + u32::from_be_bytes([0, a, b, c]) as usize;
            if !(39..=MAX_WIRE - 5).contains(&expected) || received > expected {
                return Err(invalid());
            }
            if received == expected {
                return Ok(wire);
            }
        }
        if !allow_fragments || source.read_u8().await? != 22 {
            return Err(invalid());
        }
    }
}
