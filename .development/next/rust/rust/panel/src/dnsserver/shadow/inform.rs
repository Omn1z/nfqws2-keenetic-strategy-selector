//! One parameter-only DHCPINFORM on a caller-verified physical WAN.
//!
//! This exchange neither owns UDP port 68 nor changes the firmware lease.
//! Callers still verify WAN provenance and filter local DNS feedback loops.

use super::diagnostics::Trace;
use std::{io, net::Ipv4Addr, time::Duration};
#[cfg(any(target_os = "linux", test))]
use tokio::time::timeout_at;
use tokio::time::Instant;

#[cfg(any(target_os = "linux", test))]
mod capture;
#[cfg(target_os = "linux")]
mod linux;
pub(super) mod state;
#[cfg(test)]
mod tests;
#[cfg(any(target_os = "linux", test))]
mod wire;

const WINDOW: Duration = Duration::from_millis(1200);
#[cfg(any(target_os = "linux", test))]
const SLICE: Duration = Duration::from_millis(100);
#[cfg(any(target_os = "linux", test))]
const MAX_READS: usize = 512;
#[cfg(any(target_os = "linux", test))]
const BUFFER: usize = 4096;

#[derive(Clone, Copy)]
pub(super) struct Target<'a> {
    pub device: &'a str,
    pub index: u32,
    pub mac: [u8; 6],
    pub client: Ipv4Addr,
    /// `None` selects limited broadcast on this device only.
    pub server: Option<Ipv4Addr>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Ack {
    pub server: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Clone, Copy)]
#[cfg(any(target_os = "linux", test))]
struct Identity {
    client: Ipv4Addr,
    server: Option<Ipv4Addr>,
    mac: [u8; 6],
    xid: [u8; 4],
}

fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

fn valid_device(device: &str) -> bool {
    !device.is_empty()
        && device.len() <= 15
        && device != "lo"
        && device
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && (device == "br-wan"
            || device.starts_with("br-wan.")
            || !["awg", "nwg", "wg", "tun", "tap", "br", "docker", "veth"]
                .iter()
                .any(|kind| device.starts_with(kind)))
}

fn validate(target: Target<'_>) -> io::Result<()> {
    if !valid_device(target.device)
        || target.index == 0
        || target.mac == [0; 6]
        || target.mac[0] & 1 != 0
        || !unicast(target.client)
        || target
            .server
            .is_some_and(|server| !unicast(server) || server == target.client)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DHCPINFORM requires a verified Ethernet WAN and unicast client/server",
        ));
    }
    Ok(())
}

pub(super) async fn probe(target: Target<'_>, deadline: Instant, trace: &Trace) -> io::Result<Ack> {
    let deadline = deadline.min(Instant::now() + WINDOW);
    if Instant::now() >= deadline {
        return Err(elapsed(None));
    }
    validate(target)?;
    #[cfg(target_os = "linux")]
    return linux::probe(target, deadline, trace).await;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = trace;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DHCPINFORM requires Linux",
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
trait Socket {
    async fn send(&self, packet: &[u8]) -> io::Result<()>;
    async fn receive(&self, packet: &mut [u8]) -> io::Result<usize>;
}

#[derive(Debug)]
struct ReplyTimeout(Option<&'static str>);

impl std::fmt::Display for ReplyTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(reason) => write!(
                f,
                "DHCPINFORM received a matching reply but rejected it ({reason})"
            ),
            None => f.write_str("DHCPINFORM did not receive a matching reply"),
        }
    }
}

impl std::error::Error for ReplyTimeout {}

fn elapsed(rejected: Option<&'static str>) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, ReplyTimeout(rejected))
}

#[cfg(any(target_os = "linux", test))]
struct ReceiveReport<'a> {
    trace: &'a Trace,
    received: u16,
    matched: u16,
    rejected: u16,
}

#[cfg(any(target_os = "linux", test))]
impl ReceiveReport<'_> {
    fn observe(&mut self, reply: &wire::Reply) {
        self.received += 1;
        match reply {
            wire::Reply::Unrelated => (),
            wire::Reply::Ack(_) => self.matched += 1,
            wire::Reply::Rejected(reason) => {
                self.matched += 1;
                self.rejected += 1;
                if self.rejected <= 3 {
                    // The parser supplies only static rejection descriptions.
                    self.trace.step("dhcp.reject", reason);
                }
            }
        }
    }
}

#[cfg(any(target_os = "linux", test))]
impl Drop for ReceiveReport<'_> {
    fn drop(&mut self) {
        self.trace.step("dhcp.receive", &format!(
            "Сокет DNS-сервиса: получено={}, совпало с текущим запросом={}, отклонено={}. Счётчик учитывает пакеты после IP/firewall.",
            self.received, self.matched, self.rejected,
        ));
    }
}

#[cfg(any(target_os = "linux", test))]
async fn exchange(
    socket: &impl Socket,
    id: Identity,
    deadline: Instant,
    trace: &Trace,
) -> io::Result<Ack> {
    let mut report = trace.active().then(|| ReceiveReport {
        trace,
        received: 0,
        matched: 0,
        rejected: 0,
    });
    let send_started = Instant::now();
    if send_started >= deadline {
        return Err(elapsed(None));
    }
    timeout_at(
        deadline.min(send_started + SLICE),
        socket.send(&wire::request(id)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DHCPINFORM send timed out"))??;
    trace.step("dhcp.send", "DHCPINFORM передан ядру");
    let mut buffer = [0; BUFFER];
    let mut rejected = None;
    for index in 0..MAX_READS {
        let now = Instant::now();
        if now >= deadline {
            return Err(elapsed(rejected));
        }
        let result = timeout_at(deadline.min(now + SLICE), socket.receive(&mut buffer)).await;
        if Instant::now() >= deadline {
            return Err(elapsed(rejected));
        }
        match result {
            Ok(Ok(len)) => {
                // MSG_TRUNC can report an oversized datagram. It reached this
                // socket but can never identify or approve this transaction.
                let reply = buffer
                    .get(..len)
                    .map_or(wire::Reply::Unrelated, |packet| wire::reply(packet, id));
                if let Some(report) = report.as_mut() {
                    report.observe(&reply);
                }
                match reply {
                    wire::Reply::Ack(ack) => return Ok(ack),
                    wire::Reply::Rejected(reason) => rejected = Some(reason),
                    wire::Reply::Unrelated => (),
                }
            }
            Ok(Err(err))
                if !matches!(
                    err.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(err)
            }
            _ => (),
        }
        if index % 32 == 31 {
            tokio::task::yield_now().await;
        }
    }
    Err(io::Error::other(
        "DHCPINFORM reached the receive limit without a matching ACK",
    ))
}
