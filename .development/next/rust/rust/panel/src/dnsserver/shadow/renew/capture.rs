//! Passive evidence from one verified firmware DHCP client.
use std::{io, net::Ipv4Addr};
use time::OffsetDateTime;
use tokio::time::Instant;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    Dns {
        servers: Vec<Ipv4Addr>,
        expires_at: Instant,
        lease_seconds: u32,
    },
    AckNoDns,
    Nak,
}

#[derive(Clone)]
pub(in crate::dnsserver::shadow) struct Receipt {
    pub(in crate::dnsserver::shadow) observation: Observation,
    pub(in crate::dnsserver::shadow) observed_at: OffsetDateTime,
}

#[cfg(target_os = "linux")]
pub(in crate::dnsserver::shadow) use linux::{open_packet_receiver, read_packet, Capture};

#[cfg(not(target_os = "linux"))]
pub(in crate::dnsserver::shadow) struct Capture;

#[cfg(not(target_os = "linux"))]
impl Capture {
    pub(in crate::dnsserver::shadow) fn open(
        _: &str,
        _: u32,
        _: Ipv4Addr,
        _: [u8; 6],
    ) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(in crate::dnsserver::shadow) async fn next(
        &mut self,
        _: impl FnMut(u64),
    ) -> io::Result<Receipt> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(any(target_os = "linux", test))]
mod parse {
    use super::*;
    use std::time::Duration;

    pub(super) const BUFFER: usize = 1536;
    const PENDING_TTL: Duration = Duration::from_secs(120);
    const MAX_LEASE_SECS: u32 = 7 * 24 * 60 * 60;
    const ANY: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const BROADCAST: Ipv4Addr = Ipv4Addr::BROADCAST;

    fn peer(ip: Ipv4Addr) -> bool {
        ip.octets()[0] != 0
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !ip.is_link_local()
            && !ip.is_broadcast()
    }

    fn address(bytes: &[u8]) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))
    }

    fn fold_checksum(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    fn checksum_sum(bytes: &[u8]) -> u32 {
        bytes
            .chunks(2)
            .map(|chunk| u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)])))
            .sum()
    }

    struct Datagram<'a> {
        header: &'a [u8],
        udp: &'a [u8],
        dhcp: &'a [u8],
        source: Ipv4Addr,
        destination: Ipv4Addr,
    }

    impl<'a> Datagram<'a> {
        fn parse(packet: &'a [u8], outgoing: bool) -> Option<Self> {
            let ip = packet.get(..20)?;
            if packet.len() > BUFFER || ip[0] >> 4 != 4 || ip[9] != 17 {
                return None;
            }
            let header_len = usize::from(ip[0] & 15) * 4;
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            if header_len < 20
                || total < header_len + 8 + 240
                || u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff != 0
            {
                return None;
            }
            let udp = packet.get(header_len..total)?;
            let (source_port, destination_port, op) =
                if outgoing { (68, 67, 1) } else { (67, 68, 2) };
            if usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
                || u16::from_be_bytes([udp[0], udp[1]]) != source_port
                || u16::from_be_bytes([udp[2], udp[3]]) != destination_port
                || udp[8] != op
            {
                return None;
            }
            Some(Self {
                header: &packet[..header_len],
                udp,
                dhcp: &udp[8..],
                source: address(&ip[12..16])?,
                destination: address(&ip[16..20])?,
            })
        }

        fn checksums_valid(&self) -> bool {
            if fold_checksum(checksum_sum(self.header)) != 0xffff {
                return false;
            }
            // A zero UDP checksum is permitted for IPv4. Actual IPv4 source
            // and destination, including a relay, form the UDP pseudo-header.
            self.udp[6..8] == [0, 0]
                || fold_checksum(
                    checksum_sum(&self.header[12..20])
                        + 17
                        + self.udp.len() as u32
                        + checksum_sum(self.udp),
                ) == 0xffff
        }
    }

    #[derive(Default)]
    struct Options<'a> {
        control: [Option<&'a [u8]>; 5],
        dns: Option<Vec<u8>>,
    }

    impl<'a> Options<'a> {
        fn get(&self, option: usize) -> Option<&'a [u8]> {
            self.control[option - 50]
        }

        fn parse(dhcp: &'a [u8]) -> Option<Self> {
            let mut result = Self::default();
            result.area(&dhcp[240..])?;
            if let Some(overload) = result.get(52) {
                let [bits @ 1..=3] = overload else {
                    return None;
                };
                if bits & 1 != 0 {
                    result.area(&dhcp[108..236])?;
                }
                if bits & 2 != 0 {
                    result.area(&dhcp[44..108])?;
                }
            }
            Some(result)
        }

        fn area(&mut self, mut input: &'a [u8]) -> Option<()> {
            while let Some((&code, remaining)) = input.split_first() {
                input = remaining;
                match code {
                    0 => continue,
                    255 => return Some(()),
                    _ => (),
                }
                let (&len, rest) = input.split_first()?;
                let (value, after) = rest.split_at_checked(usize::from(len))?;
                match code {
                    50..=54 => {
                        if self.control[usize::from(code - 50)]
                            .replace(value)
                            .is_some()
                        {
                            return None;
                        }
                    }
                    // RFC3396 concatenates option 6 fragments in wire order.
                    6 => self
                        .dns
                        .get_or_insert_with(Vec::new)
                        .extend_from_slice(value),
                    _ => (),
                }
                input = after;
            }
            None
        }
    }

    #[derive(Clone, Copy)]
    struct Pending {
        xid: [u8; 4],
        first: Instant,
        sequence: u64,
        server: Option<Ipv4Addr>,
    }

    pub(super) struct Tracker {
        client: Ipv4Addr,
        mac: [u8; 6],
        pending: [Option<Pending>; 8],
        sequence: u64,
        pub(super) requests: u64,
    }

    impl Tracker {
        pub(super) fn new(client: Ipv4Addr, mac: [u8; 6]) -> io::Result<Self> {
            if !peer(client) || mac[0] & 1 != 0 || mac == [0; 6] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid firmware DHCP identity",
                ));
            }
            Ok(Self {
                client,
                mac,
                pending: [None; 8],
                sequence: 0,
                requests: 0,
            })
        }

        pub(super) fn packet(
            &mut self,
            data: &[u8],
            outgoing: bool,
            now: Instant,
        ) -> Option<Observation> {
            for pending in &mut self.pending {
                if pending.is_some_and(|request| {
                    now < request.first || now.duration_since(request.first) >= PENDING_TTL
                }) {
                    *pending = None;
                }
            }
            let frame = Datagram::parse(data, outgoing)?;
            let dhcp = frame.dhcp;
            if dhcp[1..3] != [1, 6] || dhcp[28..34] != self.mac {
                return None;
            }
            let xid = <[u8; 4]>::try_from(&dhcp[4..8]).ok()?;
            let pending = self
                .pending
                .iter()
                .flatten()
                .find(|p| p.xid == xid)
                .copied();
            if (!outgoing && pending.is_none()) || dhcp[236..240] != [99, 130, 83, 99] {
                return None;
            }
            let options = Options::parse(dhcp)?;
            match (outgoing, options.get(53)?) {
                (true, [3]) => {
                    let server = self.request_server(&frame, &options)?;
                    if pending.is_none() {
                        self.remember(xid, now, server);
                    }
                    if pending.is_none_or(|saved| saved.server == server) {
                        self.requests = self.requests.saturating_add(1);
                    }
                    // Even a changed server on a reused XID must never
                    // replace already recorded identity or renew its timer.
                    None
                }
                (false, [kind @ (5 | 6)]) => {
                    let request = pending?;
                    let result = self.reply(&frame, &options, request, *kind)?;
                    for slot in &mut self.pending {
                        if slot.is_some_and(|entry| entry.sequence <= request.sequence) {
                            *slot = None;
                        }
                    }
                    Some(result)
                }
                _ => None,
            }
        }

        fn request_server(
            &self,
            frame: &Datagram<'_>,
            options: &Options<'_>,
        ) -> Option<Option<Ipv4Addr>> {
            let ciaddr = address(&frame.dhcp[12..16])?;
            if frame.dhcp[16..20] != [0; 4]
                || frame.dhcp[24..28] != [0; 4]
                || frame.destination == self.client
                || (frame.destination != BROADCAST && !peer(frame.destination))
            {
                return None;
            }
            let server = match options.get(54) {
                None => None,
                Some(raw) => Some(address(raw).filter(|ip| peer(*ip) && *ip != self.client)?),
            };
            let requested = options.get(50);
            if ciaddr == self.client {
                if frame.source != self.client || server.is_some() || requested.is_some() {
                    return None;
                }
            } else if ciaddr != ANY
                || frame.source != ANY
                || frame.destination != BROADCAST
                || requested.and_then(address) != Some(self.client)
            {
                return None;
            }
            Some(server)
        }

        fn remember(&mut self, xid: [u8; 4], first: Instant, server: Option<Ipv4Addr>) {
            let slot = self
                .pending
                .iter_mut()
                .min_by_key(|p| p.map_or(0, |item| item.sequence))
                .unwrap();
            self.sequence += 1;
            *slot = Some(Pending {
                xid,
                first,
                sequence: self.sequence,
                server,
            });
        }

        fn reply(
            &self,
            frame: &Datagram<'_>,
            options: &Options<'_>,
            request: Pending,
            kind: u8,
        ) -> Option<Observation> {
            let client = self.client;
            let ciaddr = address(&frame.dhcp[12..16])?;
            let yiaddr = address(&frame.dhcp[16..20])?;
            let relay = address(&frame.dhcp[24..28])?;
            let server = address(options.get(54)?)?;
            if !peer(frame.source)
                || frame.source == client
                || (frame.destination != client && frame.destination != BROADCAST)
                || !frame.checksums_valid()
                || (ciaddr != ANY && ciaddr != client)
                || (relay != ANY && (!peer(relay) || relay == client))
                || !peer(server)
                || server == client
                || request.server.is_some_and(|expected| expected != server)
            {
                return None;
            }
            if kind == 6 {
                return (yiaddr == ANY && ciaddr == ANY).then_some(Observation::Nak);
            }
            let lease = u32::from_be_bytes(options.get(51)?.try_into().ok()?);
            if yiaddr != client || lease == 0 {
                return None;
            }
            let Some(dns) = &options.dns else {
                return Some(Observation::AckNoDns);
            };
            if dns.is_empty() || dns.len() % 4 != 0 {
                return None;
            }
            let mut servers = Vec::with_capacity(8);
            for raw in dns.chunks_exact(4) {
                let ip = address(raw).filter(|ip| peer(*ip) && *ip != client)?;
                if servers.len() < 8 && !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
            let lease_seconds = lease.min(MAX_LEASE_SECS);
            let expires_at = request.first + Duration::from_secs(u64::from(lease_seconds));
            Some(Observation::Dns {
                servers,
                expires_at,
                lease_seconds,
            })
        }
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(target_os = "linux")]
mod linux;
