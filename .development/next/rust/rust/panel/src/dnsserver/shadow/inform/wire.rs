use super::{unicast, Ack, Identity, Ipv4Addr};

const UDP: usize = 8;
const DHCP_HEADER: usize = 240;
const DHCP_REQUEST: usize = 300;
const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;
const COOKIE: [u8; 4] = [99, 130, 83, 99];

pub(super) fn request(id: Identity) -> [u8; UDP + DHCP_REQUEST] {
    let mut packet = [0; UDP + DHCP_REQUEST];
    packet[..2].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    packet[2..4].copy_from_slice(&SERVER_PORT.to_be_bytes());
    packet[4..6].copy_from_slice(&((UDP + DHCP_REQUEST) as u16).to_be_bytes());
    let dhcp = &mut packet[UDP..];
    dhcp[..3].copy_from_slice(&[1, 1, 6]);
    dhcp[4..8].copy_from_slice(&id.xid);
    dhcp[12..16].copy_from_slice(&id.client.octets());
    dhcp[28..34].copy_from_slice(&id.mac);
    dhcp[236..240].copy_from_slice(&COOKIE);
    dhcp[240..247].copy_from_slice(&[53, 1, 8, 55, 1, 6, 255]);
    packet
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Reply {
    Unrelated,
    Rejected(&'static str),
    Ack(Ack),
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn peer(ip: Ipv4Addr, id: Identity) -> bool {
    unicast(ip) && ip != id.client
}

// Only a matching transaction may contribute a diagnostic rejection.
fn datagram(packet: &[u8], id: Identity) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = usize::from(packet[0] & 15) * 4;
    let total = usize::from(be16(&packet[2..4]));
    if ihl < 20
        || total > packet.len()
        || total < ihl + UDP + DHCP_HEADER
        || be16(&packet[6..8]) & 0x3fff != 0
        || packet[16..20] != id.client.octets()
    {
        return None;
    }
    let udp = &packet[ihl..total];
    let length = usize::from(be16(&udp[4..6]));
    if be16(&udp[..2]) != SERVER_PORT
        || be16(&udp[2..4]) != CLIENT_PORT
        || length < UDP + DHCP_HEADER
        || length > udp.len()
    {
        return None;
    }
    let dhcp = &udp[UDP..length];
    (dhcp[..3] == [2, 1, 6] && dhcp[4..8] == id.xid && dhcp[28..34] == id.mac)
        .then_some(&udp[..length])
}

fn checksum_ok(endpoints: &[u8], udp: &[u8]) -> bool {
    let sum = |bytes: &[u8]| {
        bytes
            .chunks(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)])))
            .sum::<u32>()
    };
    let mut total = sum(endpoints) + 17 + udp.len() as u32 + sum(udp);
    while total > 0xffff {
        total = (total & 0xffff) + (total >> 16);
    }
    total == 0xffff
}

#[derive(Default)]
struct Options<'a> {
    overload: Option<&'a [u8]>,
    message: Option<&'a [u8]>,
    server: Option<&'a [u8]>,
    dns: Vec<u8>,
}

impl<'a> Options<'a> {
    fn parse(&mut self, mut bytes: &'a [u8]) -> Result<(), &'static str> {
        while let Some((&code, rest)) = bytes.split_first() {
            bytes = rest;
            match code {
                0 => continue,
                255 => return Ok(()),
                _ => (),
            }
            let (&length, rest) = bytes.split_first().ok_or("truncated DHCP option length")?;
            let length = usize::from(length);
            let value = rest.get(..length).ok_or("truncated DHCP option data")?;
            bytes = &rest[length..];
            let scalar = match code {
                6 => {
                    self.dns.extend_from_slice(value);
                    continue;
                }
                52 => &mut self.overload,
                53 => &mut self.message,
                54 => &mut self.server,
                _ => continue,
            };
            if scalar.replace(value).is_some() {
                return Err("duplicate DHCP control option");
            }
        }
        Err("DHCP option area lacks END")
    }
}

fn validate(packet: &[u8], udp: &[u8], id: Identity) -> Result<Ack, &'static str> {
    if !peer(ipv4(&packet[12..16]), id) {
        return Err("invalid DHCP reply source");
    }
    if be16(&udp[6..8]) != 0 && !checksum_ok(&packet[12..20], udp) {
        return Err("invalid UDP checksum");
    }
    let dhcp = &udp[UDP..];
    if dhcp[236..240] != COOKIE {
        return Err("wrong DHCP cookie");
    }
    if dhcp[12..16] != [0; 4] && dhcp[12..16] != id.client.octets() {
        return Err("wrong ACK ciaddr");
    }
    if dhcp[16..20] != [0; 4] {
        return Err("unexpected address assignment in INFORM ACK");
    }
    if dhcp[24..28] != [0; 4] && !peer(ipv4(&dhcp[24..28]), id) {
        return Err("invalid DHCP relay address");
    }
    let mut options = Options::default();
    options.parse(&dhcp[DHCP_HEADER..])?;
    if let Some(overload) = options.overload {
        let &[flags @ 1..=3] = overload else {
            return Err("invalid option overload");
        };
        if flags & 1 != 0 {
            options.parse(&dhcp[108..236])?;
        }
        if flags & 2 != 0 {
            options.parse(&dhcp[44..108])?;
        }
    }
    let Some(server) = options.server.filter(|value| value.len() == 4).map(ipv4) else {
        return Err("wrong DHCP type or server identifier");
    };
    if options.message != Some(&[5])
        || !peer(server, id)
        || id.server.is_some_and(|known| server != known)
    {
        return Err("wrong DHCP type or server identifier");
    }
    if options.dns.is_empty() || options.dns.len() % 4 != 0 {
        return Err("DHCPACK has no valid DNS option");
    }
    Ok(Ack {
        server,
        dns: options.dns.chunks_exact(4).map(ipv4).collect(),
    })
}

pub(super) fn reply(packet: &[u8], id: Identity) -> Reply {
    let Some(udp) = datagram(packet, id) else {
        return Reply::Unrelated;
    };
    match validate(packet, udp, id) {
        Ok(ack) => Reply::Ack(ack),
        Err(reason) => Reply::Rejected(reason),
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct Observation {
    pub(super) outgoing: bool,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    kind: &'static str,
    server: Option<Ipv4Addr>,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    relay: Ipv4Addr,
    options_error: Option<&'static str>,
    verdict: Option<&'static str>,
}

#[cfg(any(target_os = "linux", test))]
impl Observation {
    pub(super) fn summary(&self) -> String {
        let (direction, source_port, destination_port) = if self.outgoing {
            ("исходящий", CLIENT_PORT, SERVER_PORT)
        } else {
            ("входящий", SERVER_PORT, CLIENT_PORT)
        };
        let server = self
            .server
            .map_or_else(|| "отсутствует".to_owned(), |ip| ip.to_string());
        let mut text = format!(
            "{direction} {}:{source_port} → {}:{destination_port}; DHCP={}, server-id={server}, ciaddr={}, yiaddr={}, relay={}",
            self.source, self.destination, self.kind, self.ciaddr, self.yiaddr, self.relay,
        );
        if let Some(reason) = self.options_error {
            text.push_str(&format!("; options: {reason}"));
        }
        if let Some(verdict) = self.verdict {
            text.push_str(&format!("; проверка ответа: {verdict}"));
        }
        text
    }
}

/// Diagnostic only, with the already-owned transaction's kernel and parser
/// correlation. This does not make a frame eligible for DNS discovery.
#[cfg(any(target_os = "linux", test))]
pub(super) fn observation(packet: &[u8], id: Identity, outgoing: bool) -> Option<Observation> {
    if packet.len() < 20
        || packet[0] >> 4 != 4
        || packet[9] != 17
        || be16(&packet[6..8]) & 0xbfff != 0
    {
        return None;
    }
    let ihl = usize::from(packet[0] & 15) * 4;
    let total = usize::from(be16(&packet[2..4]));
    if ihl < 20 || total < ihl + UDP + DHCP_HEADER {
        return None;
    }
    let udp = packet.get(ihl..total)?;
    let length = usize::from(be16(&udp[4..6]));
    if length < UDP + DHCP_HEADER {
        return None;
    }
    let dhcp = udp.get(UDP..length)?;
    let ports = (be16(&udp[..2]), be16(&udp[2..4]));
    let source = ipv4(&packet[12..16]);
    let destination = ipv4(&packet[16..20]);
    let boundary = if outgoing {
        ports == (CLIENT_PORT, SERVER_PORT)
            && source == id.client
            && destination == id.server.unwrap_or(Ipv4Addr::BROADCAST)
            && dhcp[0] == 1
    } else {
        ports == (SERVER_PORT, CLIENT_PORT)
            && (destination == id.client || destination.is_broadcast())
            && dhcp[0] == 2
    };
    if !boundary || dhcp[1..3] != [1, 6] || dhcp[4..8] != id.xid || dhcp[28..34] != id.mac {
        return None;
    }
    let mut options = Options::default();
    let options_error = if dhcp[236..240] == COOKIE {
        options.parse(&dhcp[DHCP_HEADER..]).err()
    } else {
        Some("wrong DHCP cookie")
    };
    let kind = match options.message {
        Some([5]) => "ACK",
        Some([6]) => "NAK",
        Some([8]) => "INFORM",
        _ => "неизвестен",
    };
    let verdict = (!outgoing).then(|| match reply(packet, id) {
        Reply::Ack(_) => "OK",
        Reply::Rejected(reason) => reason,
        Reply::Unrelated => "пакет на WAN не соответствует адресу или заголовку ожидаемого ответа",
    });
    Some(Observation {
        outgoing,
        source,
        destination,
        kind,
        server: options.server.filter(|value| value.len() == 4).map(ipv4),
        ciaddr: ipv4(&dhcp[12..16]),
        yiaddr: ipv4(&dhcp[16..20]),
        relay: ipv4(&dhcp[24..28]),
        options_error,
        verdict,
    })
}
