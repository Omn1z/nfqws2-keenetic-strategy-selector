use std::{
    collections::{HashMap, HashSet},
    io,
    net::Ipv6Addr,
};
pub(crate) type Neighbors = HashMap<String, HashSet<Ipv6Addr>>;

#[cfg(any(target_os = "linux", test))]
fn lan_bridge(name: &[u8], wan: &[String]) -> bool {
    if wan.iter().any(|n| n.as_bytes() == name) {
        return false;
    }
    let Some(suffix) = name.strip_prefix(b"br") else {
        return false;
    };
    if let Some(label) = suffix.strip_prefix(b"-") {
        return !label.is_empty()
            && !label
                .get(..3)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"wan"));
    }
    !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_ndp(_: &[String]) -> io::Result<Neighbors> {
    Ok(Neighbors::new())
}

// Read-only RTM_GETNEIGH on Linux. This replaces one iproute2 process per
// refresh with a single route-netlink dump; only bridge-side IPv6 entries are used.
#[cfg(target_os = "linux")]
pub(crate) fn read_ndp(wan: &[String]) -> io::Result<Neighbors> {
    use std::{
        ffi::CStr,
        mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::{Duration, Instant},
    };
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // socket returned a fresh descriptor; OwnedFd closes it on every return.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut peer: libc::sockaddr_nl = unsafe { mem::zeroed() };
    peer.nl_family = libc::AF_NETLINK as _;
    let mut req = [0u8; 28]; // nlmsghdr + ndmsg
    req[..4].copy_from_slice(&28u32.to_ne_bytes());
    req[4..6].copy_from_slice(&libc::RTM_GETNEIGH.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    req[16] = libc::AF_INET6 as u8;
    let peer_size = mem::size_of_val(&peer) as libc::socklen_t;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            (&peer as *const libc::sockaddr_nl).cast(),
            peer_size,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut table = Neighbors::new();
    let mut interfaces = HashMap::new();
    let mut buf = vec![0u8; 32768];
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as i32;
        if left == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, left) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut size = peer_size;
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
                (&mut peer as *mut libc::sockaddr_nl).cast(),
                &mut size,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(err);
        }
        if peer.nl_pid != 0 {
            continue;
        }
        if n == 0 || n as usize > buf.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if consume_dump(&buf[..n as usize], &mut table, |index| {
            *interfaces.entry(index).or_insert_with(|| {
                let mut name = [0; libc::IF_NAMESIZE];
                // if_indextoname either returns a NUL-terminated name or a null pointer.
                let p = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
                if p.is_null() {
                    return false;
                }
                let Ok(name) = unsafe { CStr::from_ptr(name.as_ptr()) }.to_str() else {
                    return false;
                };
                lan_bridge(name.as_bytes(), wan)
                    && std::path::Path::new("/sys/class/net")
                        .join(name)
                        .join("bridge")
                        .is_dir()
            })
        })? {
            return Ok(table);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn consume_dump(
    mut data: &[u8],
    table: &mut Neighbors,
    mut lan: impl FnMut(u32) -> bool,
) -> io::Result<bool> {
    const DONE: u16 = 3;
    const ERROR: u16 = 2;
    const NEW_NEIGH: u16 = 28;
    const DUMP_INTR: u16 = 0x10;
    while !data.is_empty() {
        let header = data.get(..16).ok_or(io::ErrorKind::UnexpectedEof)?;
        let len = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(header[6..8].try_into().unwrap());
        let seq = u32::from_ne_bytes(header[8..12].try_into().unwrap());
        let body = data.get(16..len).ok_or(io::ErrorKind::UnexpectedEof)?;
        if seq == 1 {
            if flags & DUMP_INTR != 0 || kind == ERROR {
                return Err(io::Error::other("incomplete neighbor dump"));
            }
            if kind == DONE {
                if body.get(..4).is_some_and(|code| code != [0; 4]) {
                    return Err(io::Error::other("neighbor dump failed"));
                }
                return Ok(true);
            }
            if kind == NEW_NEIGH {
                add_neighbor(body, table, &mut lan)?;
            }
        }
        data = data.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    Ok(false)
}

#[cfg(any(target_os = "linux", test))]
fn add_neighbor(
    body: &[u8],
    table: &mut Neighbors,
    lan: &mut impl FnMut(u32) -> bool,
) -> io::Result<()> {
    use std::fmt::Write;
    let msg = body.get(..12).ok_or(io::ErrorKind::UnexpectedEof)?;
    // Linux AF_INET6 is 10 on supported router architectures.
    // An unusable, proxy or upstream-router neighbor is not a LAN client.
    let state = u16::from_ne_bytes([msg[8], msg[9]]);
    const INCOMPLETE_OR_FAILED: u16 = 0x01 | 0x20;
    const PROXY_OR_ROUTER: u8 = 0x08 | 0x80;
    if msg[0] != 10
        || state == 0
        || state & INCOMPLETE_OR_FAILED != 0
        || msg[10] & PROXY_OR_ROUTER != 0
        || !lan(u32::from_ne_bytes(msg[4..8].try_into().unwrap()))
    {
        return Ok(());
    }
    let mut attrs = &body[12..];
    let mut addr = None;
    let mut mac = None;
    while !attrs.is_empty() {
        let header = attrs.get(..4).ok_or(io::ErrorKind::UnexpectedEof)?;
        let len = u16::from_ne_bytes([header[0], header[1]]) as usize;
        let kind = u16::from_ne_bytes([header[2], header[3]]);
        let value = attrs.get(4..len).ok_or(io::ErrorKind::UnexpectedEof)?;
        match kind {
            1 if value.len() == 16 => {
                addr = Some(Ipv6Addr::from(<[u8; 16]>::try_from(value).unwrap()))
            }
            2 if value.len() == 6 && value[0] & 1 == 0 && value != [0; 6] => mac = Some(value),
            _ => (),
        }
        attrs = attrs.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    if let (Some(ip), Some(link)) = (addr, mac) {
        if !ip.is_multicast() && !ip.is_unspecified() && !ip.is_loopback() {
            let mut key = String::with_capacity(link.len() * 3);
            for (i, b) in link.iter().enumerate() {
                if i > 0 {
                    key.push(':');
                }
                write!(key, "{b:02x}").unwrap();
            }
            table.entry(key).or_default().insert(ip);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn msg(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let len = 16 + body.len();
        let mut raw = vec![0; len.next_multiple_of(4)];
        raw[..4].copy_from_slice(&(len as u32).to_ne_bytes());
        raw[4..6].copy_from_slice(&kind.to_ne_bytes());
        raw[6..8].copy_from_slice(&flags.to_ne_bytes());
        raw[8..12].copy_from_slice(&seq.to_ne_bytes());
        raw[16..len].copy_from_slice(body);
        raw
    }

    fn neighbor(ip: &str, iface: u32) -> Vec<u8> {
        let mut payload = [0; 44];
        payload[0] = 10;
        payload[8..10].copy_from_slice(&2u16.to_ne_bytes());
        payload[4..8].copy_from_slice(&iface.to_ne_bytes());
        payload[12..14].copy_from_slice(&20u16.to_ne_bytes());
        payload[14..16].copy_from_slice(&1u16.to_ne_bytes());
        payload[16..32].copy_from_slice(&ip.parse::<Ipv6Addr>().unwrap().octets());
        payload[32..34].copy_from_slice(&10u16.to_ne_bytes());
        payload[34..36].copy_from_slice(&2u16.to_ne_bytes());
        payload[36..42].copy_from_slice(&[2, 170, 187, 0, 17, 34]);
        msg(28, 2, 1, &payload)
    }

    #[test]
    fn route_dump_keeps_link_local_lan_neighbors_across_datagrams() {
        let mut table = Neighbors::new();
        let packets = [
            neighbor("fe80::1", 1),
            neighbor("fd00::3", 2),
            neighbor("ff02::1", 1),
            neighbor("::", 1),
            neighbor("fe80::1", 1),
        ]
        .concat();
        assert!(!consume_dump(&packets, &mut table, |i| i == 1).unwrap());
        let packets = [neighbor("fd00::2", 1), msg(3, 0, 1, &[0; 4])].concat();
        assert!(consume_dump(&packets, &mut table, |i| i == 1).unwrap());
        assert_eq!(
            table,
            HashMap::from([(
                "02:aa:bb:00:11:22".into(),
                HashSet::from(["fe80::1".parse().unwrap(), "fd00::2".parse().unwrap()])
            )])
        );
    }

    #[test]
    fn usable_hosts_are_limited_to_lan_bridges() {
        let wan = vec!["br1".into(), "br-uplink".into()];
        for name in ["br0", "br12", "br-lan", "br-guest"] {
            assert!(lan_bridge(name.as_bytes(), &wan));
        }
        for name in [
            "br",
            "br-",
            "brx",
            "br1",
            "br-wan",
            "br-WAN2",
            "br-uplink",
            "ppp0",
            "eth1",
            "docker0",
        ] {
            assert!(!lan_bridge(name.as_bytes(), &wan));
        }
        let normal = neighbor("2001:db8::1", 1);
        for (state, flags, link) in [
            (0, 0, 2),
            (1, 0, 2),
            (32, 0, 2),
            (2, 0x08, 2),
            (2, 0x80, 2),
            (2, 0, 1),
        ] {
            let mut row = normal.clone();
            row[24..26].copy_from_slice(&u16::to_ne_bytes(state));
            row[26] = flags;
            row[52] = link;
            let mut table = Neighbors::new();
            consume_dump(&row, &mut table, |_| true).unwrap();
            assert!(table.is_empty());
        }
        for state in [2u16, 4, 8, 16, 64, 128] {
            let mut row = normal.clone();
            row[24..26].copy_from_slice(&state.to_ne_bytes());
            let mut table = Neighbors::new();
            consume_dump(&row, &mut table, |_| true).unwrap();
            assert_eq!(table.len(), 1);
        }
    }

    #[test]
    fn route_dump_rejects_errors_and_truncation_and_matches_sequence() {
        let mut table = Neighbors::new();
        assert!(!consume_dump(&msg(3, 0, 2, &[]), &mut table, |_| true).unwrap());
        let mut truncated = neighbor("fd00::1", 1);
        truncated.pop();
        let mut corrupt = neighbor("fd00::1", 1);
        corrupt[28..30].copy_from_slice(&u16::MAX.to_ne_bytes());
        for packet in [
            msg(2, 0, 1, &[]),
            msg(3, 16, 1, &[]),
            msg(3, 0, 1, &1u32.to_ne_bytes()),
            vec![0; 10],
            truncated,
            corrupt,
        ] {
            assert!(consume_dump(&packet, &mut table, |_| true).is_err());
        }
    }
}
