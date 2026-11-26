use crate::{conf, invalid};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

type Cache = BTreeMap<(String, u16), (Instant, Vec<SocketAddr>)>;
static CACHE: Mutex<Cache> = Mutex::new(BTreeMap::new());

fn cached_addresses<'a>(
    cache: &'a Cache,
    key: &(String, u16),
    now: Instant,
) -> Option<&'a [SocketAddr]> {
    cache
        .get(key)
        .filter(|(until, _)| *until > now)
        .map(|(_, addresses)| addresses.as_slice())
}

pub(crate) fn cached_endpoint_address(text: &str) -> Option<SocketAddr> {
    let (host, port) = conf::endpoint(text).ok()?;
    let key = (host.to_ascii_lowercase(), port);
    let entries = CACHE.lock().ok()?;
    let addresses = cached_addresses(&entries, &key, Instant::now())?;
    first_ipv4(addresses).or_else(|| addresses.first().copied())
}

fn first_ipv4(addresses: &[SocketAddr]) -> Option<SocketAddr> {
    addresses
        .iter()
        .find_map(|address| match address.ip().to_canonical() {
            IpAddr::V4(ip) => Some(SocketAddr::new(ip.into(), address.port())),
            IpAddr::V6(_) => None,
        })
}

pub(crate) fn resolve_client_endpoint(text: &str, deadline: Instant) -> io::Result<SocketAddr> {
    let (host, port) = conf::endpoint(text)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    first_ipv4(&lookup_host(host, port, deadline, true)?)
        .ok_or_else(|| invalid("не удалось разрешить IPv4-адрес сервера (endpoint)"))
}

/// Keep all resolver answers for routing and shared transport checks.
pub fn resolve_endpoint_addresses(text: &str, deadline: Instant) -> io::Result<Vec<SocketAddr>> {
    let (host, port) = conf::endpoint(text)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    lookup_host(host, port, deadline, true)
}

pub(crate) fn resolve_fresh_endpoint_addresses(
    text: &str,
    deadline: Instant,
) -> io::Result<Vec<SocketAddr>> {
    let (host, port) = conf::endpoint(text)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    lookup_host(host, port, deadline, false)
}

pub(crate) fn resolve_fresh_client_ipv4_addresses(
    text: &str,
    deadline: Instant,
) -> io::Result<Vec<SocketAddr>> {
    let (host, port) = conf::endpoint(text)?;
    query_host(host, port, deadline, system_ipv4_addresses)
}

/// Unlike the generic OS resolver wrapper, preserve the positive no-name or
/// no-address result separately from a timeout, resolver failure or syscall.
pub(crate) fn resolve_initial_replacement(
    text: &str,
    deadline: Instant,
) -> io::Result<Option<Vec<SocketAddr>>> {
    let (host, port) = conf::endpoint(text)?;
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    let addresses = replacement_lookup(host, port, deadline, system_replacement_addresses)?;
    if addresses
        .as_ref()
        .is_some_and(|addresses| first_ipv4(addresses).is_none())
        && replacement_lookup(host, port, deadline, system_ipv4_addresses)?.is_some()
    {
        // A changed answer calls for a new complete lookup.
        return Err(io::ErrorKind::Interrupted.into());
    }
    Ok(addresses)
}

pub(crate) fn verify_warm_replacement_ipv4_failure(
    text: &str,
    deadline: Instant,
) -> io::Result<()> {
    let (host, port) = conf::endpoint(text)?;
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    match replacement_lookup(host, port, deadline, system_ipv4_addresses) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(_) => Err(io::ErrorKind::Interrupted.into()),
    }
}

fn replacement_lookup(
    host: &str,
    port: u16,
    deadline: Instant,
    resolve: fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> io::Result<Option<Vec<SocketAddr>>> {
    // A successful AAAA lookup can mask a transient A failure in AF_UNSPEC.
    match query_host(host, port, deadline, resolve) {
        Ok(addresses) => Ok(Some(addresses)),
        Err(error)
            if error
                .get_ref()
                .is_some_and(|cause| cause.is::<NoEndpointAddress>()) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
struct NoEndpointAddress;

impl std::fmt::Display for NoEndpointAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("не удалось разрешить IPv4-адрес сервера (endpoint)")
    }
}

impl std::error::Error for NoEndpointAddress {}

fn lookup_host(
    host: &str,
    port: u16,
    deadline: Instant,
    use_cache: bool,
) -> io::Result<Vec<SocketAddr>> {
    // A policy checks all configured transports on each learned DNS answer.
    // Reuse recent successful lookups without pinning a rotating host forever.
    let key = (host.to_ascii_lowercase(), port);
    if use_cache {
        let entries = CACHE.lock().map_err(|_| invalid("кеш DNS недоступен"))?;
        if let Some(addresses) = cached_addresses(&entries, &key, Instant::now()) {
            return Ok(addresses.to_vec());
        }
    }
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    let addrs = query_host(host, port, deadline, system_addresses).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            invalid(&error.to_string())
        } else {
            error
        }
    })?;
    if use_cache {
        let now = Instant::now();
        let mut entries = CACHE.lock().map_err(|_| invalid("кеш DNS недоступен"))?;
        entries.retain(|_, (until, _)| *until > now);
        if entries.len() < 256 {
            entries.insert(key, (now + Duration::from_secs(30), addrs.clone()));
        }
    }
    Ok(addrs)
}

fn query_host(
    host: &str,
    port: u16,
    deadline: Instant,
    resolve: fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> io::Result<Vec<SocketAddr>> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    // A firmware resolver may keep running after the caller's deadline.
    static RESOLVING: AtomicUsize = AtomicUsize::new(0);
    RESOLVING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 2).then_some(n + 1)
        })
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "служба DNS занята"))?;
    let host = host.to_owned();
    let (tx, rx) = mpsc::channel();
    if let Err(err) = thread::Builder::new()
        .name("awg-resolve".into())
        .spawn(move || {
            let result = resolve(&host, port).and_then(|addresses| {
                let mut unique = Vec::new();
                for address in addresses {
                    if !unique.contains(&address) {
                        unique.push(address);
                    }
                }
                if unique.is_empty() {
                    return Err(invalid("адрес сервера не найден"));
                }
                Ok(unique)
            });
            RESOLVING.fetch_sub(1, Ordering::Release);
            let _ = tx.send(result);
        })
    {
        RESOLVING.fetch_sub(1, Ordering::Release);
        return Err(err);
    }
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => io::Error::from(io::ErrorKind::TimedOut),
            mpsc::RecvTimeoutError::Disconnected => io::Error::other("служба DNS остановлена"),
        })?
}

fn system_addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(Iterator::collect)
}

#[cfg(target_os = "linux")]
fn system_ipv4_addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    system_ip_addresses(host, port, libc::AF_INET)
}

#[cfg(target_os = "linux")]
fn system_replacement_addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    system_ip_addresses(host, port, libc::AF_UNSPEC)
}

#[cfg(not(target_os = "linux"))]
fn system_replacement_addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    system_addresses(host, port)
}

#[cfg(target_os = "linux")]
fn system_ip_addresses(host: &str, port: u16, family: libc::c_int) -> io::Result<Vec<SocketAddr>> {
    use std::{
        ffi::CString,
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
        ptr,
    };

    struct Records(*mut libc::addrinfo);
    impl Drop for Records {
        fn drop(&mut self) {
            // getaddrinfo owns the linked list until freeaddrinfo returns it.
            if !self.0.is_null() {
                unsafe { libc::freeaddrinfo(self.0) };
            }
        }
    }

    let host = CString::new(host).map_err(|_| invalid("неверное имя сервера"))?;
    let hints = libc::addrinfo {
        ai_family: family,
        ai_socktype: libc::SOCK_DGRAM,
        ai_protocol: libc::IPPROTO_UDP,
        ai_flags: 0,
        ai_addrlen: 0,
        ai_addr: ptr::null_mut(),
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };
    let mut head = ptr::null_mut();
    // Both inputs live through the call. A successful call returns a list
    // owned by this function. Check each address family and length before casting.
    let status = unsafe { libc::getaddrinfo(host.as_ptr(), ptr::null(), &hints, &mut head) };
    if status != 0 {
        let kind = match status {
            libc::EAI_NONAME | libc::EAI_NODATA => {
                return Err(io::Error::new(io::ErrorKind::NotFound, NoEndpointAddress));
            }
            libc::EAI_AGAIN => io::ErrorKind::TimedOut,
            libc::EAI_FAIL => io::ErrorKind::ConnectionAborted,
            libc::EAI_SYSTEM => return Err(io::Error::last_os_error()),
            _ => io::ErrorKind::InvalidInput,
        };
        return Err(io::Error::new(
            kind,
            "не удалось разрешить IPv4-адрес сервера (endpoint)",
        ));
    }
    let records = Records(head);
    let mut record = records.0;
    let mut addresses = Vec::new();
    while let Some(info) = unsafe { record.as_ref() } {
        if info.ai_family == libc::AF_INET
            && !info.ai_addr.is_null()
            && info.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>()
        {
            let addr = unsafe { &*info.ai_addr.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
            addresses.push(SocketAddr::new(ip.into(), port));
        } else if info.ai_family == libc::AF_INET6
            && !info.ai_addr.is_null()
            && info.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in6>()
        {
            let addr = unsafe { &*info.ai_addr.cast::<libc::sockaddr_in6>() };
            addresses.push(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                port,
                u32::from_be(addr.sin6_flowinfo),
                addr.sin6_scope_id,
            )));
        } else {
            return Err(io::ErrorKind::InvalidData.into());
        }
        record = info.ai_next;
    }
    Ok(addresses)
}

#[cfg(not(target_os = "linux"))]
fn system_ipv4_addresses(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok(system_addresses(host, port)?
        .into_iter()
        .filter(SocketAddr::is_ipv4)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_client_prefers_first_ipv4_while_routing_keeps_each_family() {
        let port = 51820;
        let dual_host = "test-ordered-endpoint.invalid";
        let v6_host = "test-v6-only-endpoint.invalid";
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let v4: SocketAddr = "192.0.2.11:51820".parse().unwrap();
        let other_v4: SocketAddr = "192.0.2.12:51820".parse().unwrap();
        let answers = vec![v6, v4, other_v4];
        let now = Instant::now();
        let until = now + Duration::from_secs(30);
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert((dual_host.into(), port), (until, answers.clone()));
            cache.insert((v6_host.into(), port), (until, vec![v6]));
        }

        let dual = format!("{dual_host}:{port}");
        let v6_name = format!("{v6_host}:{port}");
        assert_eq!(resolve_client_endpoint(&dual, now).unwrap(), v4);
        assert_eq!(
            resolve_fresh_endpoint_addresses(&dual, now)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            resolve_fresh_client_ipv4_addresses(&dual, now)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(cached_endpoint_address(&dual), Some(v4));
        assert_eq!(resolve_endpoint_addresses(&dual, now).unwrap(), answers);
        assert!(resolve_client_endpoint(&v6_name, now).is_err());
        assert_eq!(resolve_client_endpoint(&v6.to_string(), now).unwrap(), v6);
        assert_eq!(resolve_endpoint_addresses(&v6_name, now).unwrap(), [v6]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the isolated guest's loopback DNS at port 53"]
    fn fresh_named_reconnect_only_queries_a_and_sees_dns_rotation() {
        assert_eq!(
            std::fs::read_to_string("/synthetic-guest").unwrap(),
            "ea1-qemu-airgap"
        );
        let resolver = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 53)).unwrap();
        resolver
            .set_read_timeout(Some(Duration::from_secs(6)))
            .unwrap();
        let host = "rotation.example.test.";
        let port = 51820;
        let endpoint = format!("{host}:{port}");
        let cached = "192.0.2.99:51820".parse().unwrap();
        CACHE.lock().unwrap().insert(
            (host.into(), port),
            (Instant::now() + Duration::from_secs(30), vec![cached]),
        );
        let server = thread::spawn(move || {
            for first in [Some(80), Some(81), None] {
                let mut packet = [0; 512];
                let (length, client) = resolver.recv_from(&mut packet).unwrap();
                assert!(length >= 12);
                const NAME: &[u8] = b"\x08rotation\x07example\x04test\0";
                let question_end = 12 + NAME.len() + 4;
                assert!(length >= question_end);
                assert_eq!(&packet[12..12 + NAME.len()], NAME);
                assert_eq!(&packet[12 + NAME.len()..question_end], [0, 1, 0, 1]);
                let mut response = packet[..question_end].to_vec();
                if let Some(first) = first {
                    response[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
                    for last in [first, 42] {
                        response.extend_from_slice(&[
                            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last,
                        ]);
                    }
                } else {
                    response[2..12].copy_from_slice(&[0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0]);
                }
                resolver.send_to(&response, client).unwrap();
            }
        });
        for first in [80, 81] {
            let selected = resolve_fresh_client_ipv4_addresses(
                &endpoint,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(
                selected,
                [
                    SocketAddr::from(([192, 0, 2, first], port)),
                    SocketAddr::from(([192, 0, 2, 42], port)),
                ]
            );
        }
        let absent =
            resolve_fresh_client_ipv4_addresses(&endpoint, Instant::now() + Duration::from_secs(5))
                .unwrap_err();
        assert_eq!(absent.kind(), io::ErrorKind::NotFound);
        server.join().unwrap();
        assert_eq!(cached_endpoint_address(&endpoint), Some(cached));
    }
}
