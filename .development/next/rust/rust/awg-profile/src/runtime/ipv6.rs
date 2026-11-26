use std::{
    io,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(90);
const LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Reach {
    Split,
    Online,
    Offline,
}
fn classify(route: io::Result<()>, tcp: impl FnOnce() -> io::Result<()>) -> Reach {
    match route {
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable
            ) =>
        {
            Reach::Split
        }
        Ok(()) if tcp().is_ok() => Reach::Online,
        _ => Reach::Offline,
    }
}

#[cfg(target_os = "linux")]
fn probe(iface: &str) -> (Reach, Option<bool>) {
    use std::net::{Ipv6Addr, SocketAddrV6};
    let resolver = SocketAddrV6::new(
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        53,
        0,
        0,
    )
    .into();
    probe_to(iface, resolver)
}

#[cfg(target_os = "linux")]
fn probe_to(iface: &str, address: SocketAddr) -> (Reach, Option<bool>) {
    use socket2::{Domain, SockAddr, Socket, Type};
    let resolver = SockAddr::from(address);
    let socket = |kind| -> io::Result<Socket> {
        let s = Socket::new(Domain::IPV6, kind, None)?;
        s.bind_device(Some(iface.as_bytes()))?;
        Ok(s)
    };
    // UDP connect performs a bound route lookup without sending a packet.
    // A split VPN need not route the public control host. If a path exists,
    // use the same TCP check as Go and never retry it over the native WAN.
    let route = socket(Type::DGRAM).and_then(|s| s.connect(&resolver));
    let mut attempted = None;
    let reach = classify(route, || {
        let bound = socket(Type::STREAM)?;
        let connected = bound.connect_timeout(&resolver, Duration::from_secs(2));
        attempted = Some(connected.is_ok());
        connected
    });
    (reach, attempted)
}

struct Entry {
    iface: String,
    index: u32,
    key: String,
    endpoint: SocketAddr,
    when: Instant,
    reach: Reach,
}
#[derive(Default)]
pub(super) struct Cache(Mutex<Vec<Entry>>);
impl Cache {
    #[cfg(target_os = "linux")]
    pub(super) fn reach(&self, iface: &str, key: &str, endpoint: SocketAddr) -> Reach {
        let Some(index) = interface_index(iface) else {
            return Reach::Offline;
        };
        self.result(iface, index, key, endpoint, Instant::now(), || {
            probe(iface).0
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn fresh_bound(&self, iface: &str, key: &str, endpoint: SocketAddr) -> Option<bool> {
        let index = interface_index(iface)?;
        let (reach, attempted) = probe(iface);
        if attempted.is_some() && interface_index(iface) == Some(index) {
            self.save(iface, index, key, endpoint, Instant::now(), reach);
            return attempted;
        }
        None
    }
    fn result(
        &self,
        iface: &str,
        index: u32,
        key: &str,
        endpoint: SocketAddr,
        now: Instant,
        probe: impl FnOnce() -> Reach,
    ) -> Reach {
        {
            let mut entries = self.0.lock().unwrap();
            entries.retain(|e| now.saturating_duration_since(e.when) < TTL);
            if let Some(e) = entries.iter().find(|e| {
                e.iface == iface && e.index == index && e.key == key && e.endpoint == endpoint
            }) {
                return e.reach;
            }
        }
        let reach = probe();
        self.save(iface, index, key, endpoint, now, reach);
        reach
    }

    fn save(
        &self,
        iface: &str,
        index: u32,
        key: &str,
        endpoint: SocketAddr,
        now: Instant,
        reach: Reach,
    ) {
        let mut entries = self.0.lock().unwrap();
        entries.retain(|e| e.iface != iface);
        if entries.len() >= LIMIT {
            entries.remove(0);
        }
        entries.push(Entry {
            iface: iface.into(),
            index,
            key: key.into(),
            endpoint,
            when: now,
            reach,
        });
    }
    #[cfg(test)]
    fn check(
        &self,
        iface: &str,
        index: u32,
        key: &str,
        endpoint: SocketAddr,
        now: Instant,
        probe: impl FnOnce() -> Reach,
    ) -> bool {
        self.result(iface, index, key, endpoint, now, probe) != Reach::Offline
    }
}

#[cfg(target_os = "linux")]
fn interface_index(iface: &str) -> Option<u32> {
    let name = std::ffi::CString::new(iface).ok()?;
    // The NUL-terminated interface name stays live through the system call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_without_a_public_route_is_distinct_from_a_failed_tcp_connection() {
        let yes = || Ok(());
        assert_eq!(classify(Ok(()), yes), Reach::Online);
        assert_eq!(
            classify(Ok(()), || Err(io::ErrorKind::TimedOut.into())),
            Reach::Offline
        );
        assert_eq!(
            classify(Err(io::ErrorKind::NetworkUnreachable.into()), || panic!(
                "no public route"
            )),
            Reach::Split
        );
        assert_eq!(
            classify(Err(io::ErrorKind::PermissionDenied.into()), || panic!(
                "socket is not bound"
            )),
            Reach::Offline
        );
    }
    #[test]
    fn cache_expires_and_does_not_reuse_a_replaced_tunnel_or_peer() {
        let c = Cache::default();
        let ep = "[2001:db8::1]:51820".parse().unwrap();
        let now = Instant::now();
        assert!(c.check("awg0", 5, "a", ep, now, || Reach::Online));
        assert!(c.check(
            "awg0",
            5,
            "a",
            ep,
            now + TTL - Duration::from_secs(1),
            || panic!("fresh")
        ));
        assert!(!c.check("awg0", 5, "a", ep, now + TTL, || Reach::Offline));
        assert!(c.check("awg0", 5, "b", ep, now + TTL, || Reach::Split));
        assert!(!c.check("awg0", 6, "b", ep, now + TTL, || Reach::Offline));
        assert!(c.check("awg1", 7, "b", ep, now + TTL, || Reach::Online));
        assert!(c.check(
            "awg0",
            6,
            "b",
            "[2001:db8::2]:42".parse().unwrap(),
            now + TTL,
            || Reach::Online
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the isolated guest's bound IPv6 loopback route"]
    fn fresh_ipv6_probe_distinguishes_missing_path_from_failed_tcp() {
        assert_eq!(
            std::fs::read_to_string("/synthetic-guest").unwrap(),
            "ea1-qemu-airgap"
        );
        let listener = std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        assert_eq!(probe_to("lo", address), (Reach::Online, Some(true)));
        drop(listener);
        assert_eq!(probe_to("lo", address), (Reach::Offline, Some(false)));
        assert_eq!(probe_to("n2s-missing", address), (Reach::Offline, None));
    }
}
