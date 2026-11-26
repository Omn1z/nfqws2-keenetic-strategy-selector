//! Fixed production Telegram destinations accepted by the VPN retry path.
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{lookup_host, TcpStream},
    time::{timeout_at, Instant},
};

pub fn public_relay_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && b & 192 == 64)
                && !(a == 198 && matches!(b, 18 | 19))
                && !(a == 192 && (b == 0 && c == 0 || b == 88 && c == 99))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            a & 0xe000 == 0x2000
                && a != 0x2002
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && !(a == 0x3fff && b <= 0x0fff)
        }
    }
}

/// Dial only accepted public addresses within the caller's setup deadline.
pub async fn connect_public(host: &str, port: u16, deadline: Instant) -> io::Result<TcpStream> {
    let addresses = public_addresses(lookup_host((host, port)).await?);
    connect_addresses(addresses, deadline, TcpStream::connect).await
}

fn public_addresses(
    addresses: impl Iterator<Item = SocketAddr>,
) -> impl Iterator<Item = SocketAddr> {
    addresses
        .filter(|address| public_relay_ip(address.ip()))
        .take(8)
}

/// Dial a named Telegram relay with Go's fallback timing and the caller's setup deadline.
pub async fn connect_named(host: &str, port: u16, deadline: Instant) -> io::Result<TcpStream> {
    connect_addresses(
        lookup_host((host, port)).await?,
        deadline,
        TcpStream::connect,
    )
    .await
}

async fn connect_addresses<T, F>(
    addresses: impl IntoIterator<Item = SocketAddr>,
    deadline: Instant,
    dial: impl Fn(SocketAddr) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let mut addresses = addresses.into_iter().peekable();
    let first = addresses.peek().ok_or_else(missing_address)?;
    let ipv4 = first.ip().to_canonical().is_ipv4();
    let (primary, alternate): (Vec<_>, Vec<_>) =
        addresses.partition(|address| address.ip().to_canonical().is_ipv4() == ipv4);
    let primary = dial_family(primary, deadline, &dial);
    if alternate.is_empty() {
        return primary.await;
    }

    let mut primary = std::pin::pin!(primary);
    let mut alternate = std::pin::pin!(dial_family(alternate, deadline, &dial));
    // Resolver order picks the primary family. Only a stalled family gets a
    // head start. A failed family lets the other start immediately.
    tokio::select! {
        biased;
        result = &mut primary => {
            return match result {
                Ok(socket) => Ok(socket),
                Err(error) => alternate.await.or(Err(error)),
            };
        }
        _ = tokio::time::sleep(Duration::from_millis(300)) => {}
    }
    tokio::select! {
        biased;
        result = &mut primary => match result {
            Ok(socket) => Ok(socket),
            Err(error) => alternate.await.or(Err(error)),
        },
        result = &mut alternate => match result {
            Ok(socket) => Ok(socket),
            Err(_) => primary.await,
        },
    }
}

async fn dial_family<T, F>(
    addresses: Vec<SocketAddr>,
    deadline: Instant,
    dial: &impl Fn(SocketAddr) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let mut first_error = None;
    let address_count = addresses.len();
    for (index, address) in addresses.into_iter().enumerate() {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        let count = u32::try_from(address_count - index).unwrap_or(u32::MAX);
        let share = (remaining / count).max(Duration::from_secs(2));
        let attempt = dial(address);
        // Leave expiry at the setup deadline to the caller. In particular, H2
        // handles expiration of the DC setup separately from an origin failure.
        let result = if share < remaining {
            timeout_at(now + share, attempt)
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        } else {
            attempt.await
        };
        match result {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error.unwrap_or_else(missing_address))
}

fn missing_address() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any address",
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Telegram(Ipv4Addr);
/// Preserve primary results and retry only recognized Telegram destinations.
pub async fn after_direct<T, F>(
    direct: io::Result<T>,
    target: Option<Telegram>,
    via: impl FnOnce(Telegram) -> F,
) -> io::Result<(T, bool)>
where
    F: std::future::Future<Output = io::Result<Option<T>>>,
{
    match direct {
        Ok(v) => Ok((v, false)),
        Err(e) => match target {
            Some(endpoint) => via(endpoint).await?.map(|v| (v, true)).ok_or(e),
            None => Err(e),
        },
    }
}
impl Telegram {
    pub fn web(dc: i16, test: bool) -> Option<Self> {
        if test {
            return None;
        }
        match dc.unsigned_abs() {
            1 | 3 => Some(Self(Ipv4Addr::new(149, 154, 174, 100))),
            5 => Some(Self(Ipv4Addr::new(149, 154, 170, 100))),
            _ => None,
        }
    }
    pub fn address(ip: IpAddr, port: u16) -> Option<Self> {
        if port != 443 {
            return None;
        }
        let IpAddr::V4(ip) = ip.to_canonical() else {
            return None;
        };
        matches!(
            ip.octets(),
            [149, 154, 175, 50 | 100] | [149, 154, 171, 5] | [149, 154, 174 | 170, 100]
        )
        .then_some(Self(ip))
    }
    pub fn host(name: &str, port: u16) -> Option<Self> {
        if port != 443 {
            return None;
        }
        let name = name.strip_suffix('.').unwrap_or(name);
        for (dc, standard, media) in [
            (1, "kws1.web.telegram.org", "kws1-1.web.telegram.org"),
            (3, "kws3.web.telegram.org", "kws3-1.web.telegram.org"),
            (5, "kws5.web.telegram.org", "kws5-1.web.telegram.org"),
        ] {
            if name.eq_ignore_ascii_case(standard) || name.eq_ignore_ascii_case(media) {
                return Self::web(dc, false);
            }
        }
        Self::address(name.parse().ok()?, port)
    }
    pub async fn connect(self, iface: &str) -> io::Result<TcpStream> {
        if !valid_iface(iface) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(target_os = "linux")]
        {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket2::SockRef::from(&socket).bind_device(Some(iface.as_bytes()))?;
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.connect((self.0, 443).into()),
            )
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}
pub fn valid_iface(iface: &str) -> bool {
    iface.len() < 16
        && iface
            .strip_prefix("awg")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use tokio::time::{sleep, timeout};

    #[tokio::test(start_paused = true)]
    async fn named_connections_start_the_other_family_after_three_hundred_milliseconds() {
        struct PendingDial<'a>(&'a Cell<bool>);
        impl Drop for PendingDial<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let v6 = "[::1]:443".parse().unwrap();
        let v4 = "127.0.0.1:443".parse().unwrap();
        let start = Instant::now();
        let attempts = RefCell::new(Vec::new());
        let canceled = Cell::new(false);
        let result = timeout(
            Duration::from_secs(1),
            connect_addresses([v6, v4], start + Duration::from_secs(1), |address| {
                let (attempts, canceled) = (&attempts, &canceled);
                async move {
                    attempts.borrow_mut().push((address, start.elapsed()));
                    if address == v6 {
                        let _pending = PendingDial(canceled);
                        std::future::pending().await
                    } else {
                        Ok(address)
                    }
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, v4);
        assert_eq!(
            attempts.into_inner(),
            [(v6, Duration::ZERO), (v4, Duration::from_millis(300))]
        );
        assert!(canceled.get());
    }

    #[tokio::test(start_paused = true)]
    async fn named_connections_keep_family_order_and_start_immediate_fallback_after_failure() {
        let v4_first = "127.0.0.1:443".parse().unwrap();
        let v6_first = "[::1]:443".parse().unwrap();
        let v4_second = "[::ffff:127.0.0.2]:443".parse().unwrap();
        let v6_second = "[::2]:443".parse().unwrap();
        let start = Instant::now();
        let attempts = RefCell::new(Vec::new());
        let result = connect_addresses(
            [v4_first, v6_first, v4_second, v6_second],
            start + Duration::from_secs(1),
            |address| {
                attempts.borrow_mut().push(address);
                std::future::ready(if address == v6_second {
                    Ok(address)
                } else {
                    Err(io::ErrorKind::ConnectionRefused.into())
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(result, v6_second);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(
            attempts.into_inner(),
            [v4_first, v4_second, v6_first, v6_second]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn named_connections_keep_primary_running_after_an_alternate_failure() {
        let v6 = "[::1]:443".parse().unwrap();
        let v4 = "127.0.0.1:443".parse().unwrap();
        let start = Instant::now();
        let result = connect_addresses(
            [v6, v4],
            start + Duration::from_secs(1),
            |address| async move {
                if address == v6 {
                    sleep(Duration::from_millis(400)).await;
                    Ok(address)
                } else {
                    Err(io::ErrorKind::ConnectionRefused.into())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, v6);
        assert_eq!(start.elapsed(), Duration::from_millis(400));
    }

    #[tokio::test(start_paused = true)]
    async fn named_connections_return_the_first_primary_error_and_handle_a_single_family() {
        let v6 = "[::1]:443".parse().unwrap();
        let v4_first = "127.0.0.1:443".parse().unwrap();
        let v4_second = "127.0.0.2:443".parse().unwrap();
        let dial = |address| {
            std::future::ready(Err::<(), _>(
                if address == v4_first {
                    io::ErrorKind::ConnectionRefused
                } else {
                    io::ErrorKind::PermissionDenied
                }
                .into(),
            ))
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        for addresses in [vec![v4_first, v6, v4_second], vec![v4_first, v4_second]] {
            let error = connect_addresses(addresses, deadline, dial)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        }
        let error = connect_addresses([], deadline, dial).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test(start_paused = true)]
    async fn named_connections_share_the_budget_between_addresses_in_one_family() {
        let first = "127.0.0.1:443".parse().unwrap();
        let second = "127.0.0.2:443".parse().unwrap();
        let third = "127.0.0.3:443".parse().unwrap();
        for (addresses, seconds, expected) in [
            (vec![first, second], 8, vec![0, 4]),
            (vec![first, second, third], 5, vec![0, 2, 4]),
        ] {
            let last = *addresses.last().unwrap();
            let start = Instant::now();
            let deadline = start + Duration::from_secs(seconds);
            let attempts = RefCell::new(Vec::new());
            let result = timeout_at(
                deadline,
                connect_addresses(addresses, deadline, |address| {
                    attempts.borrow_mut().push(start.elapsed());
                    async move {
                        if address == last {
                            Ok(address)
                        } else {
                            std::future::pending().await
                        }
                    }
                }),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result, last);
            let expected: Vec<_> = expected.into_iter().map(Duration::from_secs).collect();
            assert_eq!(attempts.into_inner(), expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn alternate_family_shares_only_its_remaining_time_after_the_stagger() {
        let v6 = "[::1]:443".parse().unwrap();
        let first_v4 = "127.0.0.1:443".parse().unwrap();
        let second_v4 = "127.0.0.2:443".parse().unwrap();
        let start = Instant::now();
        let deadline = start + Duration::from_secs(8);
        let attempts = RefCell::new(Vec::new());
        let result = timeout_at(
            deadline,
            connect_addresses([v6, first_v4, second_v4], deadline, |address| {
                attempts.borrow_mut().push((address, start.elapsed()));
                async move {
                    if address == second_v4 {
                        Ok(address)
                    } else {
                        std::future::pending().await
                    }
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, second_v4);
        assert_eq!(
            attempts.into_inner(),
            [
                (v6, Duration::ZERO),
                (first_v4, Duration::from_millis(300)),
                (second_v4, Duration::from_millis(4150)),
            ]
        );
    }

    #[tokio::test]
    async fn named_connection_dials_a_real_loopback_socket_with_the_setup_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let client = timeout_at(
            deadline,
            connect_named("127.0.0.1", address.port(), deadline),
        )
        .await
        .unwrap()
        .unwrap();
        let (_server, peer) = timeout_at(deadline, listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client.peer_addr().unwrap(), address);
        assert_eq!(client.local_addr().unwrap(), peer);
    }

    #[test]
    fn public_connection_filter_keeps_order_and_bounds_the_address_list_before_racing() {
        let v4_mapped_loopback = "[::ffff:127.0.0.1]:443".parse().unwrap();
        let v6_public = "[2606:4700::1]:443".parse().unwrap();
        let v6_local = "[::1]:443".parse().unwrap();
        let public_ipv4: Vec<_> = (1..=8)
            .map(|last| (Ipv4Addr::new(1, 1, 1, last), 443).into())
            .collect();
        let addresses = [v4_mapped_loopback, v6_public, v6_local]
            .into_iter()
            .chain(public_ipv4.iter().copied());
        let retained: Vec<_> = public_addresses(addresses).collect();
        assert_eq!(retained[0], v6_public);
        assert_eq!(retained[1..], public_ipv4[..7]);
    }

    #[test]
    fn fixed_retry_targets_accept_only_production_dc_1_3_5_and_port_443() {
        let front = Telegram::web(-3, false).unwrap();
        assert_eq!(Some(front), Telegram::host("KWS3-1.WEB.TELEGRAM.ORG.", 443));
        assert_eq!(
            Some(front),
            Telegram::address("::ffff:149.154.174.100".parse().unwrap(), 443)
        );
        assert!(Telegram::address("149.154.175.50".parse().unwrap(), 443).is_some());
        for (host, port) in [
            ("kws1.web.telegram.org.invalid", 443),
            ("kws1.web.telegram.org", 8443),
            ("149.154.167.220", 443),
            ("127.0.0.1", 443),
            ("kws2.web.telegram.org", 443),
        ] {
            assert!(Telegram::host(host, port).is_none());
        }
        for (dc, test) in [(2, false), (203, false), (10001, false), (3, true)] {
            assert!(Telegram::web(dc, test).is_none());
        }
        for iface in ["eth0", "lo", "awg0.1", "awg", "awg0/eth0"] {
            assert!(!valid_iface(iface));
        }
    }
}
