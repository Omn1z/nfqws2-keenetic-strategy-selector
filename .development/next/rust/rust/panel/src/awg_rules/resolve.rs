//! Resolution of explicit route destinations using only the caller's DNS servers.
use crate::dnsserver::ArchiveResolver;
use std::{
    fs::OpenOptions,
    io::{self, Read},
    net::{IpAddr, SocketAddr, SocketAddrV6},
    path::Path,
    time::{Duration, Instant},
};

const MAX_SERVERS: usize = 3;
const MAX_ALIASES: usize = 16;
const MAX_LOOKUP: Duration = Duration::from_secs(15);

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
fn scoped_server(value: &str) -> Option<SocketAddr> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    let (address, zone) = value.split_once('%')?;
    let scope = zone.parse::<u32>().ok();
    #[cfg(unix)]
    let scope = scope.or_else(|| {
        let zone = std::ffi::CString::new(zone).ok()?;
        // if_nametoindex reads this NUL-terminated interface name.
        Some(unsafe { libc::if_nametoindex(zone.as_ptr()) })
    });
    Some(SocketAddr::V6(SocketAddrV6::new(
        address.parse().ok()?,
        53,
        0,
        scope.filter(|index| *index != 0)?,
    )))
}
fn usable_server(addr: SocketAddr) -> bool {
    addr.port() != 0
        && !addr.ip().is_unspecified()
        && !addr.ip().is_multicast()
        && !matches!(addr.ip(),IpAddr::V4(ip) if ip.octets()[0]==0 || ip.octets()[0]>=240)
}
pub(crate) fn read_dns_file(path: &Path) -> io::Result<String> {
    const LIMIT: u64 = 16 * 1024;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("ожидается обычный файл настроек DNS"));
    }
    let mut data = String::new();
    file.take(LIMIT + 1).read_to_string(&mut data)?;
    if data.len() as u64 > LIMIT {
        return Err(invalid("файл настроек DNS превышает 16 КиБ"));
    }
    Ok(data)
}

pub(crate) fn nameservers(path: &Path) -> io::Result<Vec<SocketAddr>> {
    let data = read_dns_file(path)?;
    let mut out = Vec::new();
    for line in data.lines() {
        let mut words = line
            .split([';', '#'])
            .next()
            .unwrap_or("")
            .split_ascii_whitespace();
        if words.next() == Some("nameserver") {
            if let Some(addr) = words
                .next()
                .and_then(scoped_server)
                .filter(|v| usable_server(*v))
            {
                if !out.contains(&addr) {
                    out.push(addr);
                    if out.len() == MAX_SERVERS {
                        break;
                    }
                }
            }
        }
    }
    if out.is_empty() {
        return Err(invalid("в resolv.conf нет настроенных DNS-серверов"));
    }
    Ok(out)
}

fn exact_name(raw: &str) -> io::Result<&str> {
    nfqws2_awg_profile::exact_route_hostname(raw)
        .filter(|_| !raw.contains(':'))
        .ok_or_else(|| invalid("ожидается точное имя узла DNS"))
}
fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.octets()[0] != 0 && ip.octets()[0] < 224 && !ip.is_loopback() && !ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}

fn advance(visited: &mut Vec<String>, raw: &[u8], kind: u16) -> io::Result<(bool, Vec<IpAddr>)> {
    let (chain, addresses) = nfqws2_dns::exact_address_step(raw, kind)?;
    let follow = !chain.is_empty();
    for alias in chain {
        exact_name(&alias)?;
        if visited.len() > MAX_ALIASES || visited.contains(&alias) {
            return Err(invalid("циклическая или слишком длинная цепочка DNS CNAME"));
        }
        visited.push(alias);
    }
    Ok((follow, addresses))
}

fn lookup(host: &str, server: SocketAddr, deadline: Instant, kind: u16) -> io::Result<Vec<IpAddr>> {
    let mut visited = vec![host.to_ascii_lowercase()];
    loop {
        let query =
            nfqws2_dns::build_query(visited.last().unwrap(), kind, nfqws2_dns::transaction_id()?)?;
        let raw = nfqws2_dns::exchange_until(&query, server, deadline)?;
        let (follow, addresses) = advance(&mut visited, &raw, kind)?;
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if !addresses.is_empty() {
            if !addresses.iter().copied().all(routable) {
                return Err(invalid("DNS-ответ содержит служебный адрес"));
            }
            return Ok(addresses);
        }
        if !follow {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "для имени нет адресов запрошенного семейства",
            ));
        }
    }
}

pub(super) async fn managed_family(
    resolver: &ArchiveResolver,
    host: &str,
    deadline: Instant,
    kind: u16,
    current: &impl Fn() -> bool,
) -> io::Result<(Vec<IpAddr>, Instant)> {
    let mut names = vec![host.to_owned()];
    let mut expires: Option<Instant> = None;
    loop {
        if !current() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let end = expires.map_or(deadline, |at| deadline.min(at));
        if Instant::now() >= end {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let query =
            nfqws2_dns::build_query(names.last().unwrap(), kind, nfqws2_dns::transaction_id()?)?;
        let reply = tokio::time::timeout_at(end.into(), resolver.fresh_managed_reply(&query)).await;
        let received = Instant::now();
        if !current() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if received >= end {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let wire = match reply.map_err(|_| io::ErrorKind::TimedOut)? {
            Err(error)
                if names.len() > 1 && crate::dnsserver::is_managed_upstream_timeout(&error) =>
            {
                return Err(io::ErrorKind::TimedOut.into())
            }
            result => result?,
        };
        let (follow, addresses) = advance(&mut names, &wire, kind)?;
        if addresses.is_empty() && !follow {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "для имени нет адресов запрошенного семейства",
            ));
        }
        let ttl = nfqws2_dns::route_answer(&wire)?
            .map(|answer| answer.ttl)
            .filter(|&ttl| ttl != 0)
            .ok_or_else(|| invalid("DNS-ответ для маршрута не имеет действующего TTL"))?;
        let until = received + Duration::from_secs(ttl.into());
        let until = expires.map_or(until, |at| at.min(until));
        if !addresses.is_empty() {
            if !addresses.iter().copied().all(routable) {
                return Err(invalid("DNS-ответ содержит служебный адрес"));
            }
            return Ok((addresses, until));
        }
        expires = Some(until);
    }
}

pub(super) async fn managed_addresses(
    resolver: &ArchiveResolver,
    host: &str,
    deadline: Instant,
    ipv4: bool,
    ipv6: bool,
    current: impl Fn() -> bool,
) -> io::Result<(Vec<IpAddr>, Instant)> {
    let host = exact_name(host)?.to_ascii_lowercase();
    let mut result = Vec::new();
    let mut expires: Option<Instant> = None;
    for (enabled, kind) in [(ipv4, 1), (ipv6, 28)] {
        if enabled {
            match managed_family(resolver, &host, deadline, kind, &current).await {
                Ok((ips, until)) => {
                    result.extend(ips);
                    expires = Some(expires.map_or(until, |at| at.min(until)));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    let expires = expires.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "DNS не вернул подходящих адресов")
    })?;
    if Instant::now() >= expires {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok((result, expires))
}

fn resolve_family(
    host: &str,
    servers: &[SocketAddr],
    deadline: Instant,
    kind: u16,
) -> io::Result<Vec<IpAddr>> {
    let host = exact_name(host)?;
    if servers.is_empty()
        || servers.len() > MAX_SERVERS
        || !servers.iter().copied().all(usable_server)
    {
        return Err(invalid(
            "требуется от одного до трёх настроенных DNS-серверов",
        ));
    }
    let deadline = deadline.min(Instant::now() + MAX_LOOKUP);
    let mut error: io::Error = io::ErrorKind::TimedOut.into();
    for (i, &server) in servers.iter().enumerate() {
        let now = Instant::now();
        let left = deadline.saturating_duration_since(now);
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let share = left / (servers.len() - i) as u32;
        match lookup(host, server, now + share, kind) {
            Ok(addresses) => return Ok(addresses),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::NotFound
                ) =>
            {
                return Err(e)
            }
            Err(e) => error = e,
        }
    }
    Err(error)
}

pub(super) fn addresses(
    host: &str,
    servers: &[SocketAddr],
    deadline: Instant,
    ipv4: bool,
    ipv6: bool,
) -> io::Result<Vec<IpAddr>> {
    let mut result = Vec::new();
    for (enabled, kind) in [(ipv4, 1), (ipv6, 28)] {
        if enabled {
            match resolve_family(host, servers, deadline, kind) {
                Ok(ips) => result.extend(ips),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    if result.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS не вернул подходящих адресов",
        ));
    }
    Ok(result)
}
#[cfg(test)]
fn ipv4(host: &str, servers: &[SocketAddr], deadline: Instant) -> io::Result<Vec<IpAddr>> {
    resolve_family(host, servers, deadline, 1)
}

#[cfg(test)]
use std::net::Ipv4Addr;
#[cfg(test)]
mod tests;
