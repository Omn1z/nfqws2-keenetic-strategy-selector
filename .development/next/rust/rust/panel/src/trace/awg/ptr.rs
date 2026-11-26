use super::{Flow, FlowRoute, Ring};
use crate::awg_rules::resolve::{nameservers, read_dns_file};
use futures_util::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use std::{
    collections::BTreeSet,
    fmt::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

const BUDGET: Duration = Duration::from_millis(800);
const CONCURRENCY: usize = 4;
pub(super) const MISS: Duration = Duration::from_secs(10 * 60);
const BUSY: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(super) struct Resolver {
    etc: Option<Arc<PathBuf>>,
    slots: Arc<Semaphore>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            etc: None,
            slots: Arc::new(Semaphore::new(CONCURRENCY)),
        }
    }
}

impl Resolver {
    pub(super) fn new(root: &Path) -> Self {
        Self {
            etc: Some(Arc::new(root.join("etc"))),
            ..Self::default()
        }
    }
}

pub(super) struct Request {
    pub(super) flow: Flow,
    pub(super) route: FlowRoute,
}

pub(super) struct Resolution {
    pub(super) request: Request,
    pub(super) generation: u64,
    pub(super) host: Option<String>,
}

pub(super) struct Queue {
    resolver: Resolver,
    pending: BTreeSet<IpAddr>,
    running: FuturesUnordered<BoxFuture<'static, Resolution>>,
}

impl Queue {
    pub(super) fn new(resolver: Resolver) -> Self {
        Self {
            resolver,
            pending: BTreeSet::new(),
            running: FuturesUnordered::new(),
        }
    }

    pub(super) fn request(&mut self, ring: &mut Ring, request: Request, generation: u64) {
        let ip = request.flow.dst.to_canonical();
        let now = Instant::now();
        let Some(etc) = self.resolver.etc.clone() else {
            return;
        };
        if self.pending.contains(&ip) || ring.ptr_backoff.get(&ip).is_some_and(|end| *end > now) {
            return;
        }
        let permit = (self.pending.len() < CONCURRENCY)
            .then(|| self.resolver.slots.clone().try_acquire_owned().ok())
            .flatten();
        let Some(permit) = permit else {
            ring.defer_ptr(ip, now + BUSY);
            return;
        };
        self.pending.insert(ip);
        self.running.push(Box::pin(async move {
            let host = tokio::task::spawn_blocking(move || {
                let _slot = permit;
                lookup(&etc, ip, now + BUDGET)
            })
            .await
            .ok()
            .flatten();
            Resolution {
                request,
                generation,
                host,
            }
        }));
    }

    pub(super) fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    pub(super) async fn next(&mut self) -> Option<Resolution> {
        let result = self.running.next().await?;
        self.pending.remove(&result.request.flow.dst.to_canonical());
        Some(result)
    }
}

pub(super) fn eligible(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unique_local()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
        }
    }
}

fn reverse_name(ip: IpAddr) -> String {
    let mut name = String::new();
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            for byte in ip.octets().into_iter().rev() {
                write!(name, "{byte}.").unwrap();
            }
            name.push_str("in-addr.arpa");
        }
        IpAddr::V6(ip) => {
            for byte in ip.octets().into_iter().rev() {
                write!(name, "{:x}.{:x}.", byte & 15, byte >> 4).unwrap();
            }
            name.push_str("ip6.arpa");
        }
    }
    name
}

fn hostname(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.');
    if name.contains(':') {
        return None;
    }
    nfqws2_awg_profile::exact_route_hostname(name)
        .filter(|name| name.parse::<IpAddr>().is_err())
        .map(str::to_ascii_lowercase)
}

fn hosts_name(text: &str, ip: IpAddr) -> Option<String> {
    text.lines().find_map(|line| {
        let mut words = line.split('#').next()?.split_ascii_whitespace();
        if words.next()?.parse::<IpAddr>().ok()?.to_canonical() != ip {
            return None;
        }
        words.find_map(hostname)
    })
}

fn lookup(etc: &Path, ip: IpAddr, deadline: Instant) -> Option<String> {
    if Instant::now() >= deadline {
        return None;
    }
    if let Some(host) = read_dns_file(&etc.join("hosts"))
        .ok()
        .and_then(|text| hosts_name(&text, ip))
    {
        return Some(host);
    }
    let servers = nameservers(&etc.join("resolv.conf")).ok()?;
    lookup_servers(ip, &servers, deadline)
}

fn lookup_servers(ip: IpAddr, servers: &[SocketAddr], deadline: Instant) -> Option<String> {
    let question = reverse_name(ip);
    for (i, &upstream) in servers.iter().enumerate() {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }
        let attempt = now + remaining / (servers.len() - i) as u32;
        let mut name = question.clone();
        let mut visited = BTreeSet::new();
        for _ in 0..=16 {
            if !visited.insert(name.clone()) {
                break;
            }
            let query =
                nfqws2_dns::build_query(&name, 12, nfqws2_dns::transaction_id().ok()?).ok()?;
            let Ok(answer) = nfqws2_dns::exchange_until(&query, upstream, attempt) else {
                break;
            };
            let Ok((alias, hosts)) = nfqws2_dns::ptr_records(&answer) else {
                break;
            };
            if let Some(host) = hosts.iter().find_map(|v| hostname(v)) {
                return Some(host);
            }
            name = alias.and_then(|v| hostname(&v))?;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn sends_ipv4_and_ipv6_ptr_questions_with_canonical_names() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server = sock.local_addr().unwrap();
        let v4 = "::ffff:192.0.2.80".parse().unwrap();
        let v6 = "2001:db8::1".parse().unwrap();
        let ipv6_labels =
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        let reply = std::thread::spawn(move || {
            for name in ["80.2.0.192.in-addr.arpa", ipv6_labels] {
                let mut bytes = [0; 512];
                let (n, from) = sock.recv_from(&mut bytes).unwrap();
                assert_eq!(
                    nfqws2_dns::query_domain(&bytes[..n]).unwrap(),
                    (name.into(), 12)
                );
                let mut answer = bytes[..n].to_vec();
                answer[2..4].copy_from_slice(&[0x81, 0x80]);
                answer[7] = 1;
                answer.extend([0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 30, 0, 14]);
                answer.extend_from_slice(b"\x04Node\x07EXAMPLE\x00");
                sock.send_to(&answer, from).unwrap();
            }
        });
        for ip in [v4, v6] {
            assert_eq!(
                lookup_servers(ip, &[server], Instant::now() + BUDGET).as_deref(),
                Some("node.example")
            );
        }
        reply.join().unwrap();
        assert!(!eligible("::ffff:192.168.1.8".parse().unwrap()));
        assert!(!eligible("fd00::7".parse().unwrap()));
    }
}
