//! A bounded DNS response cache for the router. Resolution uses the caller's
//! chosen upstream. Caching preserves the request ID, question spelling and
//! DNSSEC/EDNS options, and ages TTLs against a monotonic clock.
mod wire;
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::Mutex,
    time::{Duration, Instant},
};
pub use wire::routes::{
    route_answer, trace_answer, RouteAnswer, TraceAnswer, MAX_ROUTE_ANSWER_ADDRESSES,
    MAX_ROUTE_ANSWER_TTL,
};
pub use wire::{
    address_negative_ttl, answer_records, blocked_reply, build_query, cap_ttls, clip_negative_soa,
    exact_address_step, exact_ipv4_step, first_ipv4, ptr_records, query_domain, resolved_addresses,
    response_error, udp_answer, visit_filter_targets, visit_typed_filter_targets,
};

/// Verify a candidate before it can win a race between resolvers.
pub fn validate_answer(request: &[u8], response: &[u8]) -> io::Result<()> {
    validate_forwarded_response(request, response)?;
    if response[2] & 2 != 0 || !matches!(response[3] & 15, 0 | 3) {
        return Err(wire::bad("dns: incomplete or unsuccessful response"));
    }
    Ok(())
}

/// Check the wire and question even when a forwarding proxy must preserve TC or an error code.
pub fn validate_forwarded_response(request: &[u8], response: &[u8]) -> io::Result<()> {
    wire::validate_response(response, request, &wire::query(request)?)
}

#[derive(Debug)]
pub struct Answer {
    pub wire: Vec<u8>,
    pub cached: bool,
    pub source: Option<Source>,
    /// Add the wire TTL to this instant to recover its absolute expiry.
    pub ttl_anchor: Instant,
}
#[derive(Clone, Debug)]
pub struct Source {
    pub route: String,
    pub upstream: String,
}
impl Answer {
    /// Copy a validated response to another request with the same sharing key.
    pub fn for_request(&self, request: &[u8]) -> io::Result<Self> {
        let mut answer = self.wire.clone();
        let q = wire::query(request)?;
        if answer.len() < q.end {
            return Err(wire::bad("dns: incomplete shared response"));
        }
        restore_question(request, q.end, &mut answer);
        Ok(Self {
            wire: answer,
            cached: self.cached,
            source: self.source.clone(),
            ttl_anchor: self.ttl_anchor,
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct CacheStatus {
    pub entries: usize,
    pub capacity: usize,
    pub ttl_seconds: u32,
}

struct Entry {
    weight: usize,
    created: Instant,
    expires: Instant,
    wire: Vec<u8>,
    ttls: Vec<(usize, u32)>,
    source: Option<Source>,
}
#[derive(Default)]
struct Cache {
    entries: HashMap<(String, Vec<u8>), Entry>,
    bytes: usize,
    generation: u64,
}
impl Cache {
    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, e| {
            if e.expires <= now {
                self.bytes -= e.weight;
                false
            } else {
                true
            }
        });
    }
    fn remove(&mut self, key: &(String, Vec<u8>)) {
        if let Some(e) = self.entries.remove(key) {
            self.bytes -= e.weight;
        }
    }
}
pub enum Lookup {
    Hit(Answer),
    Miss(PendingQuery),
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct QueryKey {
    identity: (String, Vec<u8>),
    generation: u64,
}

pub struct PendingQuery {
    question: wire::Question,
    key: Option<QueryKey>,
}

impl PendingQuery {
    pub fn sharing_key(&self) -> Option<&QueryKey> {
        self.key.as_ref()
    }
}

fn restore_question(request: &[u8], question_end: usize, answer: &mut [u8]) {
    answer[..2].copy_from_slice(&request[..2]);
    answer[12..question_end].copy_from_slice(&request[12..question_end]);
}
pub struct Resolver {
    capacity: usize,
    max_ttl: u32,
    timeout: Duration,
    cache: Mutex<Cache>,
}
impl Resolver {
    pub fn new(capacity: usize, max_ttl: u32, timeout: Duration) -> Self {
        Self {
            capacity,
            max_ttl,
            timeout,
            cache: Mutex::new(Cache::default()),
        }
    }
    pub fn clear(&self) -> usize {
        let mut cache = self.cache.lock().unwrap();
        let count = cache.entries.len();
        cache.entries.clear();
        cache.bytes = 0;
        cache.generation = cache.generation.wrapping_add(1);
        count
    }
    pub fn status(&self) -> CacheStatus {
        let mut cache = self.cache.lock().unwrap();
        let now = Instant::now();
        cache.expire(now);
        CacheStatus {
            entries: cache.entries.len(),
            capacity: self.capacity,
            ttl_seconds: self.max_ttl,
        }
    }
    pub fn exchange(&self, query: &[u8], upstream: SocketAddr) -> io::Result<Answer> {
        self.exchange_with(query, &upstream.to_string(), |q| {
            let deadline = Instant::now()
                .checked_add(self.timeout)
                .ok_or_else(|| wire::bad("invalid DNS timeout"))?;
            upstream_query(q, upstream, deadline)
        })
    }
    /// `scope` distinguishes upstreams and routing configurations. A custom
    /// transport can, for example, supply the response from a DoH connection.
    pub fn exchange_with(
        &self,
        query: &[u8],
        scope: &str,
        fetch: impl FnOnce(&[u8]) -> io::Result<Vec<u8>>,
    ) -> io::Result<Answer> {
        self.resolve_at(query, scope, fetch, Instant::now)
    }
    fn resolve_at(
        &self,
        query: &[u8],
        scope: &str,
        fetch: impl FnOnce(&[u8]) -> io::Result<Vec<u8>>,
        clock: impl Fn() -> Instant,
    ) -> io::Result<Answer> {
        let request = self.lookup(query, scope, clock())?;
        match request {
            Lookup::Hit(answer) => Ok(answer),
            Lookup::Miss(pending) => {
                self.finish_at(query, pending, fetch(query)?, true, None, clock())
            }
        }
    }
    pub async fn exchange_async<F: std::future::Future<Output = io::Result<Vec<u8>>>>(
        &self,
        query: &[u8],
        scope: &str,
        fetch: impl FnOnce() -> F,
    ) -> io::Result<Answer> {
        match self.lookup(query, scope, Instant::now())? {
            Lookup::Hit(answer) => Ok(answer),
            Lookup::Miss(pending) => self.finish(query, pending, fetch().await?, true, None),
        }
    }
    pub fn begin(&self, query: &[u8], scope: &str) -> io::Result<Lookup> {
        self.lookup(query, scope, Instant::now())
    }
    fn lookup(&self, query: &[u8], scope: &str, now: Instant) -> io::Result<Lookup> {
        let q = wire::query(query)?;
        let key = wire::query_key(query, &q)?.map(|key| (scope.to_owned(), key));
        let cache = self.cache.lock().unwrap();
        if let Some(answer) = Self::cached(&cache, key.as_ref(), query, q.end, now) {
            return Ok(Lookup::Hit(answer));
        }
        Ok(Lookup::Miss(PendingQuery {
            question: q,
            key: key.map(|identity| QueryKey {
                identity,
                generation: cache.generation,
            }),
        }))
    }
    pub fn recheck(&self, query: &[u8], pending: &PendingQuery) -> Option<Answer> {
        let key = pending.key.as_ref()?;
        let cache = self.cache.lock().unwrap();
        if key.generation != cache.generation {
            return None;
        }
        Self::cached(
            &cache,
            Some(&key.identity),
            query,
            pending.question.end,
            Instant::now(),
        )
    }
    fn cached(
        cache: &Cache,
        key: Option<&(String, Vec<u8>)>,
        query: &[u8],
        question_end: usize,
        now: Instant,
    ) -> Option<Answer> {
        let found = cache.entries.get(key?).filter(|e| now < e.expires)?;
        let age = now
            .saturating_duration_since(found.created)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        let mut answer = found.wire.clone();
        for &(offset, original) in &found.ttls {
            answer[offset..offset + 4].copy_from_slice(&original.saturating_sub(age).to_be_bytes());
        }
        restore_question(query, question_end, &mut answer);
        Some(Answer {
            wire: answer,
            cached: true,
            source: found.source.clone(),
            ttl_anchor: found.created + Duration::from_secs(u64::from(age)),
        })
    }
    pub fn finish(
        &self,
        query: &[u8],
        pending: PendingQuery,
        answer: Vec<u8>,
        cacheable: bool,
        source: Option<Source>,
    ) -> io::Result<Answer> {
        self.finish_at(query, pending, answer, cacheable, source, Instant::now())
    }
    fn finish_at(
        &self,
        query: &[u8],
        pending: PendingQuery,
        answer: Vec<u8>,
        cacheable: bool,
        source: Option<Source>,
        now: Instant,
    ) -> io::Result<Answer> {
        wire::validate_response(&answer, query, &pending.question)?;
        if let Some(key) = pending
            .key
            .filter(|_| cacheable && self.capacity > 0 && self.max_ttl > 0)
        {
            let QueryKey {
                identity: key,
                generation,
            } = key;
            if let Some(life) = wire::lifetime(&answer, self.max_ttl)? {
                let mut cache = self.cache.lock().unwrap();
                if cache.generation == generation {
                    cache.expire(now);
                    cache.remove(&key);
                    // Large TXT, DNSSEC or EDNS records must not turn a nominal
                    // entry count into tens of MiB on common 64 MiB routers.
                    let weight = key.0.capacity()
                        + key.1.capacity()
                        + answer.len()
                        + life.ttls.capacity() * std::mem::size_of::<(usize, u32)>()
                        + source
                            .as_ref()
                            .map_or(0, |s| s.route.capacity() + s.upstream.capacity())
                        + std::mem::size_of::<Entry>();
                    let limit = self
                        .capacity
                        .saturating_mul(1024)
                        .clamp(16 * 1024, 2 * 1024 * 1024);
                    if weight > limit {
                        return Ok(Answer {
                            wire: answer,
                            cached: false,
                            source,
                            ttl_anchor: now,
                        });
                    }
                    while !cache.entries.is_empty()
                        && (cache.entries.len() >= self.capacity || cache.bytes + weight > limit)
                    {
                        if let Some(oldest) = cache
                            .entries
                            .iter()
                            .min_by_key(|(_, e)| e.expires)
                            .map(|(k, _)| k.clone())
                        {
                            cache.remove(&oldest);
                        }
                    }
                    cache.bytes += weight;
                    cache.entries.insert(
                        key,
                        Entry {
                            weight,
                            created: now,
                            expires: now + Duration::from_secs(life.seconds.into()),
                            wire: answer.clone(),
                            ttls: life.ttls,
                            source: source.clone(),
                        },
                    );
                }
            }
        }
        Ok(Answer {
            wire: answer,
            cached: false,
            source,
            ttl_anchor: now,
        })
    }
    /// Resolve one IPv4 address with a random DNS transaction ID.
    pub fn lookup_v4(&self, host: &str, upstream: SocketAddr) -> io::Result<std::net::Ipv4Addr> {
        first_ipv4(
            &self
                .exchange(&build_query(host, 1, transaction_id()?)?, upstream)?
                .wire,
        )
    }
}

pub fn transaction_id() -> io::Result<u16> {
    let mut id = [0; 2];
    getrandom::getrandom(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(u16::from_be_bytes(id))
}

fn time_left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(left)
    }
}
/// Query one explicitly chosen DNS endpoint without a cache or a system lookup.
/// UDP and any TCP fallback share the caller's absolute deadline.
pub fn exchange_until(
    query: &[u8],
    upstream: SocketAddr,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let q = wire::query(query)?;
    time_left(deadline)?;
    let reply = upstream_query(query, upstream, deadline)?;
    wire::validate_response(&reply, query, &q)?;
    time_left(deadline)?;
    Ok(reply)
}
fn read_tcp(tcp: &mut TcpStream, mut out: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !out.is_empty() {
        tcp.set_read_timeout(Some(time_left(deadline)?))?;
        match tcp.read(out) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => out = &mut out[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn upstream_query(query: &[u8], upstream: SocketAddr, deadline: Instant) -> io::Result<Vec<u8>> {
    let udp = UdpSocket::bind(if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    udp.connect(upstream)?;
    udp.set_write_timeout(Some(time_left(deadline)?))?;
    udp.send(query)?;
    // Use TCP for large DNS replies. Most router queries only need one small
    // UDP buffer, even when many clients miss the cache together.
    let mut reply = vec![0; 4097];
    loop {
        udp.set_read_timeout(Some(time_left(deadline)?))?;
        let n = match udp.recv(&mut reply) {
            Ok(n) => n,
            #[cfg(windows)]
            Err(e) if e.raw_os_error() == Some(10040) => break, // WSAEMSGSIZE
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let response = &reply[..n];
        if n < 12 || response[..2] != query[..2] || response[2] & 0xf8 != 0x80 {
            continue;
        }
        if response[2] & 2 == 0 && n < reply.len() {
            reply.truncate(n);
            return Ok(reply);
        }
        break;
    }
    drop(udp);
    exchange_tcp_until(query, upstream, deadline)
}
/// Query an explicitly selected DNS-over-TCP listener and verify the reply
/// belongs to this transaction. Used for both truncated UDP and listener checks.
pub fn exchange_tcp_until(
    query: &[u8],
    upstream: SocketAddr,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let q = wire::query(query)?;
    let mut tcp = TcpStream::connect_timeout(&upstream, time_left(deadline)?)?;
    for mut part in [&(query.len() as u16).to_be_bytes()[..], query] {
        while !part.is_empty() {
            tcp.set_write_timeout(Some(time_left(deadline)?))?;
            match tcp.write(part) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => part = &part[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e),
            }
        }
    }
    let mut length = [0; 2];
    read_tcp(&mut tcp, &mut length, deadline)?;
    let mut reply = vec![0; usize::from(u16::from_be_bytes(length))];
    if reply.len() < 12 {
        return Err(wire::bad("dns: short TCP response"));
    }
    read_tcp(&mut tcp, &mut reply, deadline)?;
    if reply[2] & 2 != 0 {
        return Err(wire::bad("dns: truncated TCP response"));
    }
    wire::validate_response(&reply, query, &q)?;
    Ok(reply)
}

#[cfg(test)]
mod tests;
