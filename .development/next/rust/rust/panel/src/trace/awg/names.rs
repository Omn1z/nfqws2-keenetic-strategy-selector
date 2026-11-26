use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(30 * 60);
const CAP: usize = 4096;

#[derive(Default)]
pub(super) struct Names {
    by_ip: BTreeMap<IpAddr, (String, Instant)>,
    expiry: BTreeSet<(Instant, IpAddr)>,
}
impl Names {
    pub(super) fn remember(&mut self, ip: IpAddr, host: &str, now: Instant) {
        let host = host.trim().trim_end_matches('.');
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return;
        }
        while self.expiry.first().is_some_and(|(end, _)| *end <= now) {
            let (_, oldest) = self.expiry.pop_first().unwrap();
            self.by_ip.remove(&oldest);
        }
        let ip = ip.to_canonical();
        let end = now + TTL;
        if let Some((_, previous)) = self.by_ip.insert(ip, (host.to_ascii_lowercase(), end)) {
            self.expiry.remove(&(previous, ip));
        } else if self.by_ip.len() > CAP {
            let (_, oldest) = self.expiry.pop_first().unwrap();
            self.by_ip.remove(&oldest);
        }
        self.expiry.insert((end, ip));
    }

    pub(super) fn get(&self, ip: IpAddr, now: Instant) -> Option<&str> {
        self.by_ip
            .get(&ip.to_canonical())
            .filter(|(_, expires)| *expires > now)
            .map(|(name, _)| name.as_str())
    }
}
