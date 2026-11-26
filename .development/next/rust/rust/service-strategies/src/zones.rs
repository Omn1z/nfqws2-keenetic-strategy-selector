use crate::bad;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub use nfqws2_config::service_profiles::domain;
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
struct Network {
    v6: bool,
    first: u128,
    bits: u8,
}
impl Network {
    fn parse(text: &str) -> io::Result<Self> {
        let (addr, bits) = text
            .split_once('/')
            .map_or((text, None), |(a, b)| (a, Some(b)));
        let ip: IpAddr = addr.parse().map_err(|_| bad("некорректный IP-адрес"))?;
        let width = if ip.is_ipv4() { 32 } else { 128 };
        let mut bits = match bits {
            Some(b)
                if b.bytes().all(|c| c.is_ascii_digit())
                    && (b.len() == 1 || !b.starts_with('0')) =>
            {
                b.parse::<u8>()
                    .ok()
                    .filter(|n| *n <= width)
                    .ok_or_else(|| bad("некорректная маска подсети"))?
            }
            Some(_) => return Err(bad("некорректная маска подсети")),
            None => width,
        };
        let ip = if ip.is_ipv6() && bits >= 96 && ip.to_canonical().is_ipv4() {
            bits -= 96;
            ip.to_canonical()
        } else {
            ip
        };
        let (v6, num, width) = match ip {
            IpAddr::V4(a) => (false, u128::from(u32::from(a)), 32),
            IpAddr::V6(a) => (true, u128::from(a), 128),
        };
        let mask = u128::MAX.checked_shl(u32::from(width - bits)).unwrap_or(0);
        Ok(Self {
            v6,
            first: num & mask,
            bits,
        })
    }
    fn last(self) -> u128 {
        let width = if self.v6 { 128 } else { 32 };
        self.first
            | (1u128
                .checked_shl(u32::from(width - self.bits))
                .unwrap_or(0)
                .wrapping_sub(1))
    }
    fn text(self) -> String {
        let (addr, width) = if self.v6 {
            (Ipv6Addr::from(self.first).to_string(), 128)
        } else {
            (Ipv4Addr::from(self.first as u32).to_string(), 32)
        };
        if self.bits == width {
            addr
        } else {
            format!("{addr}/{}", self.bits)
        }
    }
}
pub fn ip(text: &str) -> io::Result<String> {
    Network::parse(text).map(Network::text)
}
#[derive(Default)]
pub struct Zones {
    domains: Vec<(String, usize)>,
    ips: Vec<(Network, usize)>,
}
impl Zones {
    pub fn record(&mut self, is_domain: bool, entry: &str, group: usize) -> io::Result<()> {
        if is_domain {
            let mut key = String::with_capacity(entry.len() + 1);
            for label in entry.rsplit('.') {
                key.push_str(label);
                key.push('.');
            }
            self.domains.push((key, group));
        } else {
            self.ips.push((Network::parse(entry)?, group));
        }
        Ok(())
    }
    pub fn check(mut self) -> io::Result<()> {
        self.domains.sort_unstable();
        self.ips.sort_unstable();
        fn overlap<T>(items: &[(T, usize)], contains: impl Fn(&T, &T) -> bool) -> io::Result<()> {
            let mut stack: Vec<&(T, usize)> = Vec::new();
            for item in items {
                while stack.last().is_some_and(|s| !contains(&s.0, &item.0)) {
                    stack.pop();
                }
                if stack.last().is_some_and(|s| s.1 != item.1) {
                    return Err(bad("конфликт зон между группами сервисов"));
                }
                stack.push(item);
            }
            Ok(())
        }
        overlap(&self.domains, |parent, child| child.starts_with(parent))?;
        overlap(&self.ips, |parent, child| {
            parent.v6 == child.v6 && child.first <= parent.last()
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_networks_and_overlapping_domains() {
        assert_eq!(ip("::ffff:192.0.2.129/120").unwrap(), "192.0.2.0/24");
        assert_eq!(ip("2001:db8::5/0").unwrap(), "::/0");
        assert_eq!(domain("*.ПРИМЕР.РФ.").unwrap(), "xn--e1afmkfd.xn--p1ai");
        for (kind, a, b) in [
            (true, "example.test", "a.example.test"),
            (false, "::/0", "2001:db8::1"),
            (false, "10.0.0.2/24", "10.0.0.2"),
        ] {
            let mut zones = Zones::default();
            zones.record(kind, a, 1).unwrap();
            zones.record(kind, b, 2).unwrap();
            assert!(zones.check().is_err());
        }
        assert!(ip("127.0.0.1/33").is_err());
        assert!(domain("127.0.0.1").is_err());
    }
}
