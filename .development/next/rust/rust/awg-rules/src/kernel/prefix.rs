use super::{err, io};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Family {
    V4,
    V6,
}
impl Family {
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
    pub fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }
    pub fn firewall(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }
    pub fn inet(self) -> &'static str {
        match self {
            Self::V4 => "inet",
            Self::V6 => "inet6",
        }
    }
    pub(super) fn width(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
    pub fn any(self) -> Prefix {
        Prefix {
            network: match self {
                Self::V4 => Ipv4Addr::UNSPECIFIED.into(),
                Self::V6 => Ipv6Addr::UNSPECIFIED.into(),
            },
            bits: 0,
        }
    }
}

/// Keep the address in its native family. Formatting stays compatible with
/// IPv4 journals, and IPv4 prefix operations use 32-bit arithmetic on MIPS.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Prefix {
    network: IpAddr,
    bits: u8,
}
impl Prefix {
    pub(super) fn interval(self) -> (u128, u128) {
        let start = match self.network {
            IpAddr::V4(ip) => u32::from(ip) as u128,
            IpAddr::V6(ip) => u128::from(ip),
        };
        let bits = self.family().width() - self.bits;
        (
            start,
            start
                | 1u128
                    .checked_shl(u32::from(bits))
                    .map_or(u128::MAX, |n| n - 1),
        )
    }
    pub(super) fn append_interval(f: Family, mut start: u128, end: u128, out: &mut Vec<Self>) {
        loop {
            let align = start.trailing_zeros().min(u32::from(f.width()));
            let size = (end - start).checked_add(1).map_or(128, |n| n.ilog2());
            let power = align.min(size);
            let ip = if f == Family::V4 {
                IpAddr::V4(Ipv4Addr::from(start as u32))
            } else {
                IpAddr::V6(Ipv6Addr::from(start))
            };
            out.push(Self {
                network: ip,
                bits: f.width() - power as u8,
            });
            let Some(next) = 1u128.checked_shl(power).and_then(|n| start.checked_add(n)) else {
                break;
            };
            if next > end {
                break;
            }
            start = next;
        }
    }
    pub(super) fn bucket(self) -> u8 {
        let bits = match self.network {
            IpAddr::V4(n) => u128::from(u32::from(n)),
            IpAddr::V6(n) => u128::from(n),
        };
        bits.to_le_bytes()
            .iter()
            .fold(self.bits, |sum, b| sum.wrapping_add(*b))
            & 15
    }
    /// Collapse adjacent sibling networks and redundant children without ever
    /// including an address outside the same rule's input.
    pub(super) fn compact(
        nets: std::collections::BTreeSet<Self>,
    ) -> std::collections::BTreeSet<Self> {
        let mut out = Vec::<Self>::new();
        for mut net in nets {
            if out.last().is_some_and(|p| p.covers(net)) {
                continue;
            }
            while net.bits != 0 {
                let parent = Self::masked(net.network, net.bits - 1);
                if !out
                    .last()
                    .is_some_and(|p| p.bits == net.bits && parent.covers(*p))
                {
                    break;
                }
                out.pop();
                net = parent;
            }
            out.push(net);
        }
        out.into_iter().collect()
    }
    pub(super) fn ancestors(self) -> impl Iterator<Item = Self> {
        (0..=self.bits).map(move |bits| Self::masked(self.network, bits))
    }
    pub(super) fn is_host(self) -> bool {
        self.bits == self.family().width()
    }
    pub fn host(addr: impl Into<IpAddr>) -> Self {
        let network = addr.into();
        Self {
            network,
            bits: Family::of(network).width(),
        }
    }
    fn masked(network: IpAddr, bits: u8) -> Self {
        let network = match network {
            IpAddr::V4(ip) => IpAddr::V4(
                (u32::from(ip) & u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0)).into(),
            ),
            IpAddr::V6(ip) => IpAddr::V6(
                (u128::from(ip) & u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0)).into(),
            ),
        };
        Self { network, bits }
    }
    pub fn family(self) -> Family {
        Family::of(self.network)
    }
    pub fn any(self) -> bool {
        self.bits == 0
    }
    pub fn overlaps(self, b: Self) -> bool {
        self.family() == b.family()
            && if self.bits <= b.bits {
                Self::masked(b.network, self.bits) == self
            } else {
                Self::masked(self.network, b.bits) == b
            }
    }
    pub fn covers(self, b: Self) -> bool {
        self.bits <= b.bits && self.overlaps(b)
    }
    pub fn contains(self, ip: IpAddr) -> bool {
        self.family() == Family::of(ip) && Self::masked(ip, self.bits) == self
    }
    pub fn max_by_length(self, other: Self) -> Self {
        if self.bits >= other.bits {
            self
        } else {
            other
        }
    }
    fn offset(self, n: u8) -> Option<IpAddr> {
        Some(match self.network {
            IpAddr::V4(ip) => IpAddr::V4(u32::from(ip).checked_add(u32::from(n))?.into()),
            IpAddr::V6(ip) => IpAddr::V6(u128::from(ip).checked_add(u128::from(n))?.into()),
        })
    }
    pub fn sample(self) -> IpAddr {
        self.offset(u8::from(self.bits < self.family().width()))
            .unwrap_or(self.network)
    }
    pub fn forwarded_sample(self, network: Self, router: IpAddr) -> Option<IpAddr> {
        if !self.overlaps(network) {
            return None;
        }
        let range = self.max_by_length(network);
        let broadcast = match network.network {
            IpAddr::V4(ip) if network.bits < 31 => Some(IpAddr::V4(
                (u32::from(ip) | (u32::MAX >> network.bits)).into(),
            )),
            _ => None,
        };
        (0..=2).filter_map(|n| range.offset(n)).find(|ip| {
            range.contains(*ip)
                && *ip != router
                && Some(*ip) != broadcast
                && (broadcast.is_none() || *ip != network.network)
        })
    }
    pub fn safe(self) -> bool {
        // ULA ranges are valid VPN destinations. Locally assigned networks
        // and the transport endpoints get checked against the live router.
        const V4: [(Ipv4Addr, u8); 5] = [
            (Ipv4Addr::UNSPECIFIED, 8),
            (Ipv4Addr::new(127, 0, 0, 0), 8),
            (Ipv4Addr::new(169, 254, 0, 0), 16),
            (Ipv4Addr::new(224, 0, 0, 0), 4),
            (Ipv4Addr::new(240, 0, 0, 0), 4),
        ];
        const V6: [(Ipv6Addr, u8); 4] = [
            (Ipv6Addr::UNSPECIFIED, 96),
            (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
            (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
        ];
        let overlaps = |network, bits| self.overlaps(Self { network, bits });
        match self.network {
            IpAddr::V4(_) => !V4.iter().any(|&(ip, bits)| overlaps(ip.into(), bits)),
            IpAddr::V6(_) => !V6.iter().any(|&(ip, bits)| overlaps(ip.into(), bits)),
        }
    }
    /// Visit the siblings outside an intersecting, more specific prefix.
    pub fn outside(mut self, inner: Self, mut emit: impl FnMut(Self)) {
        while self.bits < inner.bits {
            self.bits += 1;
            self = Self::masked(inner.network, self.bits);
            let sibling = match self.network {
                IpAddr::V4(ip) => IpAddr::V4((u32::from(ip) ^ (1 << (32 - self.bits))).into()),
                IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) ^ (1 << (128 - self.bits))).into()),
            };
            emit(Self {
                network: sibling,
                ..self
            });
        }
    }
}
impl FromStr for Prefix {
    type Err = io::Error;
    fn from_str(s: &str) -> io::Result<Self> {
        let (host, bits) = s.split_once('/').map_or((s, None), |(a, b)| (a, Some(b)));
        let addr: IpAddr = host
            .parse()
            .map_err(|_| err("ожидается адрес IP или CIDR"))?;
        let width = Family::of(addr).width();
        let bits = match bits {
            Some(n) => n
                .parse::<u8>()
                .ok()
                .filter(|n| *n <= width)
                .ok_or_else(|| err("неверная длина префикса IP"))?,
            None => width,
        };
        Ok(Self::masked(addr, bits))
    }
}
impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.bits)
    }
}
impl Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
