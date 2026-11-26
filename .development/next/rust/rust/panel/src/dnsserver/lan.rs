use super::config::{invalid, local};
use std::{io, net::IpAddr};

#[derive(Clone, Copy)]
pub(super) struct PeerScope {
    host: IpAddr,
    mask: Option<IpAddr>,
}

impl PeerScope {
    pub(super) fn for_host(host: IpAddr) -> Self {
        let host = host.to_canonical();
        let mask = if host.is_loopback() {
            None
        } else {
            interface_addresses().ok().and_then(|addresses| {
                addresses
                    .into_iter()
                    .rev()
                    .find(|addr| addr.ip == host)
                    .and_then(|addr| addr.mask)
            })
        };
        Self::with_mask(host, mask)
    }

    fn with_mask(host: IpAddr, mask: Option<IpAddr>) -> Self {
        let mask = mask.filter(|mask| match (host, mask) {
            (IpAddr::V4(_), IpAddr::V4(mask)) => {
                let mask = u32::from(*mask);
                mask != 0 && mask.leading_ones() == mask.count_ones()
            }
            (IpAddr::V6(_), IpAddr::V6(mask)) => {
                let mask = u128::from(*mask);
                mask != 0 && mask.leading_ones() == mask.count_ones()
            }
            _ => false,
        });
        Self { host, mask }
    }

    #[cfg(test)]
    pub(super) fn test_subnet(host: IpAddr, mask: IpAddr) -> Self {
        Self::with_mask(host, Some(mask))
    }

    pub(super) fn local_origin(self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        peer.is_loopback() || peer == self.host
    }

    pub(super) fn allows(self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        if self.local_origin(peer) {
            return true;
        }
        if !local(peer) {
            return false;
        }
        match (self.host, peer, self.mask) {
            (IpAddr::V4(host), IpAddr::V4(peer), Some(IpAddr::V4(mask))) => {
                (u32::from(host) ^ u32::from(peer)) & u32::from(mask) == 0
            }
            (IpAddr::V6(host), IpAddr::V6(peer), Some(IpAddr::V6(mask))) => {
                (u128::from(host) ^ u128::from(peer)) & u128::from(mask) == 0
            }
            _ => false,
        }
    }
}

pub(super) fn host(value: &str, wan: &[String]) -> io::Result<IpAddr> {
    let requested = value.parse::<IpAddr>().ok();
    if let Some(ip) = requested.filter(IpAddr::is_loopback) {
        return Ok(ip);
    }
    let mut hosts = addresses()?;
    hosts.retain(|(name, addr)| {
        local(*addr)
            && !addr.is_loopback()
            && !wan.contains(name)
            && ![
                "awg", "nwg", "wg", "tun", "tap", "ppp", "ipsec", "docker", "veth",
            ]
            .iter()
            .any(|p| name.starts_with(p))
    });
    hosts.sort_by_key(|(name, _)| {
        if name == "br0" {
            0
        } else if name.starts_with("br") {
            1
        } else {
            2
        }
    });
    hosts
        .into_iter()
        .map(|(_, ip)| ip)
        .find(|ip| requested.map_or(ip.is_ipv4(), |req| *ip == req))
        .ok_or_else(|| invalid("не найден локальный адрес LAN; задайте адрес интерфейса вручную"))
}

struct InterfaceAddress {
    name: String,
    ip: IpAddr,
    mask: Option<IpAddr>,
}

pub(crate) fn addresses() -> io::Result<Vec<(String, IpAddr)>> {
    Ok(interface_addresses()?
        .into_iter()
        .map(|addr| (addr.name, addr.ip))
        .collect())
}

#[cfg(not(target_os = "linux"))]
fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    Ok(Vec::new())
}
#[cfg(target_os = "linux")]
fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    use std::{
        ffi::CStr,
        net::{Ipv4Addr, Ipv6Addr},
        ptr,
    };
    let mut first = ptr::null_mut();
    // getifaddrs owns this list until freeifaddrs; each address family selects its sockaddr layout.
    unsafe {
        if libc::getifaddrs(&mut first) != 0 {
            return Err(io::Error::last_os_error());
        }
        let read_ip = |addr: *const libc::sockaddr| match addr.as_ref()?.sa_family as i32 {
            libc::AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                (*addr.cast::<libc::sockaddr_in>())
                    .sin_addr
                    .s_addr
                    .to_ne_bytes(),
            ))),
            libc::AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
                (*addr.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr,
            ))),
            _ => None,
        };
        let mut result = Vec::new();
        let mut item = first;
        while let Some(interface) = item.as_ref() {
            if interface.ifa_flags & libc::IFF_UP as libc::c_uint != 0
                && !interface.ifa_name.is_null()
            {
                if let Some(ip) = read_ip(interface.ifa_addr) {
                    result.push(InterfaceAddress {
                        name: CStr::from_ptr(interface.ifa_name)
                            .to_string_lossy()
                            .into_owned(),
                        ip,
                        mask: read_ip(interface.ifa_netmask),
                    });
                }
            }
            item = interface.ifa_next;
        }
        libc::freeifaddrs(first);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(host: &str, mask: &str) -> PeerScope {
        PeerScope::with_mask(host.parse().unwrap(), mask.parse().ok())
    }

    #[test]
    fn only_loopback_the_host_and_the_bound_lan_subnet_can_query_directly() {
        for (scope, accepted, rejected) in [
            (
                scope("192.168.1.129", "255.255.255.128"),
                ["192.168.1.130", "::ffff:192.168.1.254", "127.0.0.2"],
                ["192.168.1.5", "192.168.2.130", "10.13.13.2"],
            ),
            (
                scope("fd00:1234:5555:1::1", "ffff:ffff:ffff:ffff::"),
                ["fd00:1234:5555:1::2", "fd00:1234:5555:1:ffff::2", "::1"],
                ["fd00:1234:5555:2::2", "fd00:1234:1234:1::2", "10.13.13.2"],
            ),
        ] {
            for client in accepted {
                assert!(scope.allows(client.parse().unwrap()), "{client}");
            }
            for client in rejected {
                assert!(!scope.allows(client.parse().unwrap()), "{client}");
            }
            assert!(scope.local_origin(scope.host));
            assert!(!scope.local_origin(accepted[0].parse().unwrap()));
        }
    }

    #[test]
    fn missing_wildcard_or_invalid_masks_do_not_admit_other_networks() {
        for mask in ["", "0.0.0.0", "255.0.255.0", "ffff::"] {
            let scope = scope("192.168.1.129", mask);
            assert!(scope.allows("192.168.1.129".parse().unwrap()));
            assert!(scope.allows("::ffff:127.0.0.1".parse().unwrap()));
            assert!(!scope.allows("192.168.1.130".parse().unwrap()), "{mask}");
        }
        let loopback = PeerScope::for_host("127.0.0.1".parse().unwrap());
        assert!(loopback.allows("::ffff:127.20.0.10".parse().unwrap()));
        assert!(!loopback.allows("192.168.1.129".parse().unwrap()));
    }
}
