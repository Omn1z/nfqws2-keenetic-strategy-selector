use std::{io, net::IpAddr};

pub(super) fn netifd_wan(snapshot: &str, device: &str, ip: IpAddr) -> io::Result<bool> {
    // Like network_find_wan[6], use only active default routes in the main
    // table. Match the kernel's selected L3 device across all WANs (PPPoE,
    // VLANs, cellular links), including distinct IPv4 and IPv6 uplinks.
    #[derive(serde::Deserialize)]
    struct Dump {
        interface: Vec<Interface>,
    }
    #[derive(serde::Deserialize)]
    struct Interface {
        #[serde(default)]
        up: bool,
        l3_device: Option<String>,
        #[serde(default)]
        route: Vec<Route>,
    }
    #[derive(serde::Deserialize)]
    struct Route {
        target: String,
        mask: u8,
        table: Option<serde_json::Value>,
    }
    let all: Dump = serde_json::from_str(snapshot).map_err(io::Error::other)?;
    let default = if ip.is_ipv4() { "0.0.0.0" } else { "::" };
    Ok(!device.is_empty()
        && device != "lo"
        && !device.starts_with("awg")
        && all.interface.iter().any(|i| {
            i.up && i.l3_device.as_deref() == Some(device)
                && i.route.iter().any(|r| {
                    r.mask == 0
                        && r.target == default
                        && r.table.as_ref().is_none_or(|t| {
                            t.as_u64() == Some(254) || matches!(t.as_str(), Some("main" | "254"))
                        })
                })
        }))
}

/// Identify a verified physical WAN device for a numeric route lookup.
pub fn physical_wan<'a>(
    route: &'a str,
    ip: IpAddr,
    configured: &[String],
    netifd: Option<&str>,
) -> Option<&'a str> {
    inspect_physical_wan(route, ip, configured, netifd)
        .ok()
        .flatten()
}

/// Distinguish an unusable observed route from a malformed observation.
pub fn inspect_physical_wan<'a>(
    route: &'a str,
    ip: IpAddr,
    configured: &[String],
    netifd: Option<&str>,
) -> io::Result<Option<&'a str>> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "неверные данные маршрута WAN");
    let mut fields = route
        .lines()
        .next()
        .ok_or_else(malformed)?
        .split_ascii_whitespace();
    if fields.next().and_then(|value| value.parse::<IpAddr>().ok()) != Some(ip) {
        return Err(malformed());
    }
    let dev = fields
        .skip_while(|s| *s != "dev")
        .nth(1)
        .filter(|dev| {
            !dev.starts_with('-')
                && dev.len() < 16
                && dev
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        })
        .ok_or_else(malformed)?;
    let confirmed = match netifd {
        Some(dump) => netifd_wan(dump, dev, ip).map_err(|_| malformed())?,
        None => configured.iter().any(|allowed| allowed == dev),
    };
    Ok((confirmed && dev != "lo" && !dev.starts_with("awg")).then_some(dev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguish_unusable_wan_from_unknown_observation() {
        let ip = "192.0.2.16".parse().unwrap();
        let wan = ["wan.1".to_string()];
        assert_eq!(
            inspect_physical_wan(
                "192.0.2.16 via 192.0.2.1 dev wan.1 src 192.0.2.2",
                ip,
                &wan,
                None
            )
            .unwrap(),
            Some("wan.1")
        );
        assert_eq!(
            inspect_physical_wan("192.0.2.16 dev br-lan src 192.0.2.2", ip, &wan, None).unwrap(),
            None
        );
        assert_eq!(
            inspect_physical_wan("192.0.2.16 dev awg12", ip, &["awg12".into()], None).unwrap(),
            None
        );
        for route in [
            "",
            "192.0.2.17 dev wan.1",
            "192.0.2.16",
            "192.0.2.16 dev -bad",
        ] {
            assert_eq!(
                inspect_physical_wan(route, ip, &wan, None)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let valid_netifd = r#"{"interface":[{"up":true,"l3_device":"pppoe-wan","route":[{"target":"0.0.0.0","mask":0}]}]}"#;
        let route = "192.0.2.16 dev pppoe-wan";
        assert_eq!(
            inspect_physical_wan(route, ip, &[], Some(valid_netifd)).unwrap(),
            Some("pppoe-wan")
        );
        assert_eq!(
            inspect_physical_wan(route, ip, &[], Some("{}"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(physical_wan(route, ip, &[], Some("{}")), None);
    }
}
