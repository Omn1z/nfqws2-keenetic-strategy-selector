use std::{fs, io, net::IpAddr, path::Path, process::Command};
pub fn validate(ip: IpAddr) -> io::Result<()> {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip,IpAddr::V4(v) if v.is_broadcast())
    {
        return Err(io::Error::other(
            "требуется адрес выбранного LAN-устройства",
        ));
    }
    Ok(())
}
fn bridge(iface: &str, sys: &Path, wan: &[String]) -> bool {
    !iface.is_empty()
        && iface.len() < 16
        && iface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && !wan.iter().any(|w| w == iface)
        && sys.join(iface).join("bridge").is_dir()
}
#[derive(Debug, PartialEq)]
pub struct Device {
    pub iface: String,
    pub mac: String,
}
fn peer(iface: &str, mac: &str, sys: &Path, wan: &[String]) -> Option<Device> {
    let octets: Vec<_> = mac
        .split(':')
        .map(|s| {
            if s.len() == 2 {
                u8::from_str_radix(s, 16).ok()
            } else {
                None
            }
        })
        .collect::<Option<_>>()?;
    (octets.len() == 6
        && octets[0] & 1 == 0
        && octets.iter().any(|v| *v != 0)
        && bridge(iface, sys, wan))
    .then(|| Device {
        iface: iface.into(),
        mac: mac.into(),
    })
}
pub fn from_arp(ip: IpAddr, text: &str, sys: &Path, wan: &[String]) -> Option<Device> {
    text.lines()
        .filter_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            if words.len() != 6
                || words[0].parse() != Ok(ip)
                || !u32::from_str_radix(words[2].trim_start_matches("0x"), 16)
                    .is_ok_and(|v| v & 2 != 0)
            {
                return None;
            }
            peer(words[5], words[3], sys, wan)
        })
        .next()
}
pub fn from_neighbor(ip: IpAddr, text: &str, sys: &Path, wan: &[String]) -> Option<Device> {
    text.lines()
        .filter_map(|line| {
            let w: Vec<_> = line.split_whitespace().collect();
            if w.first()?.parse() != Ok(ip)
                || !w.contains(&"lladdr")
                || w.iter().any(|v| matches!(*v, "FAILED" | "INCOMPLETE"))
            {
                return None;
            }
            let iface = *w.get(w.iter().position(|v| *v == "dev")? + 1)?;
            peer(
                iface,
                w.get(w.iter().position(|v| *v == "lladdr")? + 1)?,
                sys,
                wan,
            )
        })
        .next()
}
pub fn interface(ip: IpAddr, wan: &[String]) -> io::Result<Device> {
    validate(ip)?;
    let sys = Path::new("/sys/class/net");
    if let Some(iface) = from_arp(
        ip,
        &fs::read_to_string("/proc/net/arp").unwrap_or_default(),
        sys,
        wan,
    ) {
        return Ok(iface);
    }
    // Read the kernel neighbor cache. This never solicits a device or sends packets.
    let out = Command::new("ip")
        .args(["neigh", "show", "to", &ip.to_string()])
        .output()?;
    if out.status.success() {
        if let Some(iface) = from_neighbor(ip, &String::from_utf8_lossy(&out.stdout), sys, wan) {
            return Ok(iface);
        }
    }
    Err(io::Error::other(
        "устройство отсутствует в таблице соседей LAN-моста",
    ))
}
