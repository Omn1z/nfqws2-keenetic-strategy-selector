use super::invalid;
use nfqws2_router_command::Runner;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs, io,
    net::Ipv6Addr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Serialize)]
pub(super) struct Interface {
    pub name: String,
    pub mac: String,
    pub up: bool,
    pub suggested: bool,
    #[serde(skip)]
    pub index: u32,
}
pub(super) fn normalized(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (width, separator) = if raw.contains('.') {
        (4, '.')
    } else if raw.contains('-') {
        (2, '-')
    } else {
        (2, ':')
    };
    let groups: Vec<_> = raw.split(separator).collect();
    if groups.len() * width != 12
        || !groups
            .iter()
            .all(|g| g.len() == width && g.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    let hex = groups.concat();
    let mut bytes = [0u8; 6];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    (bytes[0] & 1 == 0 && bytes.iter().any(|&n| n != 0)).then(|| super::format_mac(&bytes))
}
pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && name != "."
        && name != ".."
}
fn default_wan(proc: &Path) -> io::Result<BTreeSet<String>> {
    let mut wan = BTreeSet::new();
    for (name, v6) in [("route", false), ("ipv6_route", true)] {
        let routes = match fs::read_to_string(proc.join(name)) {
            Ok(s) => s,
            Err(e) if v6 && e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for line in routes.lines() {
            let mut it = line.split_ascii_whitespace();
            if v6 {
                if it.next() == Some("00000000000000000000000000000000") && it.next() == Some("00")
                {
                    if let Some(i) = it.last() {
                        wan.insert(i.to_owned());
                    }
                }
            } else if let Some(i) = it.next() {
                if it.next() == Some("00000000") {
                    wan.insert(i.to_owned());
                }
            }
        }
    }
    Ok(wan)
}
pub(super) struct Device<R> {
    root: PathBuf,
    runner: R,
}
impl<R: Runner> Device<R> {
    pub fn new(root: &Path, runner: R) -> Self {
        Self {
            root: root.to_owned(),
            runner,
        }
    }
    fn tool(&self, names: &[&str]) -> Option<PathBuf> {
        for name in names {
            for dir in ["opt/sbin", "opt/bin", "sbin", "usr/sbin", "bin", "usr/bin"] {
                let path = self.root.join(dir).join(name);
                if path.metadata().is_ok_and(|m| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        m.is_file() && m.permissions().mode() & 0o111 != 0
                    }
                    #[cfg(not(unix))]
                    {
                        m.is_file()
                    }
                }) {
                    return Some(path);
                }
            }
        }
        None
    }
    pub fn tools(&self) -> Value {
        json!({"ip":self.tool(&["ip"]).is_some(),"arptables":self.tool(&["arptables","arptables-legacy"]).is_some(),"ebtables":self.tool(&["ebtables","ebtables-legacy"]).is_some()})
    }
    fn run(&self, tool: &Path, args: &[&str]) -> io::Result<String> {
        self.runner
            .run(
                tool.to_str()
                    .ok_or_else(|| invalid("Неверный путь к программе"))?,
                args,
                Instant::now() + Duration::from_secs(3),
            )
            .map_err(|_| io::Error::other("Служебная команда сети завершилась ошибкой"))
    }
    pub fn interfaces(&self, configured: &[String]) -> io::Result<Vec<Interface>> {
        let path = self.root.join("sys/class/net");
        let list = match fs::read_dir(&path) {
            Ok(list) => list,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let routes = default_wan(&self.root.join("proc/net"));
        let identified = routes.is_ok();
        let mut wan = routes.unwrap_or_default();
        wan.extend(configured.iter().cloned());
        for name in wan.clone() {
            if valid_name(&name) {
                if let Ok(master) = fs::read_link(path.join(name).join("master")) {
                    if let Some(m) = master.file_name().and_then(|v| v.to_str()) {
                        wan.insert(m.to_owned());
                    }
                }
            }
        }
        let mut out = Vec::new();
        for item in list {
            let item = item?;
            let Ok(name) = item.file_name().into_string() else {
                continue;
            };
            if !valid_name(&name) || name == "lo" {
                continue;
            }
            let base = item.path();
            let Some(mac) = fs::read_to_string(base.join("address"))
                .ok()
                .and_then(|s| normalized(&s))
            else {
                continue;
            };
            let flags = fs::read_to_string(base.join("flags"))
                .ok()
                .and_then(|v| u32::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok())
                .unwrap_or_default();
            let index = fs::read_to_string(base.join("ifindex"))
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_default();
            let up = flags & 1 != 0;
            let lan_name = (name.starts_with("br") || name.starts_with("lan"))
                && !name.to_ascii_lowercase().contains("wan");
            let suggested = identified
                && up
                && index > 0
                && lan_name
                && !wan.contains(&name)
                && !wan
                    .iter()
                    .filter(|n| valid_name(n))
                    .any(|n| base.join("brif").join(n).exists())
                && !base.join("master").exists()
                && base.join("bridge").is_dir();
            out.push(Interface {
                name,
                mac,
                up,
                suggested,
                index,
            });
        }
        out.sort_by(|a, b| {
            b.suggested
                .cmp(&a.suggested)
                .then(b.up.cmp(&a.up))
                .then(a.name.cmp(&b.name))
        });
        Ok(out)
    }
    pub fn same_ipv6_lan(
        &self,
        wan: &[String],
        local: Ipv6Addr,
        peer: Ipv6Addr,
    ) -> io::Result<bool> {
        const DAD_FAILED_OR_TENTATIVE: u32 = 0x08 | 0x40;
        let addrs = fs::read_to_string(self.root.join("proc/net/if_inet6"))?;
        let local = u128::from(local);
        let peer = u128::from(peer);
        let mut matches = addrs.lines().filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let addr = u128::from_str_radix(fields.next()?, 16).ok()?;
            let index = u32::from_str_radix(fields.next()?, 16).ok()?;
            let length = u32::from_str_radix(fields.next()?, 16).ok()?;
            let scope = fields.next()?;
            let flags = u32::from_str_radix(fields.next()?, 16).ok()?;
            let name = fields.next()?;
            if local != addr
                || !(1..=128).contains(&length)
                || scope != "00"
                || flags & DAD_FAILED_OR_TENTATIVE != 0
            {
                return None;
            }
            Some((name, index, (local ^ peer) >> (128 - length) == 0))
        });
        let Some((name, index, true)) = matches.next().filter(|_| matches.next().is_none()) else {
            return Ok(false);
        };
        Ok(self
            .interfaces(wan)?
            .iter()
            .any(|i| i.name == name && i.index == index && i.suggested))
    }
    fn ndm_id(&self, name: &str) -> io::Result<String> {
        let digits = name
            .strip_prefix("br")
            .ok_or_else(|| invalid("Нужен LAN-мост Keenetic brN"))?;
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return Err(invalid("Неверное имя LAN-моста Keenetic"));
        }
        Ok(format!("Bridge{digits}"))
    }
    pub fn current(&self, iface: &Interface) -> io::Result<String> {
        let (kernel, native) = self.observed(iface)?;
        if native.is_some_and(|v| v != kernel) {
            return Err(invalid("MAC в ядре и конфигурации Keenetic различаются"));
        }
        Ok(kernel)
    }
    pub fn selected<'a>(&self, all: &'a [Interface], name: &str) -> io::Result<&'a Interface> {
        if !valid_name(name) {
            return Err(invalid("Недопустимое имя LAN-моста"));
        }
        if let Some(bridge) = all.iter().find(|i| i.suggested && i.name == name) {
            return Ok(bridge);
        }
        // Linux creates brif entries for the bridge's own member ports. Resolve
        // a selection made by an older UI to its eligible master, without ever
        // changing the hardware address of an individual port.
        let net = self.root.join("sys/class/net");
        let mut masters = all
            .iter()
            .filter(|i| i.suggested && net.join(&i.name).join("brif").join(name).exists());
        let master = masters.next().filter(|_| masters.next().is_none());
        master.ok_or_else(|| invalid("Цель должна быть активным LAN-мостом"))
    }
    pub fn observed(&self, iface: &Interface) -> io::Result<(String, Option<String>)> {
        let base = self.root.join("sys/class/net").join(&iface.name);
        let index = fs::read_to_string(base.join("ifindex"))?;
        if index.trim().parse::<u32>().ok() != Some(iface.index)
            || !base.join("bridge").is_dir()
            || base.join("master").exists()
        {
            return Err(invalid("Идентификатор LAN-моста изменился"));
        }
        let kernel = fs::read_to_string(base.join("address"))?;
        let kernel = normalized(&kernel).ok_or_else(|| invalid("Некорректный MAC интерфейса"))?;
        if let Some(ndmc) = self.tool(&["ndmc"]) {
            let id = self.ndm_id(&iface.name)?;
            let raw = self.run(&ndmc, &["-c", &format!("show interface {id}")])?;
            let col = raw
                .lines()
                .filter_map(|l| {
                    let (k, _) = l.split_once(':')?;
                    (k.trim() == "id").then_some(k.len())
                })
                .min();
            let field = |key: &str| {
                let mut values = raw.lines().filter_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    (Some(k.len()) == col && k.trim() == key).then(|| v.trim())
                });
                let first = values.next()?;
                values.next().is_none().then_some(first)
            };
            if field("id") != Some(id.as_str())
                || field("type") != Some("Bridge")
                || !matches!(field("security-level"), Some("private" | "protected"))
                || field("global") == Some("yes")
            {
                return Err(invalid(
                    "Keenetic не подтвердил параметры частного LAN-моста",
                ));
            }
            let native = field("mac")
                .and_then(normalized)
                .ok_or_else(|| invalid("Keenetic не сообщил действующий MAC моста"))?;
            return Ok((kernel, Some(native)));
        }
        if self.root.join("etc/ndm").is_dir() {
            return Err(invalid("На Keenetic недоступен штатный ndmc"));
        }
        Ok((kernel, None))
    }
    fn ip(&self) -> io::Result<PathBuf> {
        self.tool(&["ip"])
            .ok_or_else(|| invalid("На роутере недоступна программа ip"))
    }
    pub fn unused(
        &self,
        mac: &str,
        target: &Interface,
        all: &[Interface],
        original: bool,
        group: &BTreeSet<&str>,
    ) -> io::Result<()> {
        let members = self
            .root
            .join("sys/class/net")
            .join(&target.name)
            .join("brif");
        if all.iter().any(|i| {
            i.name != target.name
                && i.mac == mac
                && !group.contains(i.name.as_str())
                && !(original && members.join(&i.name).exists())
        }) {
            return Err(invalid("MAC уже принадлежит другому интерфейсу"));
        }
        let ip = self.ip()?;
        for family in ["-4", "-6"] {
            let rows = self.run(&ip, &[family, "neigh", "show"])?;
            for line in rows.lines() {
                let mut fields = line.split_ascii_whitespace();
                while let Some(word) = fields.next() {
                    if word == "lladdr"
                        && fields.next().is_some_and(|v| v.eq_ignore_ascii_case(mac))
                    {
                        return Err(invalid("MAC уже принадлежит известному соседу"));
                    }
                }
            }
        }
        Ok(())
    }
    pub fn set(&self, target: &Interface, mac: &str) -> io::Result<()> {
        if let Some(ndmc) = self.tool(&["ndmc"]) {
            let id = self.ndm_id(&target.name)?;
            self.run(&ndmc, &["-c", &format!("interface {id} mac address {mac}")])?;
        } else if self.root.join("etc/ndm").is_dir() {
            return Err(invalid("На Keenetic недоступен штатный ndmc"));
        } else {
            self.run(
                &self.ip()?,
                &["link", "set", "dev", &target.name, "address", mac],
            )?;
        }
        if self.current(target)? != mac {
            return Err(invalid("Изменение MAC моста не подтверждено"));
        }
        if let Some(tool) = self.tool(&["arping"]) {
            // Neighbour-cache refresh is optional, like in the Go service. Failure to
            // announce an already verified address must not undo the assignment.
            if self.announce_own_ipv4(target, &tool).is_err() {
                eprintln!(
                    "bridge MAC: failed to announce the router's own address on {}",
                    target.name
                );
            }
        }
        Ok(())
    }
    fn announce_own_ipv4(&self, target: &Interface, tool: &Path) -> io::Result<()> {
        use std::net::Ipv4Addr;
        let rows = self.run(
            &self.ip()?,
            &["-o", "-4", "addr", "show", "dev", &target.name],
        )?;
        let mut addresses = BTreeSet::new();
        for row in rows.lines() {
            let mut fields = row.split_ascii_whitespace();
            let index = fields
                .next()
                .and_then(|s| s.strip_suffix(':'))
                .and_then(|s| s.parse::<u32>().ok());
            if index != Some(target.index)
                || fields.next() != Some(target.name.as_str())
                || fields.next() != Some("inet")
            {
                continue;
            }
            let Some((ip, prefix)) = fields.next().and_then(|s| s.split_once('/')) else {
                continue;
            };
            let Ok(address) = ip.parse::<Ipv4Addr>() else {
                continue;
            };
            if prefix.parse::<u8>().is_ok_and(|p| p <= 32)
                && !address.is_unspecified()
                && !address.is_broadcast()
                && !address.is_multicast()
                && !address.is_loopback()
            {
                addresses.insert(address);
            }
        }
        for address in addresses {
            let ip = address.to_string();
            self.run(
                tool,
                &["-q", "-U", "-c", "2", "-I", &target.name, "-s", &ip, &ip],
            )?;
        }
        Ok(())
    }
}
