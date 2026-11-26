//! Exact selectors for the encrypted UDP socket of a nested AWG client.
//! The receipt is written before the first mutation, under the interface lock.
use super::invalid;
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Routes {
    pub iface: String,
    pub outer: String,
    pub endpoint: IpAddr,
    pub source: IpAddr,
}

pub(super) fn covers(network: &str, ip: IpAddr) -> bool {
    let Some((base, bits)) = network.split_once('/') else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    match (base.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(base)), IpAddr::V4(ip)) if bits <= 32 => {
            u32::from(base).checked_shr(32 - bits) == u32::from(ip).checked_shr(32 - bits)
        }
        (Ok(IpAddr::V6(base)), IpAddr::V6(ip)) if bits <= 128 => {
            u128::from(base).checked_shr(128 - bits) == u128::from(ip).checked_shr(128 - bits)
        }
        _ => false,
    }
}

use super::nested_usable as usable;
pub(super) use super::{nested_mtu as mtu, NestedOuterPeer as OuterPeer};

pub(super) fn check_outer_peer(
    buf: &[u8],
    key: &str,
    endpoint: IpAddr,
    now: u64,
) -> io::Result<OuterPeer> {
    let mut status = serde_json::json!({});
    crate::runtime::uapi(buf, now, &mut status)?;
    let text = std::str::from_utf8(buf).map_err(|_| invalid("неверный ответ UAPI внешнего AWG"))?;
    let mut matched = false;
    let mut allowed = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("public_key=") {
            matched = value.eq_ignore_ascii_case(key);
        }
        if let Some(value) = line.strip_prefix("fwmark=") {
            if !matches!(number(value)?, 0 | crate::DIRECT_SOCKET_MARK) {
                return Err(invalid(
                    "внешний клиент AWG сам использует помеченный транспорт",
                ));
            }
        }
        if let Some(value) = line.strip_prefix("allowed_ip=") {
            allowed |= matched && covers(value, endpoint);
        }
    }
    if status["connected"] != true || !matched || !allowed {
        return Err(invalid(
            "внешний AWG не подтвердил рукопожатие, публичный ключ и AllowedIPs",
        ));
    }
    let endpoint = super::supervisor::live_transport_endpoint(&status);
    let socket_mark = status["socket_mark"].as_u64().unwrap_or(0) as u32;
    Ok(OuterPeer {
        endpoint,
        socket_mark,
    })
}

pub(super) fn verify_shared_outer_wan(
    endpoint: SocketAddr,
    outer: OuterPeer,
    verify: impl FnOnce(SocketAddr, u32) -> bool,
) -> io::Result<()> {
    let outer_endpoint = outer
        .endpoint
        .ok_or_else(|| invalid("внешний AWG не подтвердил действующий UDP-адрес"))?;
    if endpoint.ip().to_canonical() == outer_endpoint.ip().to_canonical()
        && !verify(outer_endpoint, outer.socket_mark)
    {
        return Err(invalid(
            "общий адрес вложенного и внешнего AWG не подтвердил прямой маршрут WAN",
        ));
    }
    Ok(())
}

pub(super) fn source(addrs: &str, endpoint: IpAddr) -> io::Result<IpAddr> {
    addrs
        .lines()
        .find_map(|l| {
            let words: Vec<_> = l.split_ascii_whitespace().collect();
            if words.contains(&"dadfailed") || words.contains(&"tentative") {
                return None;
            }
            let family = if endpoint.is_ipv4() { "inet" } else { "inet6" };
            let ip: IpAddr = after(&words, family)?.split('/').next()?.parse().ok()?;
            (ip.is_ipv4() == endpoint.is_ipv4() && usable(ip)).then_some(ip)
        })
        .ok_or_else(|| invalid("нет исходного адреса внешнего туннеля"))
}

fn after<'a>(words: &'a [&str], key: &str) -> Option<&'a str> {
    words.windows(2).find(|p| p[0] == key).map(|p| p[1])
}

fn number(s: &str) -> io::Result<u32> {
    s.strip_prefix("0x")
        .map_or_else(|| s.parse(), |n| u32::from_str_radix(n, 16))
        .map_err(|_| invalid("неверная метка правила"))
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
struct Objects {
    lookup: bool,
    guard: bool,
    blackhole: bool,
    peer: bool,
}
fn own(seen: &mut bool, owned: bool) -> io::Result<()> {
    if !owned || std::mem::replace(seen, true) {
        return Err(invalid("селектор вложенного туннеля уже занят"));
    }
    Ok(())
}
type Ip<'a> = dyn Fn(&[&str]) -> io::Result<String> + 'a;
#[cfg(test)]
pub(in crate::client) mod tests;
impl Routes {
    pub fn table(&self) -> io::Result<u32> {
        super::nested_socket_selector(&self.iface).map(|(_, table)| table)
    }
    pub fn validate(&self, iface: &str) -> io::Result<()> {
        if self.iface != iface {
            return Err(invalid("повреждена запись маршрутов вложенного AWG"));
        }
        super::validate_nested_scope(iface, &self.outer, self.endpoint, self.source)
    }
    pub fn mark(&self) -> io::Result<u32> {
        super::nested_socket_selector(&self.iface).map(|(mark, _)| mark)
    }
    pub fn verify_installed(&self, ip: &Ip<'_>) -> io::Result<()> {
        self.validate(&self.iface)?;
        for family in ["-4", "-6"] {
            let expected = Objects {
                lookup: true,
                guard: true,
                blackhole: true,
                peer: self.endpoint.is_ipv4() == (family == "-4"),
            };
            if self.inspect(family, true, ip)? != expected {
                return Err(invalid("ядро не подтвердило селекторы вложенного AWG"));
            }
        }
        Ok(())
    }

    pub fn verify_retirement(&self, owned: bool, ip: &Ip<'_>) -> io::Result<()> {
        self.validate(&self.iface)?;
        for family in ["-4", "-6"] {
            self.inspect(family, owned, ip)?;
        }
        Ok(())
    }
    fn inspect(&self, family: &str, owned: bool, ip: &Ip<'_>) -> io::Result<Objects> {
        let mut found = Objects::default();
        let mark = self.mark()?;
        let table = self.table()?.to_string();
        let conflict = || invalid("постороннее правило или маршрут в селекторе вложенного AWG");
        for l in ip(&["-o", family, "rule", "show"])?.lines() {
            let w: Vec<_> = l.split_ascii_whitespace().collect();
            let prio = w
                .first()
                .and_then(|s| s.trim_end_matches(':').parse::<u32>().ok())
                .ok_or_else(conflict)?;
            let target = after(&w, "lookup").or_else(|| after(&w, "table"));
            if let Some(raw) = after(&w, "fwmark") {
                let (value, mask) = raw.split_once('/').unwrap_or((raw, "0xffffffff"));
                let (value, mask) = (number(value)?, number(mask)?);
                let exact = mark == value
                    && mask == u32::MAX
                    && w.get(1..4) == Some(&["from", "all", "fwmark"]);
                if exact && prio == 60 && matches!(&w[5..], ["lookup" | "table", t] if *t == table)
                {
                    own(&mut found.lookup, owned)?;
                    continue;
                }
                if exact
                    && prio == 61
                    && matches!(
                        &w[5..],
                        ["prohibit" | "reject" | "8"]
                            | ["lookup", "main" | "254", "prohibit" | "reject" | "8"]
                    )
                {
                    own(&mut found.guard, owned)?;
                    continue;
                }
                if target == Some(table.as_str())
                    || mark == value
                    || (prio <= 61 && ((mark & mask == value & mask) != w.contains(&"not")))
                {
                    return Err(conflict());
                }
            } else if target == Some(table.as_str())
                || (prio <= 61
                    && !(prio == 0
                        && matches!(&w[1..], ["from", "all", "lookup", "local" | "255"])))
            {
                return Err(conflict());
            }
        }
        let v4 = family == "-4";
        for l in ip(&["-o", family, "route", "show", "table", "all"])?.lines() {
            let w: Vec<_> = l.split_ascii_whitespace().collect();
            if after(&w, "table") != Some(table.as_str()) {
                continue;
            }
            if after(&w, "proto") != Some("99") {
                return Err(conflict());
            }
            let hole = matches!(w.as_slice(), ["blackhole" | "6", "default", ..]);
            let attrs = if hole { &w[2..] } else { &w[1..] };
            let mut attrs = attrs.iter().copied().filter(|a| *a != "linkdown");
            while let Some(key) = attrs.next() {
                let val = attrs.next().ok_or_else(conflict)?;
                let valid = match key {
                    "table" => val == table,
                    "proto" => val == "99",
                    "dev" if hole => val == "lo",
                    "metric" if hole => val == "1000",
                    "error" if hole => !v4 && val == "-22",
                    "dev" => val == self.outer,
                    "src" if !hole => val.parse::<IpAddr>().ok() == Some(self.source),
                    "scope" if !hole => matches!(val, "link" | "253"),
                    "metric" if !hole => !v4 && val == "1024",
                    "pref" => !v4 && matches!(val, "medium" | "0"),
                    _ => false,
                };
                if !valid {
                    return Err(conflict());
                }
            }
            if hole && after(&w, "metric") == Some("1000") {
                own(&mut found.blackhole, owned)?;
            } else {
                let first = w[0];
                let bits = if v4 { "32" } else { "128" };
                let (addr, length) = first.split_once('/').unwrap_or((first, bits));
                if hole
                    || v4 != self.endpoint.is_ipv4()
                    || length != bits
                    || addr.parse::<IpAddr>().ok() != Some(self.endpoint)
                    || after(&w, "dev") != Some(self.outer.as_str())
                    || after(&w, "src").is_none()
                {
                    return Err(conflict());
                }
                own(&mut found.peer, owned)?;
            }
        }
        Ok(found)
    }
    pub fn reconcile(&self, owned: bool, install: bool, ip: &Ip<'_>) -> io::Result<()> {
        self.validate(&self.iface)?;
        let before = [
            self.inspect("-4", owned, ip)?,
            self.inspect("-6", owned, ip)?,
        ];
        if !owned {
            return Ok(());
        } // Preflight both families before creating the receipt.
        let mark = format!("0x{:x}", self.mark()?);
        let table = self.table()?.to_string();
        let endpoint = format!(
            "{}/{}",
            self.endpoint,
            if self.endpoint.is_ipv4() { 32 } else { 128 }
        );
        let src = self.source.to_string();
        let verb = if install { "add" } else { "del" };
        for (family, have) in ["-4", "-6"].into_iter().zip(before) {
            let want_peer = self.endpoint.is_ipv4() == (family == "-4");
            let want = Objects {
                guard: install,
                lookup: install,
                blackhole: install,
                peer: install && want_peer,
            };
            if have == want {
                continue;
            }
            let guard = [
                family, "rule", verb, "pref", "61", "fwmark", &mark, "type", "prohibit",
            ];
            let hole = [
                family,
                "route",
                verb,
                "blackhole",
                "default",
                "table",
                &table,
                "proto",
                "99",
                "metric",
                "1000",
            ];
            let peer = [
                family,
                "route",
                verb,
                &endpoint,
                "dev",
                &self.outer,
                "src",
                &src,
                "table",
                &table,
                "proto",
                "99",
            ];
            let lookup = [
                family, "rule", verb, "pref", "60", "fwmark", &mark, "table", &table,
            ];
            let mut ops: Vec<(bool, &[&str])> = vec![
                (have.guard, &guard),
                (have.blackhole, &hole),
                (have.lookup, &lookup),
            ];
            if want_peer {
                ops.insert(2, (have.peer, &peer));
            }
            if !install {
                ops.reverse();
            }
            for (exists, args) in ops {
                if exists != install {
                    ip(args)?;
                }
            }
            let after = self.inspect(family, true, ip)?;
            if after != want {
                return Err(invalid("ядро не подтвердило маршруты вложенного AWG"));
            }
        }
        Ok(())
    }
}
