use super::invalid;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::Ipv4Addr,
};

#[derive(Default)]
pub(super) struct Interface {
    pub id: String,
    pub alias: String,
    pub description: String,
    pub ssid: String,
    pub level: String,
    pub address: String,
    pub mask: String,
    pub members: Vec<String>,
    pub up: bool,
    pub global: bool,
    pub isolation: Option<bool>,
}
#[derive(Default)]
pub(super) struct Topology {
    pub bridges: Vec<Interface>,
    pub aps: Vec<Interface>,
    pub(super) isolate_private: Option<bool>,
}
fn number(s: &str) -> bool {
    s == "0" || !s.starts_with('0') && !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}
pub(super) fn bridge(id: &str) -> bool {
    id.strip_prefix("Bridge").is_some_and(number)
}
fn ap(id: &str) -> bool {
    id.strip_prefix("WifiMaster")
        .and_then(|s| s.split_once("/AccessPoint"))
        .is_some_and(|(radio, index)| number(radio) && number(index))
}
fn native_id(s: &str) -> bool {
    s.bytes().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_./:-".contains(&c))
}
fn address(ip: &str, mask: &str) -> bool {
    let (Ok(ip), Ok(mask)) = (ip.parse::<Ipv4Addr>(), mask.parse::<Ipv4Addr>()) else {
        return false;
    };
    let mask = u32::from(mask);
    let bits = mask.leading_ones();
    !ip.is_unspecified()
        && !ip.is_multicast()
        && (1..32).contains(&bits)
        && mask.count_ones() == bits
}
pub(super) fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            continue;
        }
        if c == '\x1b' && chars.next_if_eq(&'[').is_some() {
            while chars
                .next_if(|v| v.is_ascii_digit() || matches!(v, ';' | '?'))
                .is_some()
            {}
            chars.next_if(|c| c.is_ascii_alphabetic());
        } else {
            out.push(c);
        }
    }
    out
}
fn tokens(line: &str) -> io::Result<Vec<String>> {
    let mut chars = line.as_bytes().iter().copied().peekable();
    let mut words = Vec::new();
    while chars.peek().is_some() {
        while chars.next_if(|c| matches!(c, b' ' | b'\t')).is_some() {}
        if chars.peek().is_none() {
            break;
        }
        let quoted = chars.next_if_eq(&b'"').is_some();
        let mut word = Vec::new();
        let mut closed = false;
        while let Some(&c) = chars.peek() {
            if !quoted && matches!(c, b' ' | b'\t') {
                break;
            }
            chars.next();
            if c == b'"' {
                if !quoted {
                    return Err(invalid("неверные кавычки поля интерфейса"));
                }
                closed = true;
                break;
            }
            let c = if quoted && c == b'\\' {
                let next = chars
                    .next()
                    .ok_or_else(|| invalid("неверное поле интерфейса"))?;
                if next == b'x' {
                    let mut look = chars.clone();
                    let digits = [look.next().unwrap_or(0), look.next().unwrap_or(0)];
                    if let Some(n) = std::str::from_utf8(&digits)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                    {
                        chars = look;
                        n
                    } else {
                        word.push(b'\\');
                        next
                    }
                } else {
                    if !matches!(next, b'\\' | b'"') {
                        word.push(b'\\');
                    }
                    next
                }
            } else {
                c
            };
            if c.is_ascii_control() {
                return Err(invalid("некорректное поле интерфейса"));
            }
            word.push(c);
        }
        if quoted && (!closed || chars.peek().is_some_and(|c| !matches!(c, b' ' | b'\t'))) {
            return Err(invalid("неверные кавычки поля интерфейса"));
        }
        words.push(String::from_utf8(word).map_err(|_| invalid("неверная кодировка интерфейса"))?);
    }
    Ok(words)
}
fn interface(id: &str, lines: &[&str]) -> io::Result<Interface> {
    let mut item = Interface {
        id: id.into(),
        ..Default::default()
    };
    let mut seen = BTreeSet::new();
    let depth = |s: &str| s.len() - s.trim_start_matches([' ', '\t']).len();
    let indent = lines.iter().map(|s| depth(s)).min().unwrap_or(0);
    for line in lines.iter().copied().filter(|s| depth(s) == indent) {
        let line = line.trim();
        let mut head = line.split_ascii_whitespace();
        let mut key = head.next().unwrap_or("");
        if key == "no" {
            key = head.next().unwrap_or("");
        }
        key = match key {
            "name" => "rename",
            "down" => "up",
            "ip" => match head.next() {
                Some("address") => "ip address",
                Some("global") => "ip global",
                _ => continue,
            },
            other => other,
        };
        if !matches!(
            key,
            "rename"
                | "description"
                | "ssid"
                | "up"
                | "security-level"
                | "include"
                | "inherit"
                | "peer-isolation"
                | "ip address"
                | "ip global"
        ) {
            continue;
        }
        if !bridge(id)
            && !(key == "rename" || ap(id) && matches!(key, "description" | "ssid" | "up"))
        {
            continue;
        }
        if !matches!(key, "include" | "inherit") && !seen.insert(key) {
            return Err(invalid("повторное поле интерфейса"));
        }
        let words = tokens(line)?;
        let args: Vec<_> = words.iter().map(String::as_str).collect();
        match (key, args.as_slice()) {
            ("rename", ["rename" | "name", v]) => item.alias = (*v).into(),
            ("description", ["description", v]) => item.description = (*v).into(),
            ("ssid", ["ssid", v]) => item.ssid = (*v).into(),
            ("security-level", ["security-level", v @ ("private" | "protected" | "public")]) => {
                item.level = (*v).into()
            }
            ("include" | "inherit", [_, v])
                if native_id(v) && !item.members.iter().any(|m| m == v) =>
            {
                item.members.push((*v).into())
            }
            ("up", ["up"]) => item.up = true,
            ("up", ["down"] | ["no", "up"]) => item.up = false,
            ("peer-isolation", ["peer-isolation"]) => item.isolation = Some(true),
            ("peer-isolation", ["no", "peer-isolation"]) => item.isolation = Some(false),
            ("ip global", ["ip", "global", ..]) => item.global = true,
            ("ip global", ["no", "ip", "global"]) => item.global = false,
            ("ip address", ["no", "ip", "address"]) => {}
            ("ip address", ["ip", "address", ip, mask]) if address(ip, mask) => {
                item.address = (*ip).into();
                item.mask = (*mask).into();
            }
            _ => return Err(invalid("некорректное поле интерфейса")),
        }
    }
    Ok(item)
}
pub(super) fn topology(text: &str) -> io::Result<Topology> {
    if text.len() > 2 << 20 {
        return Err(invalid("слишком большая конфигурация Keenetic"));
    }
    let mut out = Topology::default();
    let mut ids = BTreeSet::new();
    let mut blocks = Vec::<(&str, Vec<&str>)>::new();
    let mut active = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        if trimmed.starts_with('!') {
            if !indented {
                active = false;
            }
            continue;
        }
        if indented {
            if active {
                blocks.last_mut().unwrap().1.push(line);
            }
            continue;
        }
        active = false;
        if matches!(trimmed, "isolate-private" | "no isolate-private")
            && out
                .isolate_private
                .replace(trimmed == "isolate-private")
                .is_some()
        {
            return Err(invalid("повторный isolate-private"));
        }
        let mut fields = trimmed.split_ascii_whitespace();
        if fields.next() != Some("interface") {
            continue;
        }
        let id = fields
            .next()
            .filter(|s| native_id(s))
            .ok_or_else(|| invalid("некорректный интерфейс"))?;
        if fields.next().is_some() || !ids.insert(id) {
            return Err(invalid("неоднозначный интерфейс"));
        }
        blocks.push((id, Vec::new()));
        active = true;
    }
    let mut aliases: BTreeMap<String, String> =
        ids.into_iter().map(|v| (v.into(), v.into())).collect();
    for (id, lines) in blocks {
        let item = interface(id, &lines)?;
        if !item.alias.is_empty()
            && aliases
                .insert(item.alias.clone(), id.into())
                .is_some_and(|old| old != id)
        {
            return Err(invalid("неоднозначный псевдоним интерфейса"));
        }
        if bridge(id) {
            out.bridges.push(item);
        } else if ap(id) {
            out.aps.push(item);
        }
    }
    if out.bridges.is_empty() {
        return Err(invalid("не найдены сегменты Bridge"));
    }
    Ok(out)
}
impl Interface {
    pub fn eligible(&self) -> io::Result<()> {
        if !matches!(self.level.as_str(), "private" | "protected") {
            return Err(invalid("это не локальный сегмент private/protected"));
        }
        if self.global {
            return Err(invalid("это WAN/global интерфейс"));
        }
        if !self.up {
            return Err(invalid("сегмент выключен"));
        }
        if self.members.is_empty() {
            return Err(invalid("к сегменту не подключены интерфейсы"));
        }
        if !address(&self.address, &self.mask) {
            return Err(invalid("не определён адрес локального сегмента"));
        }
        Ok(())
    }
    pub fn confirm(&self, text: &str) -> io::Result<()> {
        self.eligible()?;
        if text.len() > 256 << 10 {
            return Err(invalid("слишком большой статус интерфейса"));
        }
        let column = text
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.trim() == "id")
            .map(|(k, _)| k.len())
            .min()
            .ok_or_else(|| invalid("нет идентификатора Bridge"))?;
        let mut fields = BTreeMap::new();
        for (key, value) in text
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.len() == column)
        {
            let key = key.trim();
            if matches!(
                key,
                "id" | "type"
                    | "interface-name"
                    | "state"
                    | "security-level"
                    | "address"
                    | "mask"
                    | "global"
            ) && fields.insert(key, value.trim()).is_some()
            {
                return Err(invalid("неоднозначный статус интерфейса"));
            }
        }
        for (key, value) in [
            ("id", self.id.as_str()),
            ("type", "Bridge"),
            ("state", "up"),
            ("security-level", &self.level),
            ("global", "no"),
            ("address", &self.address),
            ("mask", &self.mask),
        ] {
            if fields.get(key) != Some(&value) {
                return Err(invalid("состояние локального Bridge не подтверждено"));
            }
        }
        if !self.alias.is_empty() && fields.get("interface-name") != Some(&self.alias.as_str()) {
            return Err(invalid("псевдоним сегмента изменился"));
        }
        Ok(())
    }
}
