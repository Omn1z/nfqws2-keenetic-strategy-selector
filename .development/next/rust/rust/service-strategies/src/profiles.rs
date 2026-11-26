use crate::bad;
use std::io;

// One inclusive range per entry keeps the common "80,443" case small.
#[derive(Default)]
pub struct Ports(Vec<(u16, u16)>);
impl Ports {
    pub fn add(&mut self, value: &str, firewall: bool) -> io::Result<()> {
        fn port(v: &str) -> io::Result<u16> {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("некорректный номер порта"));
            }
            v.parse()
                .ok()
                .filter(|v| *v != 0)
                .ok_or_else(|| bad("порты должны быть в диапазоне 1–65535"))
        }
        let start = self.0.len();
        for item in value.split(',') {
            let item = if firewall { item.trim() } else { item };
            let neg = item.starts_with('~');
            let v = item.strip_prefix('~').unwrap_or(item);
            if firewall && (v == "*" || neg) {
                return Err(bad("неподдерживаемый диапазон портов firewall"));
            }
            let (lo, hi) = if v == "*" {
                (1, u16::MAX)
            } else {
                let split =
                    v.split_once('-')
                        .or_else(|| if firewall { v.split_once(':') } else { None });
                let (a, b) = split.unwrap_or((v, v));
                (port(a)?, port(b)?)
            };
            if lo > hi {
                return Err(bad("начало диапазона больше конца"));
            }
            if neg {
                if lo > 1 {
                    self.0.push((1, lo - 1));
                }
                if hi < u16::MAX {
                    self.0.push((hi + 1, u16::MAX));
                }
            } else {
                self.0.push((lo, hi));
            }
        }
        if start == self.0.len() {
            return Err(bad("фильтр не выбирает порты"));
        }
        Ok(())
    }
    pub fn formatted(&mut self, firewall: bool) -> io::Result<String> {
        self.0.sort_unstable();
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for &(lo, hi) in &self.0 {
            if let Some(prev) = ranges.last_mut().filter(|p| lo <= p.1.saturating_add(1)) {
                prev.1 = prev.1.max(hi);
            } else {
                ranges.push((lo, hi));
            }
        }
        if firewall
            && ranges
                .iter()
                .map(|(a, b)| 1 + usize::from(a != b))
                .sum::<usize>()
                > 15
        {
            return Err(bad("iptables multiport допускает до 15 слотов"));
        }
        Ok(ranges
            .into_iter()
            .map(|(a, b)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}:{b}")
                }
            })
            .collect::<Vec<_>>()
            .join(","))
    }
}
pub fn valid_text(text: &str) -> io::Result<()> {
    if text.chars().any(|c| {
        matches!(c, '$' | '\x60' | ';' | '|' | '&')
            || c.is_control() && !matches!(c, '\n' | '\r' | '\t')
    }) {
        return Err(bad("команды shell в стратегии запрещены"));
    }
    Ok(())
}
fn tokens(text: &str) -> io::Result<Vec<String>> {
    valid_text(text)?;
    let mut chars = text.chars().peekable();
    let mut word = String::new();
    let mut out = Vec::new();
    let mut quote = None;
    let mut active = false;
    while let Some(c) = chars.next() {
        if c == '\\' && quote != Some('\'') {
            let next = *chars
                .peek()
                .ok_or_else(|| bad("незавершённое экранирование"))?;
            if next == '\n' {
                chars.next();
                continue;
            }
            if next == '\r' && chars.clone().nth(1) == Some('\n') {
                chars.next();
                chars.next();
                continue;
            }
            if quote == Some('"') && !matches!(next, '"' | '\\') {
                word.push(c);
            } else {
                word.push(chars.next().unwrap());
            }
            active = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
        } else if matches!(c, '"' | '\'') {
            quote = Some(c);
            active = true;
        } else if matches!(c, ' ' | '\n' | '\r' | '\t') {
            if active {
                out.push(std::mem::take(&mut word));
                active = false;
            }
        } else if c == '#' && !active {
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
        } else {
            word.push(c);
            active = true;
        }
    }
    if quote.is_some() {
        return Err(bad("незакрытая кавычка"));
    }
    if active {
        out.push(word);
    }
    if out.len() > 2048 || out.iter().any(|w| w.contains(char::is_whitespace)) {
        return Err(bad("некорректные аргументы стратегии"));
    }
    Ok(out)
}
pub fn append(
    text: &str,
    list: &str,
    output: &mut Vec<String>,
    ports: &mut [Ports; 2],
    remaining: &mut usize,
) -> io::Result<usize> {
    let all = tokens(text)?;
    let mut count = 0;
    for profile in all.split(|s| s == "--new") {
        let mut transport = false;
        for arg in profile {
            let (key, value) = arg
                .split_once('=')
                .filter(|(_, v)| !v.is_empty())
                .ok_or_else(|| bad("ожидается --параметр=значение"))?;
            match key {
                "--filter-tcp" | "--filter-udp" => {
                    ports[usize::from(key == "--filter-udp")].add(value, false)?;
                    transport = true;
                }
                "--filter-l3" | "--filter-l7" | "--payload" | "--in-range" | "--out-range" => {}
                "--lua-desync" => {
                    let method = value.split(':').next().unwrap_or_default();
                    if !method.bytes().enumerate().all(|(i, b)| {
                        b.is_ascii_alphabetic() || b == b'_' || i > 0 && b.is_ascii_digit()
                    }) || method.is_empty()
                    {
                        return Err(bad("некорректное имя метода Lua"));
                    }
                }
                k if k.starts_with("--dpi-desync") => {}
                _ => return Err(bad(format!("неподдерживаемый параметр сервиса {key}"))),
            }
        }
        if !transport {
            return Err(bad("для профиля нужен --filter-tcp или --filter-udp"));
        }
        let size = list.len()
            + 1
            + profile.iter().map(|s| s.len() + 1).sum::<usize>()
            + usize::from(!output.is_empty()) * 6;
        *remaining = remaining
            .checked_sub(size)
            .ok_or_else(|| bad("слишком большой набор профилей"))?;
        if !output.is_empty() {
            output.push("--new".into());
        }
        output.push(list.to_owned());
        output.extend_from_slice(profile);
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complements_quotes_and_multiport_limits() {
        let mut p = Ports::default();
        p.add("~80,~81", false).unwrap();
        assert_eq!(p.formatted(false).unwrap(), "1:65535");
        assert!(Ports::default().add("~*", false).is_err());
        let mut p = Ports::default();
        p.add("1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31", true)
            .unwrap();
        assert!(p.formatted(true).is_err());
        assert_eq!(
            tokens("--filter-tcp='443' # comment\n--payload=test").unwrap(),
            ["--filter-tcp=443", "--payload=test"]
        );
        for t in [
            "--foo=1",
            "--payload=t",
            "--filter-tcp=0",
            "--filter-tcp=443 --new",
            "--filter-tcp=\"80 443\"",
            "--lua-desync=4x --filter-tcp=4",
            "--filter-tcp=443;id",
        ] {
            let mut remaining = 1024;
            assert!(
                append(
                    t,
                    "--hostlist=s",
                    &mut vec![],
                    &mut Default::default(),
                    &mut remaining
                )
                .is_err(),
                "{t}"
            );
        }
    }
}
