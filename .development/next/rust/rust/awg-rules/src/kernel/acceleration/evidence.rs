//! Read-only checks on kernel evidence before enabling selective flow offload.
use std::collections::BTreeSet;

pub(super) fn accounting(data: &[u8]) -> bool {
    let Some(end) = data.iter().rposition(|&b| b == b'\n') else {
        return false;
    };
    let Ok(rows) = std::str::from_utf8(&data[..end]) else {
        return false;
    };
    let mut flows = BTreeSet::new();
    let mut traffic = false;
    for row in rows.lines() {
        let words = row.split_ascii_whitespace();
        if !words.clone().take(4).any(|w| matches!(w, "tcp" | "udp")) {
            continue;
        }
        let mut packets = 0;
        let mut bytes = 0;
        let mut tuple = Vec::with_capacity(4);
        for word in words {
            let Some((key, value)) = word.split_once('=') else {
                continue;
            };
            match key {
                "packets" | "bytes" => {
                    let Ok(count) = value.parse::<u64>() else {
                        return false;
                    };
                    if key == "packets" {
                        packets += 1;
                        traffic |= count > 0;
                    } else {
                        bytes += 1;
                    }
                }
                "src" | "dst" | "sport" | "dport" if tuple.len() < 4 => tuple.push(word),
                _ => (),
            }
        }
        if packets != 2 || bytes != 2 || tuple.len() != 4 {
            return false;
        }
        // Two distinct tuples suffice, but later rows must still be validated.
        if flows.len() < 2 {
            flows.insert(tuple);
        }
    }
    flows.len() == 2 && traffic
}

// iptables-save quotes comments. Their contents must never become options.
fn tokens(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut active = false;
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quote != Some('\'') => word.push(chars.next()?),
            _ if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            _ if quote.is_none() && ch.is_ascii_whitespace() => {
                if active {
                    words.push(std::mem::take(&mut word));
                }
                active = false;
                continue;
            }
            _ => word.push(ch),
        }
        active = true;
    }
    if active {
        words.push(word);
    }
    quote.is_none().then_some(words)
}

fn tcp_flags(word: &str) -> Option<u8> {
    if let Some(hex) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).ok();
    }
    word.split(',').try_fold(0, |flags, flag| {
        Some(
            flags
                | match flag {
                    "NONE" => 0,
                    "FIN" => 1,
                    "SYN" => 2,
                    "RST" => 4,
                    "PSH" => 8,
                    "ACK" => 16,
                    "URG" => 32,
                    "ALL" => 63,
                    _ => return None,
                },
        )
    })
}

pub(super) fn nfqueue_safe(iptables_save: &str) -> bool {
    iptables_save
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("-A "))
        .all(|line| {
            let Some(words) = tokens(line) else {
                return false;
            };
            let mut args = Vec::new();
            let mut it = words.iter().map(String::as_str);
            while let Some(arg) = it.next() {
                if arg == "--comment" {
                    if it.next().is_none() {
                        return false;
                    }
                } else {
                    args.push(arg);
                }
            }
            if !args.windows(2).any(|w| w == ["-j", "NFQUEUE"]) {
                return true;
            }
            // Ambiguous, missing, or negated options cannot establish coverage.
            let value = |key| {
                let mut seen = args.iter().enumerate().filter(|(_, w)| **w == key);
                let (i, _) = seen.next()?;
                if seen.next().is_some() || i.checked_sub(1).is_some_and(|p| args[p] == "!") {
                    return None;
                }
                args.get(i + 1).copied()
            };
            if value("--queue-num")
                .and_then(|v| v.parse::<u16>().ok())
                .is_none()
                || args.contains(&"--queue-balance")
            {
                return false;
            }
            if value("--connbytes-mode") == Some("packets")
                && matches!(value("--connbytes-dir"), Some("original" | "reply"))
                && value("--connbytes")
                    .and_then(|v| {
                        let (start, end) = v.split_once(':')?;
                        Some((start.parse::<u32>().ok()?, end.parse::<u32>().ok()?))
                    })
                    .is_some_and(|(start, end)| start > 0 && start <= end && end <= 32)
            {
                return true;
            }
            if value("-p") != Some("tcp") || value("--tcp-flags").is_none() {
                return false;
            }
            args.windows(3).any(|w| {
                w[0] == "--tcp-flags"
                    && tcp_flags(w[1])
                        .zip(tcp_flags(w[2]))
                        .is_some_and(|(mask, flags)| mask & flags & 7 != 0)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspects_every_queue_in_every_table_and_ignores_quoted_comments() {
        let valid = "-A q -p tcp -m connbytes --connbytes 1:32 --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num 301";
        assert!(nfqueue_safe(valid));
        for (a, b) in [
            ("1:32", "1:33"),
            ("1:32", "4:1"),
            ("reply", "both"),
            ("packets", "bytes"),
            ("--connbytes ", "! --connbytes "),
            ("--connbytes-mode", "! --connbytes-mode"),
            ("301", "65536"),
        ] {
            assert!(!nfqueue_safe(&valid.replace(a, b)));
        }
        assert!(nfqueue_safe(&format!(
            "{valid} -m comment --comment \"text with 'quotes' and --tcp-flags FIN FIN\""
        )));
        let broad = "-A q -p tcp --comment \"--tcp-flags SYN SYN\" -j NFQUEUE --queue-num 300";
        assert!(!nfqueue_safe(&format!(
            "*filter\n{valid}\nCOMMIT\n*mangle\n{broad}\nCOMMIT"
        )));
        for (flags, expected) in [
            ("ALL SYN", true),
            ("FIN FIN", true),
            ("0x04 0x04", true),
            ("ACK ACK", false),
            ("NONE SYN", false),
        ] {
            let rule = format!("-A q -p tcp --tcp-flags {flags} -j NFQUEUE --queue-num 300");
            assert_eq!(nfqueue_safe(&rule), expected);
            assert!(!nfqueue_safe(&rule.replace("-p tcp", "! -p tcp")));
        }
        assert!(!nfqueue_safe(&format!("{valid} --comment \"open")));
    }
    #[test]
    fn accounting_requires_multiple_distinct_complete_flows_with_both_counters() {
        let first = "ipv4 2 tcp 6 25 src=192.0.2.1 dst=192.0.2.2 sport=1025 dport=443 packets=1 bytes=100 src=192.0.2.2 dst=192.0.2.1 sport=443 dport=1025 packets=0 bytes=0\n";
        let second = first.replace("1025", "1026");
        let valid = format!("{first}{second}");
        assert!(accounting(valid.as_bytes()));
        assert!(accounting(format!("{valid}tcp partial").as_bytes()));
        for bad in [
            format!("{first}{first}"),
            valid.trim_end().into(),
            valid.replace("packets=1", "packets=0"),
            format!("{valid}{}", first.replace(" bytes=0", "")),
            format!("{valid}{}", first.replace("bytes=100", "bytes=bad")),
        ] {
            assert!(!accounting(bad.as_bytes()));
        }
    }
}
