use std::io;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn protocol(value: &str, wanted: &str) -> bool {
    !value.starts_with('~')
        && value
            .split(',')
            .any(|item| matches!(item, "all" | "known") || item == wanted)
}

fn ports(value: &str) -> io::Result<bool> {
    let mut matched = false;
    for item in value.split(',') {
        if item == "*" {
            matched = true;
            continue;
        }
        let negated = item.starts_with('~');
        let item = item.strip_prefix('~').unwrap_or(item);
        let (lo, hi) = item.split_once('-').unwrap_or((item, item));
        let parse = |s: &str| {
            if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                return Err(invalid("некорректный фильтр TCP-портов"));
            }
            s.parse::<u16>()
                .map_err(|_| invalid("некорректный фильтр TCP-портов"))
        };
        let (lo, hi) = (parse(lo)?, parse(hi)?);
        if lo > hi {
            return Err(invalid("некорректный фильтр TCP-портов"));
        }
        matched |= (lo <= 443 && 443 <= hi) != negated;
    }
    Ok(matched)
}

/// Verify that a single candidate can actually process the runner's IPv4
/// TCP/443 TLS probe. The engine remains the authority for detailed syntax.
/// Lifecycle and profile separators cannot override the runner's isolation.
pub fn validate_https_strategy(args: &str) -> io::Result<()> {
    const LUA: &[&str] = &[
        "circular",
        "fake",
        "multisplit",
        "multidisorder",
        "split",
        "disorder",
        "fakedsplit",
        "fakeddisorder",
        "hostfakesplit",
        "http_methodeol",
        "syndata",
        "send",
        "pktmod",
        "tamper",
    ];
    const DPI: &[&str] = &[
        "fake",
        "split",
        "split2",
        "disorder",
        "disorder2",
        "fakedsplit",
        "fakeddisorder",
        "multisplit",
        "multidisorder",
        "syndata",
        "ipfrag2",
        "udplen",
        "tamper",
    ];
    if args.trim().is_empty() || args.len() > 32 << 10 || args.contains('\0') {
        return Err(invalid("пустые или слишком длинные аргументы стратегии"));
    }
    let (mut tcp_seen, mut tcp_matches, mut other_transport) = (false, false, false);
    let (mut l3_seen, mut ipv4_matches, mut tls_matches) = (false, false, true);
    let (mut payload_matches, mut desync_matches) = (true, false);
    for token in args.split_whitespace() {
        if !token.starts_with("--") {
            return Err(invalid("аргументы стратегии пишутся как --флаг=значение"));
        }
        let (key, value) = token.split_once('=').unwrap_or((token, ""));
        // getopt_long also accepts unique prefixes. Do not let an abbreviated
        // runtime flag silently override the queue or detach the owned child.
        if [
            "--qnum",
            "--daemon",
            "--pidfile",
            "--writable",
            "--new",
            "--user",
            "--uid",
            "--lua-init",
            "--lua-file",
            "--help",
            "--version",
            "--dry-run",
        ]
        .iter()
        .any(|option| option.starts_with(key))
        {
            return Err(invalid("служебный аргумент недопустим в HTTPS-стратегии"));
        }
        match key {
            "--new" | "--skip" | "--template" | "--import" | "--qnum" | "--daemon"
            | "--pidfile" | "--writable" | "--user" | "--uid" | "--help" | "--version"
            | "--dry-run" | "--lua-init" => {
                return Err(invalid(
                    "HTTPS-проверка не поддерживает служебный аргумент стратегии",
                ));
            }
            "--filter-tcp" => {
                tcp_seen = true;
                tcp_matches |= ports(value)?;
            }
            "--filter-udp" | "--filter-icmp" | "--filter-ipp" => other_transport = true,
            "--filter-l3" => {
                l3_seen = true;
                ipv4_matches |= value.split(',').any(|p| p == "ipv4");
            }
            "--filter-l7" => tls_matches = protocol(value, "tls"),
            "--payload" => payload_matches = protocol(value, "tls_client_hello"),
            "--lua-desync" => {
                let mut parts = value.split(':');
                let method = parts.next().unwrap_or("");
                if !LUA.contains(&method) {
                    return Err(invalid("неизвестный метод --lua-desync"));
                }
                let matches = payload_matches
                    && parts
                        .filter_map(|p| p.strip_prefix("payload="))
                        .all(|p| protocol(p, "tls_client_hello"));
                desync_matches |= method != "http_methodeol" && matches;
            }
            "--dpi-desync" => {
                if value.is_empty() || value.split(',').any(|m| !DPI.contains(&m)) {
                    return Err(invalid("неизвестный режим --dpi-desync"));
                }
                desync_matches = true;
            }
            _ => (),
        }
    }
    if (tcp_seen && !tcp_matches)
        || (!tcp_seen && other_transport)
        || (l3_seen && !ipv4_matches)
        || !tls_matches
        || !desync_matches
    {
        return Err(invalid(
            "стратегия не обрабатывает HTTPS (IPv4, TCP/443, TLS)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_and_payload_scopes_match_the_https_probe() {
        for args in [
            "--lua-desync=multisplit:pos=1,midsld",
            "--dpi-desync=fake,split2",
            "--filter-tcp=80,443 --filter-l7=http,tls --lua-desync=fake",
            "--filter-tcp=~80 --lua-desync=fake",
            "--filter-tcp=80 --filter-tcp=443 --lua-desync=fake",
            "--filter-l3=ipv6 --filter-l3=ipv4 --lua-desync=fake",
            "--payload=tls_client_hello --lua-desync=fake --payload=http_req --lua-desync=multisplit",
            "--filter-l7=http --filter-l7=tls --payload=known --lua-desync=fake",
            "--filter-tcp=400-450 --lua-desync=fake",
        ] {
            assert!(validate_https_strategy(args).is_ok(), "{args}");
        }
        for args in [
            "",
            "--filter-tcp=443",
            "--lua-desync=typo",
            "--filter-tcp=80 --filter-l7=http --lua-desync=multisplit",
            "--filter-udp=443 --filter-l7=tls --lua-desync=fake",
            "--filter-tcp=~400-450 --lua-desync=fake",
            "--filter-tcp=443,garbage --lua-desync=fake",
            "--filter-tcp=400:450 --lua-desync=fake",
            "--filter-tcp=65536 --lua-desync=fake",
            "--filter-tcp=450-400 --lua-desync=fake",
            "--filter-l7=tls --filter-l7=http --lua-desync=fake",
            "--filter-l3=ipv6 --lua-desync=fake",
            "--payload=http_req --lua-desync=fake --payload=tls_client_hello",
            "--lua-desync=fake:payload=~http_req,tls_client_hello",
            "--payload=http_req --lua-desync=fake:payload=tls_client_hello",
            "--lua-desync=http_methodeol",
            "--lua-desync=fake --new --lua-desync=fake",
            "--lua-desync=fake --qnum=300",
            "--lua-desync=fake --daemon",
            "--lua-desync=fake --lua-init=@untrusted.lua",
        ] {
            assert!(validate_https_strategy(args).is_err(), "{args}");
        }
    }
}
