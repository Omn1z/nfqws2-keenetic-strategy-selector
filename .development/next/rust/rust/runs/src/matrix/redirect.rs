use super::{baseline, check_queue_traffic, interrupted_probe, Control};
use hyper::Uri;
use serde_json::Value;
use std::{io, net::Ipv4Addr, ops::Range, sync::atomic::Ordering, time::Instant};

#[cfg(test)]
pub(super) mod tests;

const MAX_REQUESTS: usize = 10;
const MAX_LOCATION: usize = 8192;
pub(super) const HEADER_LIMIT: u64 = 64 << 10;

#[derive(Clone, Copy)]
pub(super) struct Hop<'a> {
    pub uri: &'a Uri,
    pub deadline: Instant,
    pub address: Option<Ipv4Addr>,
    pub redirected: bool,
}

pub(super) enum Output {
    Terminal(Value),
    Redirect(String),
}

pub(super) enum Header {
    Pending,
    Terminal,
    Redirect(String),
}

pub(super) fn header(raw: &str) -> io::Result<Header> {
    let mut rest = raw;
    while let Some((section, next)) = rest.split_once("\r\n\r\n") {
        rest = next;
        let mut lines = section.split("\r\n");
        let mut status = lines.next().unwrap_or_default().split_ascii_whitespace();
        if !status
            .next()
            .is_some_and(|version| version.starts_with("HTTP/"))
        {
            return Err(super::invalid("некорректный заголовок ответа HTTPS"));
        }
        let Some(code) = status
            .next()
            .and_then(|code| code.parse::<u16>().ok())
            .filter(|code| (100..=599).contains(code))
        else {
            return Err(super::invalid("некорректный статус ответа HTTPS"));
        };
        if (100..200).contains(&code) && code != 101 {
            continue;
        }
        if matches!(code, 301 | 302 | 303 | 307 | 308) {
            if let Some(value) = lines
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("location")
                        .then(|| value.trim_matches([' ', '\t']))
                })
                .filter(|value| !value.is_empty())
            {
                // Keep the rejected value out of the report and the command.
                if value.len() > MAX_LOCATION {
                    return Err(super::invalid("слишком длинный HTTPS Location"));
                }
                return Ok(Header::Redirect(value.to_owned()));
            }
        }
        return Ok(Header::Terminal);
    }
    Ok(Header::Pending)
}

fn same_host(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

fn public_name(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let Some((_, suffix)) = host.rsplit_once('.') else {
        return false;
    };
    host.len() <= 253
        && !matches!(
            suffix,
            "localhost"
                | "local"
                | "localdomain"
                | "lan"
                | "home"
                | "internal"
                | "onion"
                | "invalid"
                | "test"
                | "example"
        )
        && !host.ends_with(".home.arpa")
        && host != "home.arpa"
        && suffix.bytes().any(|b| b.is_ascii_alphabetic())
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a != 0
        && a < 224
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation()
        && !(a == 100 && (64..128).contains(&b))
        && !(a == 192 && (b == 0 && c == 0 || b == 88 && c == 99))
        && !(a == 198 && matches!(b, 18 | 19))
}

fn location_uri(base: &Uri, location: &str, allow_public: bool) -> io::Result<Uri> {
    let rejected = || {
        super::invalid(
            "HTTPS-перенаправление вышло за пределы адреса проверки или имеет неверный формат",
        )
    };
    if location.len() > MAX_LOCATION
        || !location.is_ascii()
        || location
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return Err(rejected());
    }
    let location = location.split('#').next().unwrap_or_default();
    if location.is_empty() {
        return Ok(base.clone());
    }
    if location.as_bytes().iter().enumerate().any(|(i, byte)| {
        *byte == b'%'
            && !location
                .as_bytes()
                .get(i + 1..i + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    }) {
        return Err(rejected());
    }
    let original = base.authority().ok_or_else(rejected)?;
    let next = if location.starts_with("//") {
        format!("https:{location}")
    } else if location.starts_with('/') {
        format!("https://{original}{location}")
    } else if location.starts_with('?') {
        format!("https://{original}{}{location}", base.path())
    } else if location
        .split(['/', '?'])
        .next()
        .is_some_and(|part| part.contains(':'))
    {
        location.to_owned()
    } else {
        let parent = base.path().rsplit_once('/').map_or("", |(path, _)| path);
        format!("https://{original}{parent}/{location}")
    };
    let next = next.parse::<Uri>().map_err(|_| rejected())?;
    let authority = next.authority().ok_or_else(rejected)?;
    let host = authority.host();
    let port = if authority.as_str() == host {
        Some(443)
    } else {
        authority.port_u16()
    };
    let same = same_host(host, original.host());
    if next.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || port != Some(443)
        || original.port_u16().unwrap_or(443) != 443
        || !(same || allow_public && public_name(host))
    {
        return Err(rejected());
    }
    let mut segments = Vec::new();
    let path = next.path();
    for segment in path.split('/').skip(1) {
        match segment {
            "." => (),
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    if path.ends_with("/.") || path.ends_with("/..") {
        segments.push("");
    }
    let query = next.query().map_or_else(String::new, |q| format!("?{q}"));
    let authority = if same { original.as_str() } else { host };
    let resolved = format!("https://{authority}/{}{query}", segments.join("/"));
    if resolved.len() > MAX_LOCATION {
        return Err(rejected());
    }
    resolved.parse().map_err(|_| rejected())
}

#[cfg(test)]
fn same_authority(base: &Uri, location: &str) -> io::Result<Uri> {
    location_uri(base, location, false)
}

pub(super) fn attest(output: Output, host: &str, before: u32, after: io::Result<u32>) -> Output {
    match output {
        Output::Terminal(mut sample) => {
            check_queue_traffic(&mut sample, before, after);
            Output::Terminal(sample)
        }
        Output::Redirect(location) if matches!(&after, Ok(sequence) if before != *sequence) => {
            Output::Redirect(location)
        }
        Output::Redirect(_) => {
            let mut sample = failure(host, "нет подтверждения NFQUEUE для HTTPS-перехода");
            check_queue_traffic(&mut sample, before, after);
            Output::Terminal(sample)
        }
    }
}

pub(super) fn failure(host: &str, detail: &str) -> Value {
    let mut sample = interrupted_probe(host);
    sample["err"] = detail.into();
    sample
}

#[derive(Clone, Copy)]
enum FailureClass {
    Timeout,
    NoPort,
    Dns,
    Other,
}

fn chain_failure(host: &str, detail: &str, baseline_report: bool, class: FailureClass) -> Value {
    let mut sample = failure(host, detail);
    if baseline_report {
        if matches!(class, FailureClass::NoPort) {
            sample["local_error"] = true.into();
        }
        baseline::classify(
            &mut sample,
            if matches!(class, FailureClass::Dns) {
                6
            } else {
                -1
            },
            matches!(class, FailureClass::Timeout),
            false,
            None,
        );
    }
    sample
}

pub(super) fn timed_out(host: &str, baseline_report: bool) -> Value {
    chain_failure(
        host,
        "истекло время HTTPS-проверки",
        baseline_report,
        FailureClass::Timeout,
    )
}

pub(super) fn no_port(host: &str, baseline_report: bool) -> Value {
    chain_failure(
        host,
        "для HTTPS-перехода нет свободного порта в диапазоне проверки",
        baseline_report,
        FailureClass::NoPort,
    )
}

pub(super) struct Chain<'a> {
    pub lease: Range<Instant>,
    pub port_count: usize,
    pub baseline: bool,
    pub address: Option<Ipv4Addr>,
    pub local_ips: &'a [String],
}

type ResolveAddress<'a> = dyn FnMut(&str, Instant) -> io::Result<Ipv4Addr> + 'a;

pub(super) fn follow_public(
    host: &str,
    uri: Uri,
    chain: Chain<'_>,
    control: &Control,
    mut resolve: impl FnMut(&str, Instant) -> io::Result<Ipv4Addr>,
    request: impl FnMut(Hop<'_>) -> io::Result<Option<Output>>,
) -> io::Result<Option<Value>> {
    drive(host, uri, chain, control, Some(&mut resolve), request)
}

#[cfg(test)]
pub(super) fn follow(
    host: &str,
    uri: Uri,
    started: Instant,
    deadline: Instant,
    port_count: usize,
    control: &Control,
    request: impl FnMut(Hop<'_>) -> io::Result<Option<Output>>,
) -> io::Result<Option<Value>> {
    drive(
        host,
        uri,
        Chain {
            lease: started..deadline,
            port_count,
            baseline: false,
            address: None,
            local_ips: &[],
        },
        control,
        None,
        request,
    )
}

#[cfg(test)]
pub(super) fn follow_baseline(
    host: &str,
    uri: Uri,
    started: Instant,
    deadline: Instant,
    port_count: usize,
    control: &Control,
    request: impl FnMut(Hop<'_>) -> io::Result<Option<Output>>,
) -> io::Result<Option<Value>> {
    drive(
        host,
        uri,
        Chain {
            lease: started..deadline,
            port_count,
            baseline: true,
            address: None,
            local_ips: &[],
        },
        control,
        None,
        request,
    )
}

fn drive(
    host: &str,
    mut uri: Uri,
    chain: Chain<'_>,
    control: &Control,
    mut resolve: Option<&mut ResolveAddress<'_>>,
    mut request: impl FnMut(Hop<'_>) -> io::Result<Option<Output>>,
) -> io::Result<Option<Value>> {
    let Range {
        start: started,
        end: deadline,
    } = chain.lease;
    let baseline_report = chain.baseline;
    let mut address = chain.address;
    let mut new_authority = false;
    let retain_interrupted = || !baseline_report && control.keeps_cancelled_rows();
    let mut previous_hop = false;
    let mut hops = 0;
    let (mut sample, offset) = loop {
        let now = Instant::now();
        let mut offset = now.saturating_duration_since(started).as_millis() as u64;
        if control.cancel.load(Ordering::Acquire) {
            if previous_hop && retain_interrupted() {
                break (interrupted_probe(host), offset);
            }
            return Ok(None);
        }
        if now >= deadline {
            break (timed_out(host, baseline_report), offset);
        }
        if new_authority {
            let next_host = uri
                .host()
                .ok_or_else(|| super::invalid("нет HTTPS-хоста"))?;
            let lookup = resolve.as_mut().expect("public redirect is configured");
            let ip = match next_host
                .parse::<Ipv4Addr>()
                .map_or_else(|_| lookup(next_host, deadline), Ok)
            {
                Ok(ip) => ip,
                Err(_) if control.cancel.load(Ordering::Acquire) => {
                    if retain_interrupted() {
                        break (interrupted_probe(host), offset);
                    }
                    return Ok(None);
                }
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    break (timed_out(host, baseline_report), offset)
                }
                Err(_) => {
                    break (
                        chain_failure(
                            host,
                            "не удалось разрешить HTTPS-переход в IPv4",
                            baseline_report,
                            FailureClass::Dns,
                        ),
                        offset,
                    )
                }
            };
            if !public_ipv4(ip) || chain.local_ips.contains(&ip.to_string()) {
                break (
                    chain_failure(
                        host,
                        "HTTPS-переход требует публичный IPv4 и не может вести на локальный адрес",
                        baseline_report,
                        FailureClass::Other,
                    ),
                    offset,
                );
            }
            if Instant::now() >= deadline {
                break (timed_out(host, baseline_report), offset);
            }
            address = Some(ip);
            offset = started.elapsed().as_millis() as u64;
        }
        hops += 1;
        match request(Hop {
            uri: &uri,
            deadline,
            address,
            redirected: previous_hop,
        })? {
            Some(Output::Terminal(sample)) => break (sample, offset),
            Some(Output::Redirect(location)) => {
                previous_hop = true;
                let next = match location_uri(&uri, &location, resolve.is_some()) {
                    Ok(next) => next,
                    Err(error) => {
                        break (
                            chain_failure(
                                host,
                                &error.to_string(),
                                baseline_report,
                                FailureClass::Other,
                            ),
                            offset,
                        )
                    }
                };
                if hops == MAX_REQUESTS {
                    break (
                        chain_failure(
                            host,
                            "stopped after 10 redirects",
                            baseline_report,
                            FailureClass::Other,
                        ),
                        offset,
                    );
                }
                if hops == chain.port_count {
                    break (no_port(host, baseline_report), offset);
                }
                new_authority = !same_host(
                    uri.host().unwrap_or_default(),
                    next.host().unwrap_or_default(),
                );
                uri = next;
            }
            None if previous_hop && retain_interrupted() => {
                break (interrupted_probe(host), offset)
            }
            None => return Ok(None),
        }
    };
    let elapsed = started.elapsed().as_millis() as u64;
    sample["total_ms"] = elapsed.into();
    let size = sample["size"].as_u64().unwrap_or_default();
    sample["speed_bps"] = size
        .saturating_mul(1000)
        .checked_div(elapsed)
        .unwrap_or_default()
        .into();
    sample["ttfb_ms"] = if sample["code"].as_u64().unwrap_or_default() != 0 {
        sample["ttfb_ms"]
            .as_u64()
            .unwrap_or_default()
            .saturating_add(offset)
            .into()
    } else {
        0.into()
    };
    Ok(Some(sample))
}
