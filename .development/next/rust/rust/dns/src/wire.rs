//! The DNS header and resource-record fields used by the wire cache.
pub(crate) mod routes;
mod ptr;
pub use ptr::ptr_records;
use std::{collections::HashSet, io, net::Ipv4Addr, ops::Range};
pub(crate) fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u16_at(raw: &[u8], i: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        raw.get(i..i + 2)
            .ok_or_else(|| bad("dns: short message"))?
            .try_into()
            .unwrap(),
    ))
}
pub(crate) fn u32_at(raw: &[u8], i: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        raw.get(i..i + 4)
            .ok_or_else(|| bad("dns: short message"))?
            .try_into()
            .unwrap(),
    ))
}

// Canonical names retain length octets, so a period inside a wire label
// cannot alias a label boundary in an owner, alias or negative proof.
fn name(raw: &[u8], mut pos: usize) -> io::Result<(Vec<u8>, usize)> {
    let mut end = None;
    let mut result = Vec::new();
    let mut hops = 0;
    loop {
        let len = usize::from(*raw.get(pos).ok_or_else(|| bad("dns: truncated name"))?);
        if len & 0xc0 == 0xc0 {
            let to = usize::from(u16_at(raw, pos)? & 0x3fff);
            if to < 12 || to >= pos || hops >= 128 {
                return Err(bad("dns: invalid name pointer"));
            }
            end.get_or_insert(pos + 2);
            hops += 1;
            pos = to;
        } else if len > 63 || result.len() + 1 + len > 255 {
            return Err(bad("dns: invalid name"));
        } else {
            pos += 1;
            result.push(len as u8);
            if len == 0 {
                return Ok((result, end.unwrap_or(pos)));
            }
            let label = raw
                .get(pos..pos + len)
                .ok_or_else(|| bad("dns: truncated label"))?;
            result.extend(label.iter().map(u8::to_ascii_lowercase));
            pos += len;
        }
    }
}

pub fn build_query(host: &str, kind: u16, id: u16) -> io::Result<Vec<u8>> {
    let name = host.trim().strip_suffix('.').unwrap_or(host.trim());
    let mut raw = vec![0; 12];
    raw[..2].copy_from_slice(&id.to_be_bytes());
    raw[2] = 1;
    raw[5] = 1;
    if name.is_empty() && host.trim() != "." {
        return Err(bad("dns: bad name"));
    }
    for label in name.split('.').filter(|_| !name.is_empty()) {
        if label.is_empty() || label.len() > 63 {
            return Err(bad("dns: bad label length"));
        }
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
    }
    if raw.len() - 12 >= 255 {
        return Err(bad("dns: name is too long"));
    }
    raw.push(0);
    raw.extend_from_slice(&kind.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    Ok(raw)
}

#[derive(PartialEq, Eq)]
pub(crate) struct Question {
    pub name: Vec<u8>,
    pub kind: u16,
    pub class: u16,
    pub end: usize,
}
fn question(raw: &[u8]) -> io::Result<Question> {
    if raw.len() > 65535 || u16_at(raw, 4)? != 1 {
        return Err(bad("dns: expected one question"));
    }
    let (name, end) = name(raw, 12)?;
    Ok(Question {
        name,
        kind: u16_at(raw, end)?,
        class: u16_at(raw, end + 2)?,
        end: end + 4,
    })
}
pub(crate) fn query(raw: &[u8]) -> io::Result<Question> {
    let q = question(raw)?;
    if u16_at(raw, 2)? & 0xf800 != 0
        || u16_at(raw, 6)? != 0
        || u16_at(raw, 8)? != 0
        || q.name.len() + 16 != q.end
    {
        return Err(bad("dns: expected standard query"));
    }
    Ok(q)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}
struct Rr {
    section: Section,
    owner: Vec<u8>,
    kind: u16,
    class: u16,
    ttl_off: usize,
    rdata: Range<usize>,
}
fn records(
    raw: &[u8],
    q: &Question,
    mut visit: impl FnMut(Rr) -> io::Result<()>,
) -> io::Result<()> {
    let mut pos = q.end;
    for (section, off) in [
        (Section::Answer, 6),
        (Section::Authority, 8),
        (Section::Additional, 10),
    ] {
        for _ in 0..u16_at(raw, off)? {
            let (owner, end) = name(raw, pos)?;
            let rdata = end + 10..end + 10 + usize::from(u16_at(raw, end + 8)?);
            if rdata.end > raw.len() {
                return Err(bad("dns: truncated record"));
            }
            pos = rdata.end;
            visit(Rr {
                section,
                owner,
                kind: u16_at(raw, end)?,
                class: u16_at(raw, end + 2)?,
                ttl_off: end + 4,
                rdata,
            })?;
        }
    }
    if pos != raw.len() {
        return Err(bad("dns: trailing bytes"));
    }
    Ok(())
}
pub(crate) fn query_key(raw: &[u8], q: &Question) -> io::Result<Option<Vec<u8>>> {
    let mut signed = false;
    records(raw, q, |rr| {
        signed |= rr.kind == 250;
        Ok(())
    })?;
    if signed {
        return Err(bad("dns: unsupported signed query"));
    }
    if raw.len() > 4096 {
        return Ok(None);
    }
    let mut key = raw.to_vec();
    key[..2].fill(0);
    key[12..q.end - 4].copy_from_slice(&q.name);
    Ok(Some(key))
}
pub(crate) fn validate_response(raw: &[u8], request: &[u8], q: &Question) -> io::Result<()> {
    let answer = question(raw)?;
    if raw.get(..2) != request.get(..2)
        || u16_at(raw, 2)? & 0xf800 != 0x8000
        || q.end != answer.end
        || q.name != answer.name
        || q.kind != answer.kind
        || q.class != answer.class
    {
        return Err(bad("dns: response does not match request"));
    }
    records(raw, &answer, |_| Ok(()))
}

pub fn first_ipv4(raw: &[u8]) -> io::Result<Ipv4Addr> {
    resolved_addresses(raw, 1)?
        .into_iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| bad("dns: no A record"))
}

/// Return the ordered CNAME chain (without the question) and the complete
/// terminal IN A RRset. The caller may query the last alias if its A records
/// are absent. NXDOMAIN and an authoritative negative proof return NotFound.
pub fn exact_ipv4_step(raw: &[u8]) -> io::Result<(Vec<String>, Vec<Ipv4Addr>)> {
    let (chain, ips) = exact_address_step(raw, 1)?;
    Ok((
        chain,
        ips.into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V4(v) = ip {
                    Some(v)
                } else {
                    None
                }
            })
            .collect(),
    ))
}

/// Validate one complete DNS answer for the requested address family.
pub fn exact_address_step(
    raw: &[u8],
    kind: u16,
) -> io::Result<(Vec<String>, Vec<std::net::IpAddr>)> {
    use std::collections::HashMap;
    #[derive(Default)]
    struct Owner {
        alias: Option<Vec<u8>>,
        addresses: Vec<std::net::IpAddr>,
    }
    let q = question(raw)?;
    let flags = u16_at(raw, 2)?;
    if flags & 0xfa00 != 0x8000 || !matches!(kind, 1 | 28) || q.kind != kind || q.class != 1 {
        return Err(bad("dns: expected a complete address response"));
    }
    let count =
        usize::from(u16_at(raw, 6)?) + usize::from(u16_at(raw, 8)?) + usize::from(u16_at(raw, 10)?);
    if count > 512 {
        return Err(bad("dns: too many resource records"));
    }
    let mut owners: HashMap<Vec<u8>, Owner> = HashMap::new();
    let mut negative = Vec::new();
    let mut rcode = flags & 15;
    records(raw, &q, |rr| {
        if rr.kind == 41 {
            rcode |= ((u32_at(raw, rr.ttl_off)? >> 24) as u16) << 4;
        }
        if rr.class != 1 {
            return Ok(());
        }
        if rr.section == Section::Authority && rr.kind == 6 {
            let (_, end) = name(raw, rr.rdata.start)?;
            let (_, end) = name(raw, end)?;
            if end + 20 != rr.rdata.end {
                return Err(bad("dns: invalid negative SOA"));
            }
            negative.push(rr.owner);
        } else if rr.section == Section::Answer && (rr.kind == kind || rr.kind == 5) {
            let node = owners.entry(rr.owner).or_default();
            if rr.kind == kind {
                let bytes = &raw[rr.rdata];
                let ip = if kind == 1 {
                    std::net::IpAddr::from(
                        <[u8; 4]>::try_from(bytes)
                            .map_err(|_| bad("dns: invalid A record length"))?,
                    )
                } else {
                    std::net::IpAddr::from(
                        <[u8; 16]>::try_from(bytes)
                            .map_err(|_| bad("dns: invalid AAAA record length"))?,
                    )
                };
                if node.alias.is_some() {
                    return Err(bad("dns: owner has both A and CNAME"));
                }
                node.addresses.push(ip);
            } else {
                let to = alias(raw, rr.rdata)?;
                if !node.addresses.is_empty() || node.alias.as_ref().is_some_and(|v| v != &to) {
                    return Err(bad("dns: conflicting CNAME"));
                }
                node.alias = Some(to);
            }
        }
        Ok(())
    })?;
    match rcode {
        0 => (),
        3 => return Err(io::Error::new(io::ErrorKind::NotFound, "dns: NXDOMAIN")),
        other => return Err(io::Error::other(format!("dns: response code {other}"))),
    }
    let mut owner = q.name.as_slice();
    let mut aliases = Vec::new();
    let mut seen = HashSet::new();
    while let Some(target) = owners.get(owner).and_then(|node| node.alias.as_deref()) {
        if aliases.len() == 16 || !seen.insert(owner) {
            return Err(bad("dns: invalid CNAME chain"));
        }
        aliases.push(display_name(target).trim_end_matches('.').to_owned());
        owner = target;
    }
    let mut addresses = owners
        .get(owner)
        .map(|v| v.addresses.clone())
        .unwrap_or_default();
    if addresses.is_empty() && negative.iter().any(|zone| subdomain(owner, zone)) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "dns: no A records"));
    }
    addresses.sort_unstable();
    addresses.dedup();
    Ok((aliases, addresses))
}

/// TTL of a negative address answer with an authority SOA covering its terminal name.
/// Answer records, if present, must all belong to the question's CNAME chain.
pub fn address_negative_ttl(raw: &[u8], kind: u16) -> io::Result<Option<u32>> {
    if !matches!(u16_at(raw, 2)? & 15, 0 | 3) {
        return Ok(None);
    }
    match exact_address_step(raw, kind) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => return Ok(None),
        Err(error) => return Err(error),
    }
    if u16_at(raw, 6)? != 0 {
        let q = question(raw)?;
        let mut aliases = std::collections::HashMap::new();
        records(raw, &q, |rr| {
            if rr.section == Section::Answer {
                if rr.class != q.class || rr.kind != 5 {
                    return Err(bad("dns: negative answer contains non-CNAME data"));
                }
                aliases.insert(rr.owner, alias(raw, rr.rdata)?);
            }
            Ok(())
        })?;
        if aliases.len() > 16 {
            return Ok(None);
        }
        let mut owner = q.name;
        for _ in 0..aliases.len() {
            let Some(target) = aliases.remove(&owner) else {
                return Ok(None);
            };
            owner = target;
        }
    }
    Ok(lifetime(raw, u32::MAX)?.map(|timing| timing.seconds))
}

/// Only return addresses belonging to the question's terminal CNAME.
pub fn resolved_addresses(raw: &[u8], kind: u16) -> io::Result<Vec<std::net::IpAddr>> {
    let flags = u16_at(raw, 2)?;
    if flags & 0x8000 == 0 {
        return Err(bad("dns: expected a response"));
    }
    if flags & 15 != 0 {
        return Err(bad(match flags & 15 {
            1 => "dns: format error",
            2 => "dns: server failure",
            3 => "dns: NXDOMAIN",
            5 => "dns: refused",
            _ => "dns: rcode error",
        }));
    }
    let q = question(raw)?;
    let mut a = Vec::new();
    let mut aliases = Vec::new();
    records(raw, &q, |rr| {
        if rr.section != Section::Answer || rr.class != q.class {
            return Ok(());
        }
        match (rr.kind, rr.rdata.len()) {
            (1, 4) if kind == 1 => a.push((
                rr.owner,
                std::net::IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[rr.rdata]).unwrap())),
            )),
            (28, 16) if kind == 28 => a.push((
                rr.owner,
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&raw[rr.rdata]).unwrap(),
                )),
            )),
            (5, _) => aliases.push((rr.owner, alias(raw, rr.rdata)?)),
            _ => (),
        }
        Ok(())
    })?;
    let owner = terminal(&q.name, &aliases).ok_or_else(|| bad("dns: alias loop"))?;
    Ok(a.into_iter()
        .filter(|(name, _)| name == owner)
        .map(|(_, ip)| ip)
        .collect())
}

fn display_name(wire: &[u8]) -> String {
    let mut name = String::new();
    let mut pos = 0;
    while wire[pos] > 0 {
        let size = wire[pos] as usize;
        pos += 1;
        for &b in &wire[pos..pos + size] {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_') {
                name.push(b as char);
            } else {
                use std::fmt::Write;
                write!(&mut name, "\\{b:03}").unwrap();
            }
        }
        name.push('.');
        pos += size;
    }
    name
}
pub fn query_domain(raw: &[u8]) -> io::Result<(String, u16)> {
    let q = query(raw)?;
    Ok((
        display_name(&q.name).trim_end_matches('.').to_owned(),
        q.kind,
    ))
}
pub fn response_error(raw: &[u8], rcode: u8) -> Vec<u8> {
    let Some(header) = raw.get(..12) else {
        return Vec::new();
    };
    let q = query(raw).ok();
    let mut out = vec![0; 12];
    out[..2].copy_from_slice(&header[..2]);
    out[2] = 0x80 | header[2] & 1;
    out[3] = 0x80 | rcode & 15;
    if let Some(q) = q {
        out[5] = 1;
        out.extend_from_slice(&raw[12..q.end]);
    }
    out
}
pub fn blocked_reply(raw: &[u8]) -> io::Result<Vec<u8>> {
    query(raw)?;
    let mut out = response_error(raw, 3);
    out[9] = 1;
    // The locally generated negative SOA belongs to the original question.
    out.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 60]);
    let names = b"\x02ns\x07invalid\x00\x0ahostmaster\x07invalid\x00";
    out.extend_from_slice(&((names.len() + 20) as u16).to_be_bytes());
    out.extend_from_slice(names);
    for n in [0u32, 3600, 600, 86400, 60] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    Ok(out)
}
/// Visits reachable CNAMEs, addresses and SVCB/HTTPS address hints.
pub fn visit_filter_targets<T>(
    raw: &[u8],
    mut check: impl FnMut(&str) -> Option<T>,
) -> io::Result<Option<T>> {
    visit_typed_filter_targets(raw, |name, _| check(name))
}

/// Address hints use the containing HTTPS or SVCB type. The original query
/// type can differ from the type of every record in a CNAME chain.
pub fn visit_typed_filter_targets<T>(
    raw: &[u8],
    mut check: impl FnMut(&str, u16) -> Option<T>,
) -> io::Result<Option<T>> {
    let q = question(raw)?;
    if u16_at(raw, 6)? == 0 {
        return Ok(None);
    }
    enum Target {
        Alias(Vec<u8>),
        Addresses {
            data: Range<usize>,
            width: usize,
            kind: u16,
        },
    }
    let mut links = std::collections::HashMap::<Vec<u8>, Vec<Target>>::new();
    let mut bytes = 0;
    records(raw, &q, |rr| {
        if rr.section != Section::Answer
            || rr.class != q.class
            || !matches!(rr.kind, 1 | 5 | 28 | 64 | 65)
        {
            return Ok(());
        }
        bytes += rr.owner.len() + std::mem::size_of::<Target>();
        let out = links.entry(rr.owner).or_default();
        match rr.kind {
            5 => {
                let target = alias(raw, rr.rdata)?;
                bytes += target.len();
                out.push(Target::Alias(target));
            }
            1 | 28 => {
                let width = if rr.kind == 1 { 4 } else { 16 };
                if rr.rdata.len() != width {
                    return Err(bad("dns: invalid address record"));
                }
                out.push(Target::Addresses {
                    data: rr.rdata,
                    width,
                    kind: rr.kind,
                });
            }
            _ => {
                let (_, mut pos) = name(raw, rr.rdata.start + 2)?;
                if pos > rr.rdata.end {
                    return Err(bad("dns: invalid service target"));
                }
                while pos < rr.rdata.end {
                    let key = u16_at(raw, pos)?;
                    let len = u16_at(raw, pos + 2)? as usize;
                    pos += 4;
                    let end = pos + len;
                    if end > rr.rdata.end {
                        return Err(bad("dns: invalid service parameter"));
                    }
                    if matches!(key, 4 | 6) {
                        let width = if key == 4 { 4 } else { 16 };
                        if len == 0 || !len.is_multiple_of(width) {
                            return Err(bad("dns: invalid address hint"));
                        }
                        out.push(Target::Addresses {
                            data: pos..end,
                            width,
                            kind: rr.kind,
                        });
                        bytes += std::mem::size_of::<Target>();
                    }
                    pos = end;
                }
            }
        }
        if bytes > 512 * 1024 {
            return Err(bad("dns: excessive answer target data"));
        }
        Ok(())
    })?;
    let mut queue = vec![q.name.as_slice()];
    let mut visited = HashSet::from([q.name.as_slice()]);
    while let Some(owner) = queue.pop() {
        if let Some(targets) = links.get(owner) {
            for target in targets {
                match target {
                    Target::Alias(name) if visited.insert(name.as_slice()) => {
                        if let Some(v) = check(display_name(name).trim_end_matches('.'), 5) {
                            return Ok(Some(v));
                        }
                        queue.push(name);
                    }
                    Target::Addresses { data, width, kind } => {
                        for addr in raw[data.clone()].chunks_exact(*width) {
                            let ip = if *width == 4 {
                                Ipv4Addr::from(<[u8; 4]>::try_from(addr).unwrap()).to_string()
                            } else {
                                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(addr).unwrap())
                                    .to_string()
                            };
                            if let Some(v) = check(&ip, *kind) {
                                return Ok(Some(v));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(None)
}
pub fn udp_answer(request: &[u8], response: Vec<u8>) -> Vec<u8> {
    if response.len() <= 512 {
        return response;
    }
    let mut limit = 512usize;
    if let Ok(q) = query(request) {
        let _ = records(request, &q, |rr| {
            if rr.kind == 41 {
                limit = usize::from(rr.class).clamp(512, 1232);
            }
            Ok(())
        });
    }
    if response.len() <= limit {
        return response;
    }
    let mut cut = response_error(request, response.get(3).copied().unwrap_or(2) & 15);
    if cut.len() >= 12 {
        cut[2] |= 2;
    }
    cut
}
pub fn cap_ttls(raw: &mut [u8], limit: u32) -> io::Result<()> {
    let mut updates = Vec::new();
    records(raw, &question(raw)?, |rr| {
        if rr.kind != 41 && u32_at(raw, rr.ttl_off)? > limit {
            updates.push(rr.ttl_off);
        }
        Ok(())
    })?;
    for pos in updates {
        raw[pos..pos + 4].copy_from_slice(&limit.to_be_bytes());
    }
    Ok(())
}
pub fn answer_records(raw: &[u8]) -> io::Result<Vec<String>> {
    let q = question(raw)?;
    let mut out = Vec::new();
    records(raw, &q, |rr| {
        if rr.section != Section::Answer {
            return Ok(());
        }
        let bytes = &raw[rr.rdata.clone()];
        let (kind, data) = match (rr.kind, bytes.len()) {
            (1, 4) => (
                "A".into(),
                Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()).to_string(),
            ),
            (28, 16) => (
                "AAAA".into(),
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string(),
            ),
            (5, _) => ("CNAME".into(), display_name(&alias(raw, rr.rdata)?)),
            (kind, _) => {
                use std::fmt::Write;
                let mut data = format!("\\# {} ", bytes.len());
                for b in bytes {
                    write!(data, "{b:02X}").unwrap();
                }
                (format!("TYPE{kind}"), data)
            }
        };
        let class = if rr.class == 1 {
            "IN".into()
        } else {
            format!("CLASS{}", rr.class)
        };
        out.push(format!(
            "{}\t{}\t{class}\t{kind}\t{data}",
            display_name(&rr.owner),
            u32_at(raw, rr.ttl_off)?
        ));
        Ok(())
    })?;
    Ok(out)
}
fn alias(raw: &[u8], span: Range<usize>) -> io::Result<Vec<u8>> {
    let (target, end) = name(raw, span.start)?;
    if end != span.end {
        return Err(bad("dns: invalid alias"));
    }
    Ok(target)
}
fn terminal<'a>(start: &'a [u8], aliases: &'a [(Vec<u8>, Vec<u8>)]) -> Option<&'a [u8]> {
    let mut owner = start;
    let mut visited = HashSet::new();
    for _ in 0..16 {
        if !visited.insert(owner) {
            return None;
        }
        match aliases.iter().find(|(from, _)| from == owner) {
            Some((_, to)) => owner = to,
            None => return Some(owner),
        }
    }
    None
}
fn subdomain(mut name: &[u8], zone: &[u8]) -> bool {
    while let Some(&len) = name.first() {
        if name == zone {
            return true;
        }
        name = &name[1 + len as usize..];
    }
    false
}

pub(crate) struct Lifetime {
    pub seconds: u32,
    /// Header TTL offsets and original (SOA-clipped for negative answers) values.
    pub ttls: Vec<(usize, u32)>,
}
pub(crate) fn lifetime(raw: &[u8], maximum: u32) -> io::Result<Option<Lifetime>> {
    if raw.len() > 4096 || maximum == 0 {
        return Ok(None);
    }
    response_ttls(raw, maximum).map(|timing| timing.filter(|timing| timing.seconds > 0))
}

/// Apply RFC 2308 to a fresh negative response before delivering it.
pub fn clip_negative_soa(raw: &mut [u8]) -> io::Result<()> {
    if let Some(timing) = response_ttls(raw, u32::MAX)? {
        for (offset, ttl) in timing.ttls {
            raw[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
        }
    }
    Ok(())
}

fn response_ttls(raw: &[u8], maximum: u32) -> io::Result<Option<Lifetime>> {
    let flags = u16_at(raw, 2)?;
    if !matches!(flags & 15, 0 | 3) || flags & 0x0200 != 0 {
        return Ok(None);
    }
    let q = question(raw)?;
    if q.end != q.name.len() + 16 {
        return Ok(None);
    }
    let mut aliases = Vec::new();
    let mut positive_owners = Vec::new();
    let mut soas = Vec::new();
    let mut ttls = Vec::new();
    let mut seconds = maximum;
    let mut unsupported = false;
    records(raw, &q, |rr| {
        if rr.kind == 41 {
            // The top byte carries the extended RCODE. Leave EDNS flags intact.
            unsupported |= u32_at(raw, rr.ttl_off)? >> 24 != 0;
            return Ok(());
        }
        let ttl = u32_at(raw, rr.ttl_off)?;
        ttls.push((rr.ttl_off, ttl));
        seconds = seconds.min(ttl);
        unsupported |= rr.kind == 250;
        if rr.section == Section::Authority && rr.kind == 6 {
            let (_, end) = name(raw, rr.rdata.start)?;
            let (_, end) = name(raw, end)?;
            if end + 20 != rr.rdata.end {
                return Err(bad("dns: invalid SOA length"));
            }
            soas.push((
                rr.owner,
                rr.class,
                ttl.min(u32_at(raw, end + 16)?),
                ttls.len() - 1,
            ));
            return Ok(());
        }
        if rr.class != q.class {
            return Ok(());
        }
        if rr.section == Section::Answer {
            if rr.kind == q.kind || (q.kind == 255 && rr.kind != 46) {
                positive_owners.push(rr.owner.clone());
            }
            if rr.kind == 5 {
                aliases.push((rr.owner, alias(raw, rr.rdata)?));
            }
        }
        Ok(())
    })?;
    let Some(owner) = terminal(&q.name, &aliases) else {
        return Ok(None);
    };
    if unsupported {
        return Ok(None);
    }
    if flags & 15 == 3 || !positive_owners.iter().any(|o| o == owner || o == &q.name) {
        let mut proof = false;
        for (zone, class, limit, idx) in soas {
            ttls[idx].1 = limit;
            if class == q.class && subdomain(owner, &zone) {
                proof = true;
                seconds = seconds.min(limit);
            }
        }
        if !proof {
            seconds = 0;
        }
    }
    Ok(Some(Lifetime { seconds, ttls }))
}
