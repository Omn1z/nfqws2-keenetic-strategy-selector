//! Addresses a client can use from a matched DNS reply. Record owners use
//! their canonical wire representation, including label boundaries.
use super::*;
use std::{collections::HashMap, net::IpAddr};

pub const MAX_ROUTE_ANSWER_ADDRESSES: usize = 128;
pub const MAX_ROUTE_ANSWER_TTL: u32 = 300;

#[derive(Debug, PartialEq, Eq)]
pub struct RouteAnswer {
    pub qtype: u16,
    pub addresses: Vec<IpAddr>,
    pub ttl: u32,
}

pub struct TraceAnswer {
    pub qtype: u16,
    pub addresses: Vec<IpAddr>,
    pub sinkholed: bool,
}
struct Node {
    alias: Option<Vec<u8>>,
    addresses: Vec<IpAddr>,
    services: Vec<Vec<u8>>,
    ttl: u32,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            alias: None,
            addresses: vec![],
            services: vec![],
            ttl: u32::MAX,
        }
    }
}
impl Node {
    fn add(&mut self, ip: IpAddr) -> io::Result<()> {
        if !self.addresses.contains(&ip) {
            if self.addresses.len() == MAX_ROUTE_ANSWER_ADDRESSES {
                return Err(bad("dns: more than 128 distinct route addresses"));
            }
            self.addresses.push(ip);
        }
        Ok(())
    }
}
fn address(bytes: &[u8]) -> io::Result<IpAddr> {
    match bytes.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).unwrap(),
        ))),
        16 => Ok(IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        ))),
        _ => Err(bad("dns: invalid route address")),
    }
}
fn service_target(raw: &[u8], rr: &Range<usize>) -> io::Result<(u16, Vec<u8>, usize)> {
    if rr.len() < 3 {
        return Err(bad("dns: short service binding"));
    }
    let priority = u16_at(raw, rr.start)?;
    let (target, pos) = name(raw, rr.start + 2)?;
    if pos > rr.end {
        return Err(bad("dns: invalid service target"));
    }
    Ok((priority, target, pos))
}
fn service(raw: &[u8], rr: &Range<usize>, node: &mut Node) -> io::Result<()> {
    let (priority, target, pos) = service_target(raw, rr)?;
    if priority == 0 {
        if target == [0]
            || !node.services.is_empty()
            || !node.addresses.is_empty()
            || node
                .alias
                .as_ref()
                .is_some_and(|previous| previous != &target)
        {
            return Err(bad("dns: conflicting service alias"));
        }
        node.alias = Some(target);
    } else if !node.services.contains(&target) {
        node.services.push(target);
    }
    for ip in service_hints(raw, pos, rr.end, priority)? {
        node.add(ip)?;
    }
    Ok(())
}
fn service_hints(raw: &[u8], mut pos: usize, end: usize, priority: u16) -> io::Result<Vec<IpAddr>> {
    let mut hints = Vec::new();
    let mut last = None;
    while pos < end {
        if end - pos < 4 {
            return Err(bad("dns: short service parameters"));
        }
        let key = u16_at(raw, pos)?;
        let len = usize::from(u16_at(raw, pos + 2)?);
        pos += 4;
        if pos + len > end || last.is_some_and(|k| k >= key) {
            return Err(bad("dns: invalid service parameters"));
        }
        if priority != 0 && matches!(key, 4 | 6) {
            let width = if key == 4 { 4 } else { 16 };
            if len == 0 || !len.is_multiple_of(width) {
                return Err(bad("dns: invalid address hint"));
            }
            for bytes in raw[pos..pos + len].chunks_exact(width) {
                hints.push(address(bytes)?);
            }
        }
        pos += len;
        last = Some(key);
    }
    Ok(hints)
}

/// Trace the upstream answer, including null routes and service binding hints.
/// Learning still uses only destinations reachable from the question owner.
pub fn trace_answer(raw: &[u8]) -> io::Result<TraceAnswer> {
    let q = question(raw)?;
    let flags = u16_at(raw, 2)?;
    if flags & 0xfa00 != 0x8000 {
        return Err(bad("dns: expected a complete trace response"));
    }
    let count = u16_at(raw, 6)?;
    let mut addresses = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |ip: IpAddr| {
        let ip = ip.to_canonical();
        if seen.insert(ip) {
            addresses.push(ip);
        }
    };
    records(raw, &q, |rr| {
        if rr.section == Section::Answer {
            match rr.kind {
                1 if rr.rdata.len() == 4 => add(address(&raw[rr.rdata])?),
                28 if rr.rdata.len() == 16 => add(address(&raw[rr.rdata])?),
                64 | 65 => {
                    if let Ok((priority, _, pos)) = service_target(raw, &rr.rdata) {
                        if let Ok(hints) = service_hints(raw, pos, rr.rdata.end, priority) {
                            hints.into_iter().for_each(&mut add);
                        }
                    }
                }
                _ => (),
            }
        }
        Ok(())
    })?;
    let sinkholed = match flags & 15 {
        3 => true,
        0 => count == 0 || !addresses.is_empty() && addresses.iter().all(IpAddr::is_unspecified),
        _ => false,
    };
    Ok(TraceAnswer {
        qtype: q.kind,
        addresses,
        sinkholed,
    })
}
/// Negative answers and null sinkholes provide no usable destinations.
/// The TTL covers the shortest link from the question to the address and is
/// also applied to the outgoing answer, so clients revalidate the route.
pub fn route_answer(raw: &[u8]) -> io::Result<Option<RouteAnswer>> {
    let q = question(raw)?;
    let flags = u16_at(raw, 2)?;
    if flags & 0xfa00 != 0x8000 {
        return Err(bad("dns: expected a complete response"));
    }
    if q.class != 1 {
        return Ok(None);
    }
    let count = [6, 8, 10]
        .into_iter()
        .try_fold(0usize, |n, p| u16_at(raw, p).map(|v| n + usize::from(v)))?;
    if count > 512 {
        return Err(bad("dns: excessive route answer records"));
    }
    let mut owners = HashMap::<Vec<u8>, Node>::new();
    let mut glue = HashMap::<Vec<u8>, Node>::new();
    let mut ok = flags & 15 == 0;
    records(raw, &q, |rr| {
        if rr.kind == 41 {
            ok &= u32_at(raw, rr.ttl_off)? >> 24 == 0;
            return Ok(());
        }
        if !ok {
            return Ok(());
        }
        if rr.class != 1 {
            return Ok(());
        }
        let table = match rr.section {
            Section::Answer if matches!(rr.kind, 1 | 5 | 28 | 64 | 65) => &mut owners,
            Section::Additional if matches!(rr.kind, 1 | 28) => &mut glue,
            _ => return Ok(()),
        };
        if matches!(rr.kind, 64 | 65) && q.kind != 255 && q.kind != rr.kind {
            return Ok(());
        }
        let node = table.entry(rr.owner).or_default();
        node.ttl = node.ttl.min(u32_at(raw, rr.ttl_off)?);
        if rr.kind == 5 {
            let next = alias(raw, rr.rdata)?;
            if !node.addresses.is_empty()
                || !node.services.is_empty()
                || node.alias.as_ref().is_some_and(|v| v != &next)
            {
                return Err(bad("dns: conflicting routing CNAME"));
            }
            node.alias = Some(next);
        } else {
            if node.alias.is_some() {
                return Err(bad("dns: CNAME alongside route records"));
            }
            match rr.kind {
                1 | 28 => {
                    if rr.rdata.len() != if rr.kind == 1 { 4 } else { 16 } {
                        return Err(bad("dns: invalid address record"));
                    }
                    node.add(address(&raw[rr.rdata])?)?;
                }
                _ => service(raw, &rr.rdata, node)?,
            }
        }
        Ok(())
    })?;
    if !ok {
        // No IP may be installed for NXDOMAIN or another failure. A matched
        // IPv4-only policy can still suppress AAAA and verify readiness.
        return Ok(Some(RouteAnswer {
            qtype: q.kind,
            addresses: Vec::new(),
            ttl: 0,
        }));
    }
    let mut current = &q.name;
    let mut chain = HashSet::new();
    let mut addresses = std::collections::BTreeSet::new();
    let mut ttl = MAX_ROUTE_ANSWER_TTL;
    while let Some(node) = owners.get(current) {
        if !chain.insert(current) || chain.len() > 17 {
            return Err(bad("dns: routing alias cycle or chain too long"));
        }
        ttl = ttl.min(node.ttl);
        if let Some(to) = &node.alias {
            current = to;
            continue;
        }
        addresses.extend(node.addresses.iter().copied());
        if matches!(q.kind, 64 | 65 | 255) {
            // Only named targets of the selected binding may supply glue.
            // A "." service target uses its own owner name.
            for name in &node.services {
                let target = if name.as_slice() == [0] {
                    current
                } else {
                    name
                };
                if let Some(data) = glue.get(target) {
                    ttl = ttl.min(data.ttl);
                    addresses.extend(data.addresses.iter().copied());
                    if addresses.len() > MAX_ROUTE_ANSWER_ADDRESSES {
                        return Err(bad("dns: more than 128 distinct route addresses"));
                    }
                }
            }
        }
        break;
    }
    addresses.retain(|ip| !ip.is_unspecified());
    if addresses.len() > MAX_ROUTE_ANSWER_ADDRESSES {
        return Err(bad("dns: more than 128 distinct route addresses"));
    }
    Ok(Some(RouteAnswer {
        qtype: q.kind,
        addresses: addresses.into_iter().collect(),
        ttl,
    }))
}

#[cfg(test)]
mod trace_tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn reply(qtype: u16, rcode: u8, records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut wire = build_query("trace.example", qtype, 7).unwrap();
        wire[2..4].copy_from_slice(&[0x81, 0x80 | rcode]);
        wire[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for (kind, data) in records {
            wire.extend([0xc0, 12]);
            wire.extend(kind.to_be_bytes());
            wire.extend([0, 1, 0, 0, 0, 60]);
            wire.extend((data.len() as u16).to_be_bytes());
            wire.extend(*data);
        }
        wire
    }

    #[test]
    fn mixed_addresses_keep_their_first_wire_position_for_a_and_aaaa_questions() {
        let first: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let last: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v4 = [192, 0, 2, 8];
        for qtype in [1, 28] {
            let packet = reply(
                qtype,
                0,
                &[
                    (28, &first.octets()),
                    (1, &v4),
                    (28, &first.octets()),
                    (28, &last.octets()),
                    (1, &v4),
                ],
            );
            let trace = trace_answer(&packet).unwrap();
            assert_eq!(trace.qtype, qtype);
            assert_eq!(trace.addresses, [IpAddr::V6(first), v4.into(), last.into()]);
            assert!(!trace.sinkholed);
        }
    }

    #[test]
    fn service_hints_share_deduplication_with_address_records_and_ignore_glue() {
        let a = [192, 0, 2, 10];
        let b = [192, 0, 2, 9];
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut hints = vec![0, 1, 0, 0, 4, 0, 8];
        hints.extend(a);
        hints.extend(b);
        hints.extend([0, 6, 0, 16]);
        hints.extend(v6.octets());
        for kind in [64, 65] {
            let mut packet = reply(
                kind,
                0,
                &[
                    (1, &a),
                    (kind, &hints),
                    (28, &v6.octets()),
                    (1, &[192, 0, 2, 7]),
                    (1, &[192, 0, 2, 6]),
                ],
            );
            // The last two records belong to the authority and additional sections.
            packet[6..12].copy_from_slice(&[0, 3, 0, 1, 0, 1]);
            let trace = trace_answer(&packet).unwrap();
            assert_eq!(trace.qtype, kind);
            assert_eq!(trace.addresses, [IpAddr::from(a), b.into(), v6.into()]);
            assert!(!trace.sinkholed);
        }
    }

    #[test]
    fn trace_can_report_a_large_tcp_answer_without_enlarging_route_learning() {
        let addresses: Vec<_> = (0u16..513)
            .map(|n| {
                let [high, low] = n.to_be_bytes();
                [198, 18, high, low]
            })
            .collect();
        let records: Vec<_> = addresses.iter().map(|ip| (1, ip.as_slice())).collect();
        let packet = reply(1, 0, &records);
        let trace = trace_answer(&packet).unwrap();
        assert_eq!(
            trace.addresses,
            addresses
                .iter()
                .copied()
                .map(IpAddr::from)
                .collect::<Vec<_>>()
        );
        assert!(route_answer(&packet).is_err());
    }

    #[test]
    fn sinkhole_depends_on_rcode_answer_count_and_all_returned_addresses() {
        let txt = b"\x03txt";
        for (rcode, records, expected) in [
            (0, vec![], true),
            (3, vec![(5, &b"\x05alias\x07example\0"[..])], true),
            (0, vec![(16, &txt[..])], false),
            (2, vec![], false),
            (5, vec![], false),
        ] {
            let trace = trace_answer(&reply(16, rcode, &records)).unwrap();
            assert_eq!(trace.qtype, 16);
            assert!(trace.addresses.is_empty());
            assert_eq!(trace.sinkholed, expected);
        }
        let nulls = [IpAddr::from([0; 4]), Ipv6Addr::UNSPECIFIED.into()];
        let trace = trace_answer(&reply(28, 0, &[(1, &[0; 4]), (28, &[0; 16])])).unwrap();
        assert_eq!(trace.addresses, nulls);
        assert!(trace.sinkholed);
        let public = [192, 0, 2, 1];
        let mixed = trace_answer(&reply(1, 0, &[(1, &[0; 4]), (1, &public)])).unwrap();
        assert_eq!(mixed.addresses, [nulls[0], public.into()]);
        assert!(!mixed.sinkholed);
    }

    #[test]
    fn mapped_aaaa_uses_the_same_trace_address_as_a_including_null() {
        for ip in [Ipv4Addr::new(192, 0, 2, 4), Ipv4Addr::UNSPECIFIED] {
            let mapped = ip.to_ipv6_mapped().octets();
            let trace = trace_answer(&reply(28, 0, &[(28, &mapped), (1, &ip.octets())])).unwrap();
            assert_eq!(trace.addresses, [IpAddr::V4(ip)]);
            assert_eq!(trace.sinkholed, ip.is_unspecified());
        }
    }
}
