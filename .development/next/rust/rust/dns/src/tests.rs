use super::*;
use std::{
    net::{Ipv4Addr, TcpListener},
    thread,
};

fn owner(label: &str) -> Vec<u8> {
    let q = build_query(label, 1, 0).unwrap();
    q[12..q.len() - 4].to_vec()
}
fn rr(name: &[u8], kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
    let mut record = name.to_vec();
    for field in [kind, 1] {
        record.extend(field.to_be_bytes());
    }
    record.extend(ttl.to_be_bytes());
    record.extend((data.len() as u16).to_be_bytes());
    record.extend(data);
    record
}
fn response(q: &[u8], rcode: u8, answers: &[Vec<u8>], ns: &[Vec<u8>]) -> Vec<u8> {
    let mut packet = q.to_vec();
    packet[2] = 0x81;
    packet[3] = 0x80 | rcode;
    packet[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    packet[8..10].copy_from_slice(&(ns.len() as u16).to_be_bytes());
    for rec in answers.iter().chain(ns) {
        packet.extend(rec);
    }
    packet
}
fn positive(q: &[u8]) -> Vec<u8> {
    response(q, 0, &[rr(&[0xc0, 12], 1, 60, &[192, 0, 2, 10])], &[])
}
fn soa(zone: &str, ttl: u32, minimum: u32) -> Vec<u8> {
    let mut data = owner("ns.example");
    data.extend(owner("hostmaster.example"));
    data.extend([0; 16]);
    data.extend(minimum.to_be_bytes());
    rr(&owner(zone), 6, ttl, &data)
}
fn resolver() -> Resolver {
    Resolver::new(3, 120, Duration::from_secs(2))
}

#[test]
fn cached_route_answer_keeps_absolute_ttl_across_fractional_cache_age() {
    let resolver = resolver();
    let start = Instant::now();
    let query = build_query("existing.test", 1, 1).unwrap();
    let first = resolver
        .resolve_at(&query, "pool", |q| Ok(positive(q)), || start)
        .unwrap();
    assert_eq!(first.ttl_anchor, start);
    for millis in [750, 1_300, 59_900] {
        let request = build_query("existing.test", 1, 2).unwrap();
        let answer = resolver
            .resolve_at(
                &request,
                "pool",
                |_| panic!("fresh cache was missed"),
                || start + Duration::from_millis(millis),
            )
            .unwrap();
        let ttl = route_answer(&answer.wire).unwrap().unwrap().ttl.into();
        assert_eq!(
            answer.ttl_anchor + Duration::from_secs(ttl),
            start + Duration::from_secs(60)
        );
    }
}

#[test]
fn routing_uses_only_chain_and_service_targets_and_shortest_delivered_ttl() {
    let q = build_query("portal.test", 65, 1).unwrap();
    let mut service = vec![0, 1];
    service.extend(owner("subscriber.test"));
    service.extend([0, 4, 0, 4, 192, 0, 2, 4]);
    let mut alias_mode = vec![0, 0];
    alias_mode.extend(owner("binding.test"));
    let mut wire = response(
        &q,
        0,
        &[
            rr(&owner("binding.test"), 65, 600, &service),
            rr(&owner("local.test"), 65, 45, &alias_mode),
            rr(&[0xc0, 12], 5, 28, &owner("local.test")),
            rr(&owner("other.test"), 1, 1, &[192, 0, 2, 200]),
        ],
        &[],
    );
    wire[11] = 2;
    let v6: std::net::Ipv6Addr = "2001:db8::3".parse().unwrap();
    wire.extend(rr(&owner("subscriber.test"), 28, 20, &v6.octets()));
    wire.extend(rr(&owner("other.test"), 1, 1, &[192, 0, 2, 201]));
    let interpreted = route_answer(&wire).unwrap().unwrap();
    assert_eq!(interpreted.qtype, 65);
    assert_eq!(interpreted.ttl, 20);
    assert_eq!(
        interpreted.addresses,
        [std::net::IpAddr::from([192, 0, 2, 4]), v6.into()]
    );
}
#[test]
fn routing_rejects_partial_or_conflicting_rrsets_and_ignores_negative_replies() {
    let q = build_query("vpn.test", 1, 3).unwrap();
    let a = rr(&[0xc0, 12], 1, u32::MAX, &[192, 0, 2, 1]);
    let cname = rr(&[0xc0, 12], 5, 1, &owner("next.test"));
    let wrap = |records: Vec<Vec<u8>>| response(&q, 0, &records, &[]);
    let record = route_answer(&wrap(vec![a.clone()])).unwrap().unwrap();
    assert_eq!(record.ttl, 300);
    for rs in [
        vec![cname.clone(), a.clone()],
        vec![cname, rr(&owner("next.test"), 5, 1, &owner("vpn.test"))],
        vec![a, rr(&[0xc0, 12], 1, 20, &[192, 0, 2])],
        (0..129)
            .map(|i| rr(&[0xc0, 12], 1, 60, &[192, 0, 2, i]))
            .collect(),
    ] {
        assert!(route_answer(&wrap(rs)).is_err());
    }
    let aaaa = build_query("vpn.test", 28, 4).unwrap();
    let negative = route_answer(&response(&aaaa, 3, &[], &[]))
        .unwrap()
        .unwrap();
    assert_eq!(negative.qtype, 28);
    assert!(negative.addresses.is_empty());
    assert!(route_answer(&wrap(vec![rr(&[0xc0, 12], 1, 60, &[0; 4])]))
        .unwrap()
        .unwrap()
        .addresses
        .is_empty());
    let mut truncated = positive(&q);
    truncated[2] |= 2;
    assert!(route_answer(&truncated).is_err());
}
#[test]
fn routing_rejects_malformed_service_parameters_without_returning_earlier_hints() {
    let q = build_query("vpn.test", 65, 1).unwrap();
    let hints = [0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 3];
    for tail in [&[0][..], &[0, 6, 0, 15], &[0, 4, 0, 4, 192, 0, 2, 6]] {
        let mut data = hints.to_vec();
        data.extend(tail);
        assert!(route_answer(&response(&q, 0, &[rr(&[0xc0, 12], 65, 60, &data)], &[])).is_err());
    }
}
#[test]
fn fallback_ttl_cap_covers_every_section_and_preserves_edns_and_signed_rdata() {
    let q = build_query("www.example", 1, 9).unwrap();
    let opt = rr(&[0], 41, 0x8000, &[]);
    let sig = [0xAB; 32];
    let mut packet = response(
        &q,
        0,
        &[rr(&[192, 12], 1, 77, &[192, 0, 2, 9])],
        &[soa("example", 90, 80)],
    );
    packet[11] = 2;
    packet.extend(rr(&[192, 12], 46, 400, &sig));
    packet.extend(&opt);
    let mut expect = response(
        &q,
        0,
        &[rr(&[192, 12], 1, 30, &[192, 0, 2, 9])],
        &[soa("example", 30, 80)],
    );
    expect[11] = 2;
    expect.extend(rr(&[192, 12], 46, 30, &sig));
    expect.extend(&opt);
    cap_ttls(&mut packet, 30).unwrap();
    assert_eq!(packet, expect);
    assert_eq!(wire::lifetime(&packet, 120).unwrap().unwrap().seconds, 30);
}
#[test]
fn local_block_preserves_question_and_only_related_aliases_are_filtered() {
    let q = build_query("ExAmPle", 1, 77).unwrap();
    let a = blocked_reply(&q).unwrap();
    validate_answer(&q, &a).unwrap();
    assert_eq!(a[3] & 15, 3);
    assert_eq!(a[2] & 4, 0);
    assert_eq!(a[3] & 32, 0);
    assert_eq!(&a[12..q.len()], &q[12..]);
    assert_eq!(wire::lifetime(&a, 120).unwrap().unwrap().seconds, 60);
    let chain = [
        rr(&owner("decoy"), 5, 60, &owner("unrelated")),
        rr(&owner("middle"), 5, 60, &owner("track.test")),
        rr(&[192, 12], 5, 60, &owner("middle")),
        rr(&owner("track.test"), 5, 60, &owner("middle")),
    ];
    let wire = response(&q, 0, &chain, &[]);
    let mut seen = Vec::new();
    visit_filter_targets(&wire, |s| {
        seen.push(s.to_owned());
        None::<()>
    })
    .unwrap();
    assert_eq!(seen, ["middle", "track.test"]);
    let hints = [
        0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 7, 0, 6, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    let wire = response(
        &q,
        0,
        &[
            rr(&[192, 12], 65, 60, &hints),
            rr(&owner("else"), 1, 60, &[192, 0, 2, 8]),
        ],
        &[],
    );
    let mut seen = Vec::new();
    visit_filter_targets(&wire, |s| {
        seen.push(s.to_owned());
        None::<()>
    })
    .unwrap();
    assert_eq!(seen, ["192.0.2.7", "::1"]);
    let wire = response(
        &q,
        0,
        &[
            rr(&[192, 12], 1, 60, &[192, 0, 2, 1]),
            rr(&[192, 12], 28, 60, &[0; 16]),
            rr(&[192, 12], 64, 60, &hints),
            rr(&[192, 12], 65, 60, &hints),
            rr(&[192, 12], 5, 60, &owner("alias.example")),
        ],
        &[],
    );
    let mut kinds = Vec::new();
    visit_typed_filter_targets(&wire, |_, kind| {
        kinds.push(kind);
        None::<()>
    })
    .unwrap();
    assert_eq!(kinds, [1, 28, 64, 64, 65, 65, 5]);
    let root = build_query(".", 2, 4).unwrap();
    assert_eq!(&root[12..], &[0, 0, 2, 0, 1]);
    assert!(validate_answer(&q, &root).is_err());
}
#[test]
fn wire_limits_and_memory_budget_on_large_answers() {
    let r = Resolver::new(32, 120, Duration::from_secs(1));
    for i in 0..32 {
        let q = build_query(&format!("a{i}.example"), 16, 125).unwrap();
        let large = rr(&[192, 12], 16, 300, &vec![17; 3800]);
        let wire = response(&q, 0, &[large], &[]);
        let out = r.exchange_with(&q, "pool", |_| Ok(wire)).unwrap();
        let capped = udp_answer(&q, out.wire);
        assert!(capped.len() <= 512 && capped[2] & 2 != 0);
        assert_eq!(query_domain(&q).unwrap().1, 16);
    }
    let occupied = r.cache.lock().unwrap().bytes;
    assert!(occupied <= 32 * 1024);
    assert!((1..32).contains(&r.status().entries));
    r.clear();
    assert_eq!(r.cache.lock().unwrap().bytes, 0);
}

#[test]
fn parses_standard_question_alias_and_original_answer_owner() {
    let q = build_query("www.example.", 1, 0x1234).unwrap();
    assert_eq!(&q[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&q[12..], b"\x03www\x07example\x00\x00\x01\x00\x01");
    let records = [
        rr(&owner("other.example"), 1, 1, &[192, 0, 2, 1]),
        rr(&[0xc0, 12], 5, 35, &owner("alias.example")),
        rr(&owner("alias.example"), 1, 40, &[203, 0, 113, 2]),
    ];
    assert_eq!(
        first_ipv4(&response(&q, 0, &records, &[])).unwrap(),
        Ipv4Addr::new(203, 0, 113, 2)
    );
    let q6 = build_query("www.example", 28, 16).unwrap();
    let address = "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap();
    let aliases = [
        rr(&owner("unrelated.example"), 28, 60, &[0; 16]),
        rr(&[0xc0, 12], 5, 60, &owner("alias.example")),
        rr(&owner("alias.example"), 28, 60, &address.octets()),
    ];
    assert_eq!(
        resolved_addresses(&response(&q6, 0, &aliases, &[]), 28).unwrap(),
        vec![std::net::IpAddr::V6(address)]
    );
    for name in [
        "".into(),
        "invalid..example".into(),
        "a".repeat(64),
        vec!["a".repeat(63); 4].join("."),
    ] {
        assert!(build_query(&name, 1, 1).is_err());
    }
    let bad_alias = rr(&[0xc0, 12], 5, 35, &[0xc0, 12]);
    assert!(first_ipv4(&response(&q, 0, &[bad_alias], &[])).is_err());
    assert!(first_ipv4(&response(&q, 3, &[], &[]))
        .unwrap_err()
        .to_string()
        .contains("NXDOMAIN"));
}
#[test]
fn positive_cache_ages_ttls_rewrites_id_and_preserves_query_options_and_scope() {
    let r = resolver();
    let now = Instant::now();
    let q = build_query("Host.Example", 1, 1).unwrap();
    assert!(
        !r.resolve_at(&q, "router-a", |q| Ok(positive(q)), || now)
            .unwrap()
            .cached
    );
    let q2 = build_query("HOST.example", 1, 2).unwrap();
    let hit = r
        .resolve_at(
            &q2,
            "router-a",
            |_| panic!("cache miss"),
            || now + Duration::from_secs(7),
        )
        .unwrap();
    assert!(hit.cached);
    assert_eq!(&hit.wire[..2], &[0, 2]);
    assert_eq!(&hit.wire[12..q.len()], &q2[12..]);
    assert_eq!(wire::u32_at(&hit.wire, q.len() + 6).unwrap(), 53);
    let mut options = q2.clone();
    options[3] |= 0x10;
    assert!(
        !r.resolve_at(&options, "router-a", |q| Ok(positive(q)), || now)
            .unwrap()
            .cached
    );
    assert!(
        !r.resolve_at(&q2, "router-b", |q| Ok(positive(q)), || now)
            .unwrap()
            .cached
    );
    assert!(
        !r.resolve_at(
            &q2,
            "router-a",
            |q| Ok(positive(q)),
            || now + Duration::from_secs(60)
        )
        .unwrap()
        .cached
    );
}
#[test]
fn negative_answers_require_matching_zone_and_age_from_soa_minimum() {
    let r = resolver();
    let q = build_query("alias.example", 1, 1).unwrap();
    let now = Instant::now();
    for code in [0, 3] {
        r.clear();
        let rr = soa("example", 40, 3);
        let original = response(&q, code, &[], &[rr]);
        let at = wire::lifetime(&original, 120).unwrap().unwrap().ttls[0].0;
        let mut fresh = original.clone();
        clip_negative_soa(&mut fresh).unwrap();
        assert_eq!(wire::u32_at(&fresh, at).unwrap(), 3);
        let answer = r
            .resolve_at(&q, "root", |_| Ok(original.clone()), || now)
            .unwrap();
        assert!(!answer.cached);
        assert_eq!(wire::u32_at(&answer.wire, at).unwrap(), 40);
        let hit = r
            .resolve_at(
                &q,
                "root",
                |_| panic!("cache miss"),
                || now + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(wire::u32_at(&hit.wire, at).unwrap(), 1);
        assert!(
            !r.resolve_at(
                &q,
                "root",
                |_| Ok(original),
                || now + Duration::from_secs(3)
            )
            .unwrap()
            .cached
        );
    }
    let alias = rr(&[0xc0, 12], 5, 20, &owner("foo.another"));
    for raw in [
        response(&q, 3, &[], &[]),
        response(&q, 0, &[alias], &[soa("example", 10, 5)]),
        response(&q, 2, &[], &[soa("example", 10, 5)]),
        response(&q, 3, &[], &[soa("ample", 10, 5)]),
    ] {
        assert!(wire::lifetime(&raw, 120).unwrap().is_none());
    }
}
#[test]
fn clear_invalidates_pending_writes_and_capacity_evicts_earliest_expiry() {
    let r = Resolver::new(1, 60, Duration::from_secs(1));
    let q = build_query("old.example", 1, 1).unwrap();
    let result = r
        .exchange_with(&q, "scope", |q| {
            r.clear();
            Ok(positive(q))
        })
        .unwrap();
    assert!(!result.cached);
    assert_eq!(r.status().entries, 0);
    for host in ["old.example", "new.example", "old.example"] {
        let q = build_query(host, 1, 23).unwrap();
        assert!(
            !r.exchange_with(&q, "scope", |q| Ok(positive(q)))
                .unwrap()
                .cached
        );
        assert_eq!(r.status().entries, 1);
    }
    assert_eq!(r.clear(), 1);
}
#[test]
fn malformed_messages_never_enter_cache() {
    let r = resolver();
    let q = build_query("example", 1, 3).unwrap();
    let answer = positive(&q);
    for end in 0..answer.len() {
        assert!(r
            .exchange_with(&q, "x", |_| Ok(answer[..end].to_vec()))
            .is_err());
    }
    let mut mismatched_id = answer.clone();
    mismatched_id[1] = 4;
    let mut mismatched_name = answer.clone();
    mismatched_name[13] = b'q';
    let mut pointer = answer.clone();
    pointer[q.len() + 1] = q.len() as u8;
    for raw in [mismatched_id, mismatched_name, pointer] {
        assert!(r.exchange_with(&q, "x", |_| Ok(raw)).is_err());
    }
    assert_eq!(r.status().entries, 0);
}
#[test]
fn udp_and_tcp_fallback_return_measured_local_upstream_answer() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    thread::scope(|scope| {
        scope.spawn(move || {
            let mut data = [0; 512];
            let (n, peer) = udp.recv_from(&mut data).unwrap();
            udp.send_to(&positive(&data[..n]), peer).unwrap();
            let (n, peer) = udp.recv_from(&mut data).unwrap();
            let mut cut = data[..n].to_vec();
            cut[2] |= 0x82;
            udp.send_to(&cut, peer).unwrap();
            let (mut conn, _) = tcp.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut prefix = [0; 2];
            conn.read_exact(&mut prefix).unwrap();
            let mut q = vec![0; usize::from(u16::from_be_bytes(prefix))];
            conn.read_exact(&mut q).unwrap();
            let answer = positive(&q);
            conn.write_all(&(answer.len() as u16).to_be_bytes())
                .unwrap();
            conn.write_all(&answer).unwrap();
        });
        let r = resolver();
        for host in ["first.example", "second.example", "second.example"] {
            assert_eq!(
                r.lookup_v4(host, addr).unwrap(),
                Ipv4Addr::new(192, 0, 2, 10)
            );
        }
    });
}
