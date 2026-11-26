use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn sparse(base: [u8; 4], n: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(Ipv4Addr::from(base)) + 2 * n)
}

#[test]
fn marked_65536_sources_and_destinations_use_separate_sets_and_one_tunnel_route() {
    let (_tmp, db, _) = setup();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut policy = crate::policy::current(&doc).unwrap();
    let source = |n| sparse([10, 40, 0, 0], n);
    let dest = |n| sparse([77, 16, 0, 0], n);
    policy.killswitch = true;
    policy.zones[0].source_ips = (0..65536).map(|n| source(n).to_string()).collect();
    policy.zones[0].ips = (0..65536).map(|n| dest(n).to_string()).collect();
    let plan = plan::compile_effective(&doc, policy, None, false, &[], Default::default()).unwrap();
    assert_eq!(plan.source_ranges.len(), 1);
    assert_eq!(plan.source_ranges.values().next().unwrap().len(), 65536);
    assert_eq!(plan.scoped.len(), 65536);
    for n in [0, 42, 65535] {
        let flow = plan
            .scoped
            .iter()
            .find(|(s, _)| s.dest.contains(dest(n).into()))
            .unwrap();
        assert!(plan.matches_source(flow.0, source(n).into()));
        assert!(!plan.matches_source(flow.0, Ipv4Addr::from(u32::from(source(n)) + 1).into()));
    }
    let objects = objects(&plan);
    assert_eq!(
        objects
            .iter()
            .filter(|o| matches!(o, Object::SetMember(..)))
            .count(),
        131072
    );
    assert_eq!(
        objects
            .iter()
            .filter(|o| matches!(o, Object::Route(..)))
            .count(),
        1
    );
    assert_eq!(
        objects
            .iter()
            .filter(|o| matches!(o, Object::MarkFence(..)))
            .count(),
        1
    );
    let groups = objects
        .iter()
        .find_map(|o| match o {
            Object::Classifier(_, groups) => Some(groups),
            _ => None,
        })
        .unwrap();
    assert!((256..=512).contains(&groups.len()));
    assert!(groups.iter().all(|g| g.slot == 1 && g.source.is_some()));
    for object in objects
        .iter()
        .filter(|o| matches!(o, Object::GroupFirewall(..)))
    {
        let (_, _, spec) = object.xtables().unwrap();
        assert_eq!(
            spec.iter().filter(|s| s.as_str() == "--match-set").count(),
            2
        );
    }
    plan.check_handoff_size().unwrap();
}

#[test]
fn source_class_keeps_first_rule_for_each_address_pair_and_go_ipv4_cleaning() {
    let (_tmp, db, _) = setup();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut policy = crate::policy::current(&doc).unwrap();
    let mut first = policy.zones[0].clone();
    first.route = "direct".into();
    first.source_ips = vec!["192.168.4.0/25".into(), "192.168.9.11".into()];
    first.ips = vec!["77.0.0.2".into()];
    let mut tunnel = first.clone();
    tunnel.route = "tunnel".into();
    tunnel.ips = vec!["77.0.0.0/24".into()];
    tunnel.source_ips = vec!["192.168.4.0/24".into(), "192.168.9.11".into()];
    let mut last = tunnel.clone();
    // AWG2_MULTI discards IPv6-only source entries, leaving an IPv4 wildcard.
    last.source_ips = vec!["2001:db8::1".into()];
    last.ips = vec!["88.7.6.5".into()];
    policy.zones = vec![first, tunnel, last];
    let plan = plan::compile_effective(
        &doc,
        policy,
        None,
        false,
        &[],
        plan::Layout {
            go_ipv4: true,
            force_marked: true,
            ..Default::default()
        },
    )
    .unwrap();
    let matches = |source: &str, dest: &str| {
        let src = source.parse::<IpAddr>().unwrap();
        let dst = dest.parse::<IpAddr>().unwrap();
        plan.flows()
            .filter(|(s, _)| plan.matches_source(*s, src) && s.dest.contains(dst))
            .count()
    };
    assert_eq!(matches("192.168.4.1", "77.0.0.2"), 0);
    assert_eq!(matches("192.168.9.11", "77.0.0.2"), 0);
    assert_eq!(matches("192.168.4.128", "77.0.0.2"), 1);
    assert_eq!(matches("192.168.4.2", "77.0.0.3"), 1);
    assert_eq!(matches("192.168.9.11", "77.0.0.3"), 1);
    assert_eq!(matches("192.168.9.12", "77.0.0.3"), 0);
    assert_eq!(matches("192.168.9.12", "88.7.6.5"), 1);
    assert_eq!(matches("2001:db8::1", "88.7.6.5"), 0);
}

#[test]
fn source_partition_handles_upper_ipv6_endpoint_and_full_address_space() {
    use super::super::plan::{Family, Prefix};
    let mut parts = vec![];
    Prefix::append_interval(Family::V6, 0, u128::MAX, &mut parts);
    assert_eq!(parts, vec![Family::V6.any()]);
    parts.clear();
    Prefix::append_interval(Family::V6, u128::MAX - 2, u128::MAX, &mut parts);
    assert_eq!(
        parts.iter().map(|p| p.interval()).collect::<Vec<_>>(),
        vec![(u128::MAX - 2, u128::MAX - 2), (u128::MAX - 1, u128::MAX)]
    );
}

#[test]
fn preflight_rejects_an_expanded_classifier_larger_than_the_full_xtables_inventory() {
    let (_dir, db, _) = setup();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut p = crate::policy::current(&doc).unwrap();
    let zone = p.zones[0].clone();
    p.zones = (0..384)
        .map(|i| {
            let mut z = zone.clone();
            z.source_ips = vec![sparse([10, 16, 0, 0], i).to_string()];
            z.ips = (0..16)
                .map(|n| Ipv4Addr::from(0x4d00_0000 + 32 * i + n).to_string())
                .collect();
            z
        })
        .collect();
    let err = plan::compile_effective(&doc, p, None, false, &[], Default::default()).unwrap_err();
    assert!(err.to_string().contains("mangle"));
}
