use super::*;
use std::net::IpAddr;

#[test]
#[ignore = "requires isolated Linux network and mount namespaces"]
fn archive_warmup_routes_real_source_prefixes_in_rule_order() {
    for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        let parent = std::env::var(var).unwrap();
        assert!(parent.starts_with(&format!("{kind}:[")));
        let current = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert_ne!(current.to_str(), Some(parent.as_str()));
    }
    const NAME: &str = "mail.branch.test";
    let fresh: IpAddr = "203.0.113.51".parse().unwrap();
    let stale: IpAddr = "203.0.113.52".parse().unwrap();
    let (_dir, db, _) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones", "domain_source":"dnsproxy", "killswitch":true});
        let profiles = doc["servers"].as_array_mut().unwrap();
        let mut branch = profiles[0].clone();
        branch["id"] = json!("branch");
        branch["config"]["client_iface"] = json!("awg1");
        branch["config"]["endpoint"] = json!("192.0.2.22:443");
        branch["config"]["routing"] = json!({"mode":"zones", "domain_source":"dnsproxy", "zones":[
            {"name":"branch", "order":3, "enabled":true, "domains":["*.branch.test"], "source_ips":["10.99.0.13"]}
        ]});
        let primary = &mut profiles[0]["config"];
        primary["endpoint"] = json!("192.0.2.21:443");
        primary["routing"] = json!({"mode":"zones", "domain_source":"dnsproxy", "zones":[
            {"name":"direct first", "order":1, "enabled":true, "route":"direct", "domains":["*.branch.test"], "source_ips":["10.99.0.11"]},
            {"name":"main tunnel", "order":2, "enabled":true, "domains":["*.branch.test"], "source_ips":["10.99.0.11","10.99.0.12"]}
        ]});
        profiles.push(branch);
        Ok(())
    })
    .unwrap();
    let router = nfqws2_router_command::System;
    let k = kernel(&router);
    let live = |cfg: &Value, iface: &str| {
        Ok(LivePeer {
            endpoint: cfg["endpoint"].as_str().unwrap().parse().unwrap(),
            ..both_peers(cfg, iface)?
        })
    };
    let dev = |ip: IpAddr, src: &str| {
        k.call(
            "ip",
            &[
                "-4",
                "route",
                "get",
                &ip.to_string(),
                "from",
                src,
                "iif",
                "br0",
            ],
        )
        .ok()
        .and_then(|line| {
            let mut words = line.split_ascii_whitespace();
            words.find(|word| *word == "dev")?;
            words.next().map(str::to_owned)
        })
    };
    let now = nfqws2_awg_profile::now();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, now, live).unwrap();
    }
    assert_eq!(dev(fresh, "10.99.0.12").as_deref(), Some("wan0"));
    assert_eq!(dev(fresh, "10.99.0.13").as_deref(), Some("wan0"));
    let revision = Journal::read(&db).unwrap().installed.revision;
    let lookup = |ip, revision| {
        learn_archived_answer(
            &db,
            &router,
            ArchiveAnswer {
                revision,
                name: NAME,
                addresses: &[ip],
                ttl: 40,
                qtype: 1,
            },
            live,
            || Ok(()),
        )
    };
    assert!(lookup(stale, revision + 1).is_err());
    lookup(fresh, revision).unwrap();
    for (source, expected) in [
        ("10.99.0.11", "wan0"),
        ("10.99.0.12", "awg0"),
        ("10.99.0.13", "awg1"),
        ("10.99.0.14", "wan0"),
    ] {
        assert_eq!(dev(fresh, source).as_deref(), Some(expected));
        assert_eq!(dev(stale, source).as_deref(), Some("wan0"));
    }
    operate_at(&db, &router, Operation::Teardown, now, live).unwrap();
    assert_eq!(dev(fresh, "10.99.0.12").as_deref(), Some("wan0"));
    assert_eq!(dev(fresh, "10.99.0.13").as_deref(), Some("wan0"));
}
