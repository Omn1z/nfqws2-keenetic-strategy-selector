use super::*;
use base64ct::{Base64, Encoding};
use std::{fs, path::Path};

pub(super) fn input() -> String {
    format!("[Interface]\nPrivateKey = {}\nAddress = 192.0.2.8/32, fd00::8/128\nDNS = 192.0.2.1\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 0\n",
        Base64::encode_string(&[7;32]),Base64::encode_string(&[11;32]),Base64::encode_string(&[9;32]))
}
fn runtime(p: &Path) -> runtime::Runtime {
    runtime::Runtime::new(p, p.join("absent/engine"))
}

#[test]
fn legacy_routing_status_counts_only_the_owner_or_eligible_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let rt = runtime(dir.path());
    import(&db, &input(), "reserve").unwrap();
    let backup = read(&db).unwrap()["active_id"].as_str().unwrap().to_owned();
    edit_document(&db, |doc| {
        doc["routing"] = json!({"mode": "zones"});
        doc["servers"][0]["config"]["enabled"] = json!(false);
        doc["servers"][0]["config"]["client"]["enabled"] = json!(true);
        doc["servers"][0]["config"]["routing"] = json!({
            "active": true, "mode": "zones", "zones": [{
                "name": "rule", "route": "direct", "enabled": true,
                "fallback_tunnel_ids": [backup],
            }],
        });
        doc["servers"][1]["config"]["enabled"] = json!(true);
        doc["servers"][1]["config"]["client"]["enabled"] = json!(true);
        doc["servers"][1]["config"]["routing"] = json!({"active": true, "mode": "zones"});
        Ok(())
    })
    .unwrap();
    let active = || status(&db, &rt).unwrap()["routing_config"]["active"] == true;
    assert!(!active());
    edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"][0]["route"] = json!("tunnel");
        Ok(())
    })
    .unwrap();
    assert!(active());
    edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"][0]["waiting_for_connection"] = json!(true);
        Ok(())
    })
    .unwrap();
    assert!(!active());
    edit_document(&db, |doc| {
        doc["routing"]["mode"] = json!("full");
        Ok(())
    })
    .unwrap();
    assert!(active());
}

#[test]
fn routing_status_preserves_dns_subdomain_tristate_and_legacy_directions() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let rt = runtime(dir.path());
    edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"] = json!({
            "mode": "exclude",
            "zones": [
                {"name": "legacy", "domains": ["old.example"], "enabled": true,
                 "fallback_tunnel_ids": ["unused"]},
                {"name": "exact", "route": "tunnel", "domains": ["exact.example"], "enabled": true,
                 "include_subdomains": false, "tunnel_id": " awg0 ",
                 "fallback_tunnel_ids": ["awg0", " reserve ", "reserve", "", "other"]},
                {"name": "suffix", "route": "tunnel", "domains": ["suffix.example"], "enabled": true,
                 "include_subdomains": true},
            ],
        });
        doc["pending_rules"] = json!([
            {"name": "pending", "domains": ["pending.example"], "enabled": true,
             "include_subdomains": false, "fallback_tunnel_ids": ["previous"]},
        ]);
        Ok(())
    })
    .unwrap();
    let original = read(&db).unwrap();
    let data = status(&db, &rt).unwrap();
    for zones in [
        &data["routing_rules"],
        &data["routing_config"]["zones"],
        &data["config"]["routing"]["zones"],
    ] {
        assert_eq!(zones[0]["name"], "legacy");
        assert!(zones[0].get("include_subdomains").is_none());
        assert_eq!(zones[0]["route"], "direct");
        assert_eq!(zones[0]["mode"], "exclude");
        assert_eq!(zones[1]["include_subdomains"], false);
        assert_eq!(zones[1]["route"], "tunnel");
        assert_eq!(zones[2]["include_subdomains"], true);
    }
    let rules = &data["routing_rules"];
    assert!(rules[0].get("fallback_tunnel_ids").is_none());
    assert_eq!(rules[1]["tunnel_id"], "awg0");
    assert_eq!(rules[1]["fallback_tunnel_ids"], json!(["reserve", "other"]));
    assert_eq!(rules[3]["waiting_for_connection"], true);
    assert_eq!(rules[3]["include_subdomains"], false);
    assert_eq!(rules[3]["fallback_tunnel_ids"], json!(["previous"]));
    assert_eq!(read(&db).unwrap(), original);
}

#[test]
fn legacy_selection_keeps_shared_routing_and_each_connections_own_rules() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let rt = runtime(dir.path());
    import(&db, &input(), "backup").unwrap();
    let backup = read(&db).unwrap()["active_id"].as_str().unwrap().to_owned();
    let primary_routing = json!({
        "mode": "zones",
        "mtu": 1392,
        "killswitch": true,
        "domain_source": "dnsproxy",
        "sni_routing": true,
        "trace_enabled": true,
        "active": true,
        "zones": [{"name": "global", "domains": ["one.example"], "enabled": true}],
    });
    edit_document(&db, |doc| {
        doc["servers"][0]["config"]["enabled"] = json!(true);
        doc["servers"][0]["config"]["client"]["enabled"] = json!(true);
        doc["servers"][0]["config"]["routing"] = primary_routing.clone();
        doc["servers"][1]["config"]["routing"] = json!({
            "mode": "exclude",
            "mtu": 1280,
            "active": false,
            "zones": [{"name": "own", "domains": ["two.example"], "enabled": false}],
        });
        doc["servers"][1]["applied_config"] = doc["servers"][1]["config"].clone();
        Ok(())
    })
    .unwrap();
    let before = read(&db).unwrap();
    let initial = status(&db, &rt).unwrap();
    assert_eq!(initial["active_server_id"], backup);
    assert_eq!(initial["routing_config"]["mtu"], 1392);
    assert_eq!(initial["routing_config"]["active"], true);
    assert_eq!(initial["routing_rules"].as_array().unwrap().len(), 2);

    select(&db, " awg0 ").unwrap();
    select(&db, &format!(" {backup} ")).unwrap();
    let after = read(&db).unwrap();
    assert_eq!(after["active_id"], backup);
    assert_eq!(after["servers"][0], before["servers"][0]);
    assert_eq!(
        after["servers"][1]["applied_config"],
        before["servers"][1]["applied_config"]
    );
    let own = &after["servers"][1]["config"]["routing"];
    for key in ["mode", "mtu", "killswitch", "domain_source", "sni_routing", "trace_enabled"] {
        assert_eq!(own[key], primary_routing[key], "{key}");
    }
    assert_eq!(own["active"], false);
    assert_eq!(own["zones"], json!([{
        "name": "own", "domains": ["two.example"], "enabled": false, "mode": "exclude",
    }]));
    assert_eq!(status(&db, &rt).unwrap()["routing_config"]["mtu"], 1392);

    add_server(&db, "new").unwrap();
    let after = read(&db).unwrap();
    let new = &active(&after).unwrap()["config"]["routing"];
    for key in ["mode", "mtu", "killswitch", "domain_source", "sni_routing", "trace_enabled"] {
        assert_eq!(new[key], primary_routing[key], "{key}");
    }
    assert_eq!(new["active"], false);
    assert_eq!(new["zones"], json!([]));
}

#[test]
fn dns_route_inventory_requires_a_live_peer_and_reads_only_applied_tunnel_dns() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let rt = runtime(dir.path());
    import(&db, &input(), "my-dns-tunnel").unwrap();
    edit_document(&db, |d| {
        let row = d["servers"].as_array_mut().unwrap().last_mut().unwrap();
        row["config"]["client"]["enabled"] = json!(true);
        row["config"]["enabled"] = json!(true);
        row["applied_config"] = row["config"].clone();
        row["applied_config"]["dns"] = json!("192.0.2.52, fd00::1 127.0.0.1 0.0.0.0 :: ff02::1");
        Ok(())
    })
    .unwrap();
    let routes = dns_routes(&db, &rt).unwrap();
    assert_eq!(routes.len(), 1);
    let selected = &routes[0];
    assert_eq!(selected.label, "my-dns-tunnel");
    assert!(selected.ifindex.is_none());
    assert_eq!(
        selected.dns,
        [
            "192.0.2.52".parse::<std::net::IpAddr>().unwrap(),
            "fd00::1".parse().unwrap()
        ]
    );
    #[cfg(target_os = "linux")]
    {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixListener,
        };
        let dev = dir.path().join("sys/class/net").join(&selected.iface);
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("ifindex"), "5").unwrap();
        fs::write(dev.join("tun_flags"), "0x0001").unwrap();
        let run = dir.path().join("var/run/amneziawg");
        fs::create_dir_all(&run).unwrap();
        let sock = UnixListener::bind(run.join(format!("{}.sock", selected.iface))).unwrap();
        let worker = std::thread::spawn(move || {
            for (peer, stamp) in [(11, now()), (8, now()), (11, 1)] {
                let (mut stream, _) = sock.accept().unwrap();
                let mut request = String::new();
                stream.read_to_string(&mut request).unwrap();
                assert_eq!(request, "get=1\n\n");
                write!(stream,"public_key={}\nendpoint=192.0.2.4:51820\nlast_handshake_time_sec={stamp}\nallowed_ip=0.0.0.0/0\nerrno=0\n\n",format!("{peer:02x}").repeat(32)).unwrap();
            }
        });
        for expected in [Some(5), None, None] {
            assert_eq!(dns_routes(&db, &rt).unwrap()[0].ifindex, expected);
        }
        worker.join().unwrap();
    }
}
#[cfg(target_os = "linux")]
#[test]
fn routing_handshake_uses_response_time_when_uapi_crosses_a_second() {
    use std::{io::{Read, Write}, os::unix::net::UnixListener, time::Duration};

    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(dir.path());
    let dev = dir.path().join("sys/class/net/awg0");
    let run = dir.path().join("var/run/amneziawg");
    fs::create_dir_all(&dev).unwrap();
    fs::create_dir_all(&run).unwrap();
    fs::write(dev.join("tun_flags"), "0x0001").unwrap();
    let socket = UnixListener::bind(run.join("awg0.sock")).unwrap();
    let cfg = json!({"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="});
    let server = std::thread::spawn(move || {
        for future in [false, true] {
            let (mut peer, _) = socket.accept().unwrap();
            let mut request = String::new();
            peer.read_to_string(&mut request).unwrap();
            assert_eq!(request, "get=1\n\n");
            let received = now();
            let handshake = if future {
                received + 3600
            } else {
                // The caller has already issued the request. A handshake
                // after this boundary is newer than any pre-query timestamp.
                std::thread::sleep(Duration::from_millis(1010));
                let stamp = now();
                assert!(stamp > received);
                stamp
            };
            write!(peer, "public_key={}\nendpoint=192.0.2.20:443\nlast_handshake_time_sec={handshake}\nallowed_ip=203.0.113.0/24\nerrno=0\n\n", "01".repeat(32)).unwrap();
        }
    });
    let read_peer = || runtime.routing_peer_with_budget(&cfg, "awg0", Duration::from_secs(5));
    let fresh = read_peer();
    let future = read_peer();
    server.join().unwrap();
    let (endpoint, networks) = fresh.unwrap();
    assert_eq!(endpoint.to_string(), "192.0.2.20:443");
    assert_eq!(networks, ["203.0.113.0/24"]);
    assert_eq!(future.unwrap_err().to_string(), "у пира нет свежего рукопожатия");
}
#[test]
fn selfhosted_credentials_stage_wire_changes_without_overwriting_legacy_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let rt = runtime(dir.path());
    add_server(&db, "router").unwrap();
    rt.save_config(&db,&json!({"conn":{"host":"192.0.2.23","password":"fixture-only"},"traffic_obfuscation":false,"private_key":"discard","peers":[]}),&[]).unwrap();
    let d = read(&db).unwrap();
    let cfg = &active(&d).unwrap()["config"];
    assert_ne!(cfg["private_key"], "discard");
    assert!(!cfg["peers"].as_array().unwrap().is_empty());
    assert_eq!(cfg["endpoint"], "192.0.2.23:51820");
    let id = active(&d).unwrap()["id"].clone();
    edit_document(&db, |d| {
        let r = d["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == id)
            .unwrap();
        r["config"]["deployed_at"] = json!(10);
        r["config"]["conn"]["known_key"] = json!("previous");
        r["config"]["opaque"] = json!({"keep":43});
        Ok(())
    })
    .unwrap();
    rt.save_config(&db, &json!({"conn":{"password":""},"mtu":1380}), &[])
        .unwrap();
    let old = read(&db).unwrap();
    let old = active(&old).unwrap();
    assert!(old["applied_config"].is_null());
    assert_eq!(old["config"]["conn"]["password"], "fixture-only");
    rt.save_config(&db,&json!({"endpoint":"192.0.2.33:6000","conn":{"host":"192.0.2.33","password":"", "known_key":"previous"}}),&[]).unwrap();
    let committed = read(&db).unwrap();
    let row = active(&committed).unwrap();
    assert_eq!(row["applied_config"], old["config"]);
    assert_eq!(row["config"]["conn"]["known_key"], "");
    assert_eq!(row["config"]["opaque"]["keep"], 43);
    for input in [
        json!({"mtu":1900}),
        json!({"address":"bad"}),
        json!({"conn":{"host":"-oProxyCommand"}}),
        json!({"endpoint":"bad\nendpoint:3"}),
    ] {
        assert!(rt.save_config(&db, &input, &[]).is_err());
        assert_eq!(read(&db).unwrap(), committed);
    }
}
#[test]
fn warp_registration_validates_response_and_exports_standard_wireguard() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    assert!(WarpEnrollment::new("one", "", false).is_err());
    assert!(WarpEnrollment::new("one", "bad host:99", true).is_err());
    let bad = WarpEnrollment::new("one", "", true).unwrap();
    assert!(bad
        .finish(
            &db,
            br#"{"config":{"interface":{"addresses":{"v4":"bad"}},"peers":[]}}"#
        )
        .is_err());
    assert!(!dir.path().join("awg.json").exists());
    let e = WarpEnrollment::new("", "2001:db8::10", true).unwrap();
    let pubkey = e.public_key().to_owned();
    let response = json!({"id":"unused-registration-id","token":"unused-registration-secret","config":{"interface":{"addresses":{"v4":"172.16.0.2"}},"peers":[{"public_key":Base64::encode_string(&[22;32])}]}});
    e.finish(&db, &serde_json::to_vec(&response).unwrap())
        .unwrap();
    let doc = read(&db).unwrap();
    let c = &active(&doc).unwrap()["config"];
    assert_eq!(c["protocol"], "wireguard");
    assert_eq!(c["peers"][0]["public_key"], pubkey);
    assert_eq!(c["endpoint"], "[2001:db8::10]:2408");
    assert!(view::warp(c));
    assert!(!doc.to_string().contains("unused-registration"));
    let text = conf::export(c, &c["peers"][0]).unwrap();
    assert!(text.contains("Address = 172.16.0.2/32"));
    assert!(!text.contains("I1 ="));
}
#[test]
fn edited_awg31_header_key_survives_redacted_form_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let rt = runtime(dir.path());
    add_server(&db, "test").unwrap();
    rt.save_config(
        &db,
        &json!({"conn":{"host":"vpn.example.test"},"traffic_obfuscation":true}),
        &[],
    )
    .unwrap();
    let first = read(&db).unwrap();
    let cfg = &active(&first).unwrap()["config"];
    let header = s(&cfg["obf"], "header_protection_key");
    conf::key(header, false).unwrap();
    assert_eq!(cfg["obf"]["s1"], 12);
    let view = status(&db, &rt).unwrap();
    assert!(!view.to_string().contains(header));
    assert_eq!(view["config"]["obf"]["has_header_protection_key"], true);
    rt.save_config(&db, &view["config"], &[]).unwrap();
    let second = read(&db).unwrap();
    assert_eq!(
        active(&second).unwrap()["config"]["obf"]["header_protection_key"],
        header
    );
}
#[test]
fn saved_transports_use_enabled_applied_endpoints_and_literal_backups_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    assert!(transport_endpoints(&db).unwrap().is_empty());
    assert!(!dir.path().join("awg.json").exists());
    edit_document(&db, |d| {
        let first = &mut d["servers"][0];
        first["config"]["endpoint"] = json!("192.0.2.100:111");
        first["applied_config"] = first["config"].clone();
        first["applied_config"]["endpoint"] = json!(" gw.example.test:444 ");
        first["config"]["client"]["endpoint_backups"] = json!([
            "192.0.2.1",
            "[::ffff:192.0.2.1]:444",
            "[2001:db8::10]:123",
            "127.0.0.1",
            "fe80::123",
            "255.255.255.255"
        ]);
        let mut off = first.clone();
        off["id"] = json!("off");
        off["config"]["enabled"] = json!(false);
        off["applied_config"]["endpoint"] = json!("192.0.2.2:111");
        let mut bad = first.clone();
        bad["id"] = json!("bad");
        bad["applied_config"]["endpoint"] = json!("192.0.2.3:123");
        bad["config"]["client"]["endpoint_backups"] = json!(["invalid backup"]);
        d["servers"].as_array_mut().unwrap().extend([off, bad]);
        Ok(())
    })
    .unwrap();
    let before = fs::read(dir.path().join("awg.json")).unwrap();
    let endpoints: Vec<_> = transport_endpoints(&db)
        .unwrap()
        .into_iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(
        endpoints,
        ["192.0.2.1:444", "192.0.2.3:123", "[2001:db8::10]:123"]
    );
    assert_eq!(fs::read(dir.path().join("awg.json")).unwrap(), before);
}
#[test]
fn repeated_address_lists_and_local_listen_port_roundtrip() {
    let input = input()
        .replace(
            "192.0.2.8/32, fd00::8/128",
            "192.0.2.8/32\nAddress = fd00::8/128\nListenPort = 12120",
        )
        .replace("0.0.0.0/0, ::/0", "0.0.0.0/0\nAllowedIPs = ::/0");
    let c = conf::parse(&input, 5).unwrap();
    assert_eq!(c["client"]["listen_port"], 12120);
    assert_eq!(c["listen_port"], 51820);
    let peer = &c["peers"][0];
    let local = conf::export_with_mtu(&c, peer, Some(1420)).unwrap();
    assert!(local.contains("ListenPort = 12120\n"));
    let portable = conf::export(&c, peer).unwrap();
    assert!(!portable.contains("ListenPort = "));
    assert!(portable.contains("0.0.0.0/0, ::/0"));
    assert_eq!(
        conf::parse(&local, 5).unwrap()["peers"][0]["address"],
        "192.0.2.8/32, fd00::8/128"
    );
}
#[test]
fn imports_go_wg_quick_profile_with_inert_local_options() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let profile = input()
        .replace("[Interface]", "[ Interface ]")
        .replace("[Peer]", "[ peer ]")
        .replace(
            "DNS =",
            "Table = off\nSaveConfig = false\nFwMark = 17\nDNS =",
        );
    import(&db, &profile, "legacy wg-quick").unwrap();
    let document = read(&db).unwrap();
    let cfg = &active(&document).unwrap()["config"];
    assert_eq!(cfg["client"]["enabled"], false);
    assert_eq!(cfg["protocol"], "wireguard");
    assert_eq!(cfg["routing"]["mode"], "off");
    let (plain, _) = peer_export(&db, "router", "conf").unwrap();
    for option in ["Table", "SaveConfig", "FwMark"] {
        assert!(!plain.lines().any(|line| line.starts_with(option)));
    }
}
#[test]
fn saved_peers_allocate_unique_addresses_and_preserve_public_only_identity() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    add_server(&db, "fixture").unwrap();
    let generated = add_peer(
        &db,
        PeerInput {
            name: "generated".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(generated["address"], "10.13.13.3/32");
    assert_eq!(generated["private_key"], "");
    assert_eq!(generated["psk"], "");
    assert_eq!(generated["has_private"], true);
    let make = || PeerInput {
        id: "external".into(),
        public_key: Base64::encode_string(&[17; 32]),
        address: "192.0.2.7/32".into(),
        ..Default::default()
    };
    let external = add_peer(&db, make()).unwrap();
    assert_eq!(external["has_private"], false);
    assert!(add_peer(&db, make()).is_err());
    assert!(add_peer(
        &db,
        PeerInput {
            address: "192.0.2.7/24".into(),
            ..Default::default()
        }
    )
    .is_err());
    assert!(add_peer(
        &db,
        PeerInput {
            private_key: Base64::encode_string(&[8; 32]),
            ..make()
        }
    )
    .is_err());
    remove_peer(&db, "external").unwrap();
    let doc = read(&db).unwrap();
    let cfg = &active(&doc).unwrap()["config"];
    assert_eq!(cfg["peers"].as_array().unwrap().len(), 2);
    assert!(conf::key(s(&cfg["peers"][1], "psk"), false).is_ok());
    assert!(!s(&cfg["client"], "peer_id").is_empty());
    edit_document(&db, |doc| {
        doc["servers"][1]["config"]["deployed_at"] = json!(10);
        Ok(())
    })
    .unwrap();
    assert!(remove_peer(&db, s(&generated, "id")).is_err());
    assert!(add_peer(&db, PeerInput::default()).is_err());
    import(&db, &input(), "imported").unwrap();
    assert!(remove_peer(&db, "router").is_err());
}
#[test]
fn x25519_profile_vpn_and_conf_roundtrip_with_separate_private_export() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let text = input().replace("DNS =", "RandomTrailers = off\nS3 = 0\nDNS =");
    let current = status(&db, &runtime(dir.path())).unwrap();
    assert_eq!(current["active_server_id"], "awg0");
    assert!(!dir.path().join("awg.json").exists());
    import(&db, &text, "fixture").unwrap();
    let v = status(&db, &runtime(dir.path())).unwrap();
    assert_eq!(v["config"]["protocol_version"], "3.1");
    assert_eq!(v["config"]["client_iface"], "awg1");
    assert_eq!(
        v["config"]["peers"][0]["public_key"],
        "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20="
    );
    for secret in [
        Base64::encode_string(&[7; 32]),
        Base64::encode_string(&[9; 32]),
    ] {
        assert!(!v.to_string().contains(&secret));
    }
    let (out, _) = peer_export(&db, "router", "vpn").unwrap();
    assert!(out.starts_with("vpn://"));
    let recovered = vpn::parse(&out, 1).unwrap();
    assert_eq!(recovered["protocol_version"], "3.1");
    assert_eq!(recovered["peers"][0]["keepalive_range"], "0");
    let (conf, _) = peer_export(&db, "router", "conf").unwrap();
    assert!(conf.contains("PersistentKeepalive = 0"));
    assert!(conf.contains("Endpoint = [2001:db8::1]:51820"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("awg.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn rejects_bad_keys_hooks_ranges_addresses_and_compressed_size_without_echoing_secrets() {
    let good = input();
    for bad in [
        good.replace(&Base64::encode_string(&[7; 32]), "secret-not-valid"),
        good.replace(&Base64::encode_string(&[11; 32]), "secret-not-valid"),
        good.replace("192.0.2.8/32", "192.0.2.8/33"),
        good.replace("fd00::8/128", "fd00::8/150"),
        good.replace("[2001:db8::1]:51820", "bad@host:0"),
        good.replace("::/0", "::/999"),
        good.replace("DNS =", "PostUp = ignored\nDNS ="),
        good.replace("[Peer]", "[Peer]\n[Peer]"),
        good.replace("DNS =", "H1 = 2-5\nH2 = 4-9\nDNS ="),
        good.replace("DNS =", "Jc = 129\nDNS ="),
        "vpn://_______".into(),
    ] {
        let e = vpn::parse(&bad, 10).unwrap_err();
        assert!(!e.to_string().contains("secret-not-valid"));
    }
}
#[test]
fn retains_unknown_root_and_profile_fields_pending_routes_and_applied_identity() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let mut original = conf::parse(&input(), 1).unwrap();
    original["future_extension"] = json!({"secret":"hidden-foreign-field"});
    original["conn"]["password"] = json!("hidden-password");
    original["client"]["future_flag"] = json!(true);
    let applied = original.clone();
    original["endpoint"] = json!("next.test:51820");
    let saved = json!({"active_id":"old","servers":[{"id":"old","name":"legacy","config":original,"applied_config":applied,"future_value":false}],
        "future_top":55,"pending_rules":[{"name":"retained","domains":[],"marker":"hidden-future-rule"}],"routing":{"mode":"zones","mtu":1300}});
    db.transaction(|tx| tx.save("awg.json", &saved)).unwrap();
    assert!(peer_export(&db, "router", "conf")
        .unwrap()
        .0
        .contains("[2001:db8::1]:51820"));
    let before = status(&db, &runtime(dir.path())).unwrap().to_string();
    for secret in [
        "hidden-foreign-field",
        "hidden-password",
        "hidden-future-rule",
    ] {
        assert!(!before.contains(secret));
    }
    import(&db, &input(), "added").unwrap();
    let after = read(&db).unwrap();
    assert!(after["servers"][0] == saved["servers"][0]);
    assert!(after["pending_rules"] == saved["pending_rules"]);
    assert_eq!(after["future_top"], 55);
    assert_eq!(after["servers"][1]["config"]["routing"]["mtu"], 1300);
    select(&db, "old").unwrap();
    rename(&db, "old", "renamed").unwrap();
    assert_eq!(read(&db).unwrap()["servers"][0]["name"], "renamed");
}
#[test]
fn migrates_single_profile_on_write_refuses_corrupt_storage_and_preserves_concurrent_imports() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let mut legacy = conf::parse(&input(), 10).unwrap();
    legacy["retained"] = json!(42);
    db.transaction(|tx| tx.save("awg.json", &legacy)).unwrap();
    let read = super::read(&db).unwrap();
    assert_eq!(read["servers"][0]["config"]["retained"], 42);
    let raw: Value = db.read("awg.json").unwrap();
    assert!(raw.get("servers").is_none());
    std::thread::scope(|scope| {
        for i in 0..4 {
            let db = &db;
            scope.spawn(move || import(db, &input(), &format!("profile {i}")).unwrap());
        }
    });
    let after = super::read(&db).unwrap();
    assert_eq!(after["servers"].as_array().unwrap().len(), 5);
    assert_eq!(after["servers"][0]["config"]["retained"], 42);
    fs::write(dir.path().join("awg.json"), b"corrupt").unwrap();
    assert_eq!(
        status(&db, &runtime(dir.path())).unwrap()["config_recovered"],
        true
    );
    assert_eq!(fs::read(dir.path().join("awg.json")).unwrap(), b"corrupt");
    let empty = tempfile::tempdir().unwrap();
    let db = Store::open(empty.path()).unwrap();
    fs::write(empty.path().join("awg.json"), b"{").unwrap();
    assert!(import(&db, &input(), "refused").is_err());
    assert_eq!(fs::read(empty.path().join("awg.json")).unwrap(), b"{");
}
