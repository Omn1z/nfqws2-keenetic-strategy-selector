use super::*;
use std::{collections::HashMap, fs, sync::Mutex};

#[derive(Default)]
struct Mock {
    calls: Mutex<Vec<Vec<String>>>,
    uci: Mutex<HashMap<String, String>>,
}
impl Runner for Mock {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        let mut call = vec![program.into()];
        call.extend(args.iter().map(|v| v.to_string()));
        self.calls.lock().unwrap().push(call);
        if program != "uci" {
            return Ok(String::new());
        }
        let mut settings = self.uci.lock().unwrap();
        match args {
            ["-q", "get", key] => settings
                .get(*key)
                .cloned()
                .ok_or(io::ErrorKind::NotFound.into()),
            ["set", pair] => {
                let (k, v) = pair.split_once('=').unwrap();
                settings.insert(k.into(), v.into());
                Ok(String::new())
            }
            ["commit" | "changes", "firewall"] => Ok(String::new()),
            _ => panic!("unexpected UCI fixture call"),
        }
    }
}

#[tokio::test]
async fn domains_are_deduplicated_and_all_failure_keeps_existing_cache() {
    let (hosts,bad) = domain::hosts("; comment\nhttps://EXAMPLE.test:443/path\nexample.test. # same\nwrong domain\nsecond.test\n").unwrap();
    assert_eq!(bad, 1);
    assert_eq!(hosts.len(), 2);
    let (ips, failed) = domain::resolve(hosts.clone(), |name| async move {
        if name == "second.test" {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(vec![
            "2001:db8::1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "::ffff:192.0.2.1".parse().unwrap(),
        ])
    })
    .await
    .unwrap();
    assert_eq!(ips, "192.0.2.1\n2001:db8::1\n");
    assert_eq!(failed, 1);
    assert!(domain::resolve(hosts, |_| async { Ok(vec![]) })
        .await
        .is_err());
    assert!(domain::hosts("ftp://example.test/x\n-bad.test\n").is_err());
    assert!(domain::hosts("# only comments").unwrap().0.is_empty());
}

#[test]
fn transport_preserves_dynamic_peers_and_replaces_owned_peers() {
    let old = "192.0.2.50 4000\n# foreign comment\n";
    let first = transport(old, &["[2001:db8::a]:100".parse().unwrap()]).unwrap();
    let second = transport(&first, &["198.51.100.1:101".parse().unwrap()]).unwrap();
    assert!(second.starts_with(old));
    assert!(!second.contains("2001:db8::a"));
    assert_eq!(transport(&second, &[]).unwrap(), old);
    assert!(transport(
        &first.replace("# nfqws2-strategy Rust: end saved AWG endpoints", ""),
        &[]
    )
    .is_err());
}

#[test]
fn inherited_tuple_updates_preserve_other_manifest_owners() {
    let base = "192.0.2.50 4000\n# go-owned peer\n";
    let saved = transport(base, &["192.0.2.21:2408".parse().unwrap()]).unwrap();
    let inherited = transport_block(
        &saved,
        &["192.0.2.32:2408".parse().unwrap()],
        INHERITED_HEAD,
        INHERITED_TAIL,
    )
    .unwrap();
    assert!(inherited.starts_with(&saved));
    assert!(inherited.contains("192.0.2.32 2408\n"));
    assert_eq!(
        transport_block(&inherited, &[], INHERITED_HEAD, INHERITED_TAIL).unwrap(),
        saved
    );
    let crossed = format!("{INHERITED_HEAD}\n{SAVED_TAIL}\n");
    assert!(transport_block(&crossed, &[], INHERITED_HEAD, INHERITED_TAIL).is_err());
}

#[test]
fn refresh_uses_exact_tuples_and_keeps_other_publishers() {
    let prior = "192.0.2.50 4000\n# go-owned peer\n";
    let prior = transport(prior, &["192.0.2.1:50".parse().unwrap()]).unwrap();
    let inherited = [
        "198.51.100.8:990".parse().unwrap(),
        "198.51.100.8:991".parse().unwrap(),
        "[::ffff:198.51.100.8]:990".parse().unwrap(),
    ];
    let mut proof = TransportBypassProof {
        endpoint: "[::ffff:198.51.100.8]:990".parse().unwrap(),
        inherited: &inherited,
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let saved = ["[2001:db8::8]:555".parse().unwrap()];
    let next = refresh_manifest(&prior, &saved, proof).unwrap();
    assert!(next.starts_with("192.0.2.50 4000\n# go-owned peer\n"));
    assert!(next.contains("2001:db8::8 555\n"));
    assert!(next.contains("198.51.100.8 991\n"));
    assert_eq!(next.matches("198.51.100.8 990\n").count(), 1);
    assert!(!next.contains("192.0.2.1 50\n"));
    proof.endpoint = "[fe80::1%2]:1000".parse().unwrap();
    assert_eq!(
        refresh_manifest(&prior, &saved, proof).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn manually_stopped_engine_refreshes_only_the_manifest_and_defers_when_store_is_busy() {
    let root = tempfile::tempdir().unwrap();
    let cfg = Config::from_resolver(&Resolver::new_at(root.path()));
    let dir = conf_dir(&cfg).unwrap();
    let state = crate::http::AppState::open(cfg, root.path(), true).unwrap();
    fs::create_dir_all(dir.join("lists")).unwrap();
    fs::create_dir_all(root.path().join("tmp")).unwrap();
    hooks::helper(&dir.join(HELPER)).unwrap();
    fs::write(dir.join(DOMAIN_FILE), "pending.example\n").unwrap();
    fs::write(dir.join(CACHE), "192.0.2.1\n").unwrap();
    fs::write(dir.join(TRANSPORTS), "192.0.2.50 4000\n").unwrap();
    state
        .store
        .transaction(|tx| tx.save("automation.json", &json!({"nfqws2_manual_off":true})))
        .unwrap();
    let proof = TransportBypassProof {
        endpoint: "198.51.100.9:990".parse().unwrap(),
        inherited: &[],
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let runner = Mock::default();
    state
        .store
        .transaction(|_| {
            let err = refresh_transport(&state, proof, root.path(), &runner).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(
                fs::read_to_string(dir.join(TRANSPORTS))?,
                "192.0.2.50 4000\n"
            );
            Ok(())
        })
        .unwrap();
    refresh_transport(&state, proof, root.path(), &runner).unwrap();
    assert_eq!(
        fs::read_to_string(dir.join(TRANSPORTS)).unwrap(),
        format!("192.0.2.50 4000\n{SAVED_HEAD}\n198.51.100.9 990\n{SAVED_TAIL}\n")
    );
    assert_eq!(
        fs::read_to_string(dir.join(DOMAIN_FILE)).unwrap(),
        "pending.example\n"
    );
    assert_eq!(fs::read_to_string(dir.join(CACHE)).unwrap(), "192.0.2.1\n");
    assert!(manual_off(&state.store).unwrap());
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn both_platforms_restore_both_families_and_keep_one_pristine_backup() {
    for platform in [Platform::Entware, Platform::OpenWrt] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("etc/nfqws2");
        fs::create_dir_all(&dir).unwrap();
        let init = dir.join("vendor-init");
        let original = "#!/bin/sh\nsystem_config() { :; }\n  system_config\n# vendor keeps this\n";
        fs::write(&init, original).unwrap();
        let mock = Mock::default();
        for _ in 0..2 {
            hooks::helper(&dir.join(HELPER)).unwrap();
            firewall(&dir, init.to_str().unwrap(), platform, &mock, true).unwrap();
            assert_eq!(
                fs::read_to_string(dir.join("vendor-init.n2s-bak")).unwrap(),
                original
            );
            let next = fs::read_to_string(&init).unwrap();
            assert_eq!(next.matches("# nfqws2-strategy: reapply").count(), 1);
            assert!(next.ends_with("# vendor keeps this\n"));
        }
        let calls = mock.calls.lock().unwrap();
        let actions: Vec<_> = calls
            .iter()
            .filter(|c| c[0] != "uci")
            .map(|c| c[1].as_str())
            .collect();
        assert_eq!(
            actions,
            [
                "firewall_iptables",
                "firewall_ip6tables",
                "iptables",
                "ip6tables"
            ]
            .repeat(2)
        );
        assert_eq!(
            calls
                .iter()
                .filter(|c| c[0] == "uci" && c[1] == "commit")
                .count(),
            usize::from(platform == Platform::OpenWrt)
        );
        assert!(fs::read_to_string(dir.join(HELPER))
            .unwrap()
            .starts_with("#!/bin/sh\n# Generated by nfqws2-strategy."));
        if platform == Platform::Entware {
            assert!(dir
                .parent()
                .unwrap()
                .join("ndm/netfilter.d/101-nfqws2-bypass.sh")
                .is_file());
        }
    }
}

#[test]
fn custom_vendor_code_and_malformed_owned_hooks_are_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let helper = tmp.path().join(HELPER);
    fs::write(&helper, "#!/bin/sh\n# custom helper").unwrap();
    assert!(hooks::helper(&helper).is_err());
    assert_eq!(
        fs::read_to_string(&helper).unwrap(),
        "#!/bin/sh\n# custom helper"
    );
    assert!(hooks::patched("system_config_bad\n", &helper).is_err());
    assert!(hooks::patched(
        "# nfqws2-strategy: reapply NFQUEUE bypass\nuser_command\nkeep_me\n",
        &helper
    )
    .is_err());
    let escaped = hooks::patched("system_config\n", Path::new("/fixture/owner's helper")).unwrap();
    assert!(escaped.contains("'/fixture/owner'\"'\"'s helper'"));
}

#[tokio::test]
async fn off_state_and_acceleration_journal_guard_public_routes_before_side_effects() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let root = tempfile::tempdir().unwrap();
    let cfg = Config::from_resolver(&Resolver::new_at(root.path()));
    let cfg_dir = conf_dir(&cfg).unwrap();
    let s = crate::http::AppState::open(cfg, root.path(), true).unwrap();
    s.store
        .transaction(|tx| tx.save("automation.json", &json!({"nfqws2_manual_off":true})))
        .unwrap();
    let app = crate::http::router(s.clone());
    for (update, expected) in [(false, "вручную"), (true, "PPE")] {
        if update {
            fs::write(
                Path::new(&s.config.data_dir).join("awg-acceleration-state.json"),
                "preserve",
            )
            .unwrap();
        }
        let path = if update {
            "/api/nfqws2/update"
        } else {
            "/api/nfqws2/bypass/apply"
        };
        let req = Request::post(path).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), if update { 200 } else { 400 });
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains(expected));
        assert!(!cfg_dir.join(HELPER).exists());
    }
}

#[test]
fn newer_lists_keep_the_old_cache_and_valid_retries_update_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = Config::from_resolver(&Resolver::new_at(tmp.path()));
    let dir = conf_dir(&cfg).unwrap();
    let s = crate::http::AppState::open(cfg, tmp.path(), true).unwrap();
    fs::create_dir_all(dir.join("lists")).unwrap();
    fs::write(dir.join(DOMAIN_FILE), "new.example\n").unwrap();
    fs::write(dir.join(CACHE), "192.0.2.1\n").unwrap();
    fs::write(dir.join("nfqws-transport-endpoints"), "203.0.113.1 5555\n").unwrap();
    let apply = |old| {
        s.store
            .transaction(|_| install_files(&s, &dir, old, "192.0.2.99\n", &[]))
    };
    assert!(apply("stale.example\n").is_err());
    assert_eq!(fs::read_to_string(dir.join(CACHE)).unwrap(), "192.0.2.1\n");
    apply("new.example\n").unwrap();
    assert_eq!(fs::read_to_string(dir.join(CACHE)).unwrap(), "192.0.2.99\n");
    assert_eq!(
        fs::read_to_string(dir.join("nfqws-transport-endpoints")).unwrap(),
        "203.0.113.1 5555\n"
    );
}
