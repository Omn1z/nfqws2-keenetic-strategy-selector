use super::super::{filtering::Filter, transport::Doh};
use super::*;
use std::io::{Cursor, Write};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn fixture(prefix: &str, count: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    writeln!(bytes, "[Adblock Plus 2.0]").unwrap();
    for i in 0..count {
        writeln!(bytes, "||{prefix}{i}.example^").unwrap();
    }
    bytes
}
fn staged(dir: &Path, data: &[u8]) -> TempPath {
    let mut f = NamedTempFile::new_in(dir).unwrap();
    f.write_all(data).unwrap();
    f.into_temp_path()
}
#[test]
fn in_flight_answer_observes_current_exceptions_and_record_types() {
    let filter =
        Filter::compile(&serde_json::json!({"enabled":true,"lists":["adguard-dns"]})).unwrap();
    let feed = filter.feed.as_ref().unwrap();
    let snapshot = |rules: &[u8]| Arc::new(Index::read(Cursor::new(rules)).unwrap());
    let previous = snapshot(b"@@||shop.example^\n");
    let mut answer = nfqws2_dns::build_query("shop.example", 1, 42).unwrap();
    answer[2] = 0x81;
    answer[7] = 1;
    let target = b"\x07tracker\x07example\x00";
    answer.extend([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, target.len() as u8]);
    answer.extend(target);
    for (rule, expect) in [
        (&b"||tracker.example^$dnstype=A"[..], None),
        (b"||tracker.example^$dnstype=CNAME", Some("tracker.example")),
        (b"||shop.example^$dnstype=A", Some("shop.example")),
        (
            b"@@||shop.example^$dnstype=A\n||tracker.example^$dnstype=CNAME",
            None,
        ),
    ] {
        feed.state.write().unwrap().index = Some(snapshot(rule));
        let hit = filter
            .response_hit("shop.example", 1, &answer, Some(&previous), true)
            .unwrap();
        assert_eq!(hit.as_ref().map(|h| h.domain.as_str()), expect);
    }
}
#[test]
fn upstream_fixture_priorities_badfilter_dnstype_wildcard_and_exceptions() {
    let text=b"||ad.example^\n@@||good.ad.example^\n||disabled.example^\n||disabled.example^$badfilter\n||type.example^$dnstype=AAAA\n||wild*.example^\n||important.example^$important\n@@||important.example^\n||rewrite.example^$dnsrewrite=1.2.3.4\n0.0.0.0 hosts.test\n||ipv6.test^$dnstype=~A\n@@||specific.ad.example^$unsupported\n";
    let index = Index::read(Cursor::new(text)).unwrap();
    assert_eq!(index.ignored, 2);
    let f=Filter::compile(&serde_json::json!({"enabled":true,"custom_rules":[{"domain":"manual.good.ad.example","category":"trackers"}],"allowlist":["allow.important.example"]})).unwrap();
    for (name, kind, block, allowed) in [
        ("ad.example", 1, true, false),
        ("child.ad.example", 1, true, false),
        ("good.ad.example", 1, false, true),
        ("manual.good.ad.example", 1, true, false),
        ("disabled.example", 1, false, false),
        ("type.example", 1, false, false),
        ("type.example", 28, true, false),
        ("wild123.example", 1, true, false),
        ("wild.a.example", 1, true, false),
        ("mild123.example", 1, false, false),
        ("important.example", 1, true, false),
        ("allow.important.example", 1, false, true),
        ("rewrite.example", 1, false, false),
        ("hosts.test", 1, true, false),
        ("a.hosts.test", 1, false, false),
        ("ipv6.test", 1, false, false),
        ("ipv6.test", 28, true, false),
        ("specific.ad.example", 28, true, false),
    ] {
        let (hit, pass) = f.evaluate(name, kind, Some(&index));
        assert_eq!((hit.is_some(), pass), (block, allowed), "{name}/{kind}");
        if let Some(hit) = hit {
            assert_eq!(
                hit.source,
                if name.starts_with("manual.") {
                    "custom"
                } else {
                    "adguard-dns"
                }
            );
        }
    }
}
#[test]
fn multi_type_conditions_priorities_and_badfilter_match_go_engine() {
    // Recorded from the project's github.com/AdguardTeam/urlfilter v0.23.4
    // DNSEngine.MatchRequest, including the exact winning block rule text.
    type Case<'a> = (&'a str, Vec<&'a str>, Vec<u16>, Vec<Option<&'a str>>);
    for line in include_str!("fixtures/go-dnstype.jsonl").lines() {
        let (domain, rules, kinds, expected): Case<'_> = serde_json::from_str(line).unwrap();
        let index = Index::read(Cursor::new(rules.join("\n"))).unwrap();
        assert_eq!(kinds.len(), expected.len());
        for (kind, want) in kinds.into_iter().zip(expected) {
            let matched = match index.lookup(domain, kind) {
                None => None,
                Some(Verdict::Allow) => Some("allow".to_owned()),
                Some(Verdict::Block(rule)) => Some(rule),
            };
            assert_eq!(matched.as_deref(), want, "{domain}/{kind}");
        }
    }
}
#[test]
fn disabled_duplicate_and_empty_rules_cannot_validate_a_replacement_feed() {
    use std::fmt::Write;
    let mut feed = "||duplicate.example^\n".repeat(1200);
    for i in 0..1100 {
        writeln!(&mut feed, "||bad{i}.example^$badfilter\n||off{i}.example^\n||off{i}.example^$badfilter\n||never{i}.example^$dnstype=A|~A").unwrap();
    }
    let result = Index::read(Cursor::new(feed)).unwrap();
    assert_eq!(result.len(), 1);
    assert!(validate(&result, 1200).is_err());
}

#[tokio::test]
async fn identical_catalog_refresh_keeps_restored_index_and_client_cache() {
    use crate::dnsserver::{config, runtime::Diagnostics, shadow, vpn};
    use nfqws2_dns::Lookup;
    use std::sync::Mutex;

    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let dir = d.path().join("dns-blocklists");
    ensure_directory(&dir).unwrap();
    let list = fixture("stable", 1200);
    fs::write(dir.join(CACHE), &list).unwrap();
    let old_date = "2000-01-01T00:00:00Z";
    let old_meta = serde_json::json!({"adguard-dns":{
        "rules":1200, "last_updated":old_date, "last_error":"old refresh failure"
    }});
    store
        .transaction(|tx| tx.save(METADATA, &old_meta))
        .unwrap();
    let mut raw = config::defaults();
    raw["fast_dns"] = serde_json::json!(false);
    raw["scheduler_enabled"] = serde_json::json!(false);
    raw["cache_size"] = serde_json::json!(8);
    raw["filtering"] = serde_json::json!({
        "enabled":true, "lists":["adguard-dns"], "custom_rules":[], "allowlist":[]
    });
    let engine = Engine::new(
        config::Config::from_value(&raw).unwrap(),
        Arc::new(Mutex::new(Diagnostics::new(false))),
        Default::default(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(Vec::new()))),
        Default::default(),
    );
    let feed = engine.filter.as_ref().unwrap().feed.as_ref().unwrap();
    feed.restore(&dir, &store).unwrap();
    let before = feed.snapshot().unwrap();
    assert_eq!(feed.status().updated, old_date);
    let query = nfqws2_dns::build_query("cached.test", 1, 7).unwrap();
    engine
        .cache
        .exchange_with(&query, "pool", |q| {
            let mut reply = nfqws2_dns::response_error(q, 0);
            reply[7] = 1;
            reply.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 45, 0, 4, 192, 0, 2, 10]);
            Ok(reply)
        })
        .unwrap();
    let (stop, receiver) = watch::channel(false);
    feed.publish_download(staged(&dir, &list), &dir, &store, &receiver, &engine.cache)
        .unwrap();
    assert!(Arc::ptr_eq(&before, &feed.snapshot().unwrap()));
    assert!(matches!(
        engine.cache.begin(&query, "pool").unwrap(),
        Lookup::Hit(_)
    ));
    let saved: serde_json::Value = store.read(METADATA).unwrap();
    let meta = &saved["adguard-dns"];
    assert_eq!(meta["rules"], 1200);
    assert_eq!(meta["previous_rules"], 1200);
    assert_eq!(meta["last_error"], "");
    assert_ne!(meta["last_updated"], old_date);
    assert_eq!(
        feed.status().updated,
        meta["last_updated"].as_str().unwrap()
    );
    assert_eq!(fs::read(dir.join(CACHE)).unwrap(), list);

    let changed = fixture("changed", 1200);
    stop.send_replace(true);
    assert_eq!(
        feed.publish_download(
            staged(&dir, &changed),
            &dir,
            &store,
            &receiver,
            &engine.cache
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::Interrupted,
    );
    assert!(Arc::ptr_eq(&before, &feed.snapshot().unwrap()));
    assert!(matches!(
        engine.cache.begin(&query, "pool").unwrap(),
        Lookup::Hit(_)
    ));
    assert_eq!(store.read::<serde_json::Value>(METADATA).unwrap(), saved);
    assert_eq!(fs::read(dir.join(CACHE)).unwrap(), list);

    stop.send_replace(false);
    feed.publish_download(
        staged(&dir, &changed),
        &dir,
        &store,
        &receiver,
        &engine.cache,
    )
    .unwrap();
    let after = feed.snapshot().unwrap();
    assert!(!Arc::ptr_eq(&before, &after));
    assert!(before.lookup("stable17.example", 1).is_some());
    assert!(after.lookup("changed17.example", 1).is_some());
    assert!(after.lookup("stable17.example", 1).is_none());
    assert!(matches!(
        engine.cache.begin(&query, "pool").unwrap(),
        Lookup::Miss(_)
    ));
    assert_eq!(fs::read(dir.join(CACHE)).unwrap(), changed);
}

#[test]
fn atomic_install_rejects_replacement_and_preserves_go_compatible_cache_across_restart() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let dir = d.path().join("dns-blocklists");
    ensure_directory(&dir).unwrap();
    let (tx, rx) = watch::channel(false);
    let feed = Feed::default();
    let first = fixture("a", 3000);
    feed.install(staged(&dir, &first), &dir, &store, &rx)
        .unwrap();
    let old = feed.snapshot().unwrap();
    let old_meta = fs::read(dir.join("metadata.json")).unwrap();
    // A malformed sidecar must not publish the new raw file or live index.
    fs::write(dir.join("metadata.json"), b"broken metadata").unwrap();
    assert!(feed
        .install(staged(&dir, &fixture("new", 2200)), &dir, &store, &rx)
        .is_err());
    assert!(Arc::ptr_eq(&old, &feed.snapshot().unwrap()));
    assert_eq!(fs::read(dir.join(CACHE)).unwrap(), first);
    assert_eq!(
        fs::read(dir.join("metadata.json")).unwrap(),
        b"broken metadata"
    );
    // Simulate power loss after staging the new counts but before the rename.
    fs::write(
        dir.join("metadata.json"),
        br#"{"adguard-dns":{"rules":10000,"previous_rules":3000}}"#,
    )
    .unwrap();
    let recovered = Feed::default();
    recovered.restore(&dir, &store).unwrap();
    assert_eq!(recovered.status().rules, 3000);
    fs::write(dir.join("metadata.json"), &old_meta).unwrap();
    let saved_file = dir.join("test-original");
    fs::rename(dir.join(CACHE), &saved_file).unwrap();
    fs::create_dir(dir.join(CACHE)).unwrap();
    assert!(feed
        .install(staged(&dir, &fixture("new", 2200)), &dir, &store, &rx)
        .is_err());
    assert!(Arc::ptr_eq(&old, &feed.snapshot().unwrap()));
    assert_eq!(fs::read(dir.join("metadata.json")).unwrap(), old_meta);
    fs::remove_dir(dir.join(CACHE)).unwrap();
    fs::rename(saved_file, dir.join(CACHE)).unwrap();
    for data in [
        fixture("small", 1001),
        b"<!DOCTYPE html>\n".to_vec(),
        vec![b'x'; 20_000],
    ] {
        assert!(feed
            .install(staged(&dir, &data), &dir, &store, &rx)
            .is_err());
        assert_eq!(fs::read(dir.join(CACHE)).unwrap(), first);
        assert!(Arc::ptr_eq(&old, &feed.snapshot().unwrap()));
    }
    tx.send_replace(true);
    let second = fixture("b", 2000);
    assert!(feed
        .install(staged(&dir, &second), &dir, &store, &rx)
        .is_err());
    assert_eq!(fs::read(dir.join(CACHE)).unwrap(), first);
    let resumed = Feed::default();
    resumed.restore(&dir, &store).unwrap();
    assert_eq!(resumed.status().rules, 3000);
    assert!(!resumed.begin(None));
    resumed.request();
    resumed.request();
    assert!(resumed.begin(None));
    resumed.request();
    assert!(!resumed.state.read().unwrap().queued);
    tx.send_replace(false);
    resumed
        .install(staged(&dir, &second), &dir, &store, &rx)
        .unwrap();
    assert!(old.lookup("a7.example", 1).is_some());
    let current = resumed.snapshot().unwrap();
    assert!(current.lookup("a7.example", 1).is_none());
    assert!(current.lookup("b7.example", 1).is_some());
    let meta: serde_json::Value = store.read(METADATA).unwrap();
    assert_eq!(meta["adguard-dns"]["rules"], 2000);
    assert_eq!(fs::read(dir.join(CACHE)).unwrap(), second);
    let stale = SystemTime::now() - DAY - Duration::from_secs(1);
    resumed.state.write().unwrap().modified = Some(stale);
    assert!(!resumed.begin(Some(Instant::now())));
    assert!(resumed.begin(Some(Instant::now() - RETRY)));
}
#[tokio::test]
async fn publisher_tls_request_streams_and_rejects_redirect_html_size_and_broken_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = rcgen::generate_simple_self_signed(vec![fetch::HOST.to_owned()]).unwrap();
    let cert = key.cert.der().clone();
    let tls = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.clone()],
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der())
            .into(),
    )
    .unwrap();
    let source = fixture("p", 1800);
    let body = source.clone();
    let service = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        for (idx, headers) in [
            format!(
                "200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain",
                body.len()
            ),
            "302 Found\r\nLocation: https://127.0.0.1/x\r\nContent-Length: 0".into(),
            "200 OK\r\nContent-Type: text/html\r\nContent-Length: 0".into(),
            format!("200 OK\r\nContent-Length: {}", index::LIMIT + 1),
            "200 OK\r\nTransfer-Encoding: chunked".into(),
            "200 OK\r\nTransfer-Encoding: chunked".into(),
        ]
        .iter()
        .enumerate()
        {
            let (stream, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") && header.len() < 2048 {
                header.push(stream.read_u8().await.unwrap());
            }
            let request = std::str::from_utf8(&header).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /adguardsdnsfilter/filters/filter.txt http/1.1"));
            assert!(request.contains("host: adguardteam.github.io"));
            stream
                .write_all(format!("HTTP/1.1 {headers}\r\nConnection: close\r\n\r\n").as_bytes())
                .await
                .unwrap();
            if idx == 0 {
                for piece in body.chunks(303) {
                    stream.write_all(piece).await.unwrap();
                }
            }
            if idx == 4 {
                stream.write_all(b"A\r\ntwo").await.unwrap();
            }
            if idx == 5 {
                let chunk = [b'a'; 32768];
                for _ in 0..=index::LIMIT / chunk.len() {
                    stream.write_all(b"8000\r\n").await.unwrap();
                    stream.write_all(&chunk).await.unwrap();
                    stream.write_all(b"\r\n").await.unwrap();
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
            }
            let _ = stream.shutdown().await;
        }
    });
    let transport = Doh::new(false);
    transport.trust(cert);
    let file = fetch::fetch_at(
        &transport,
        addr,
        dir.path(),
        &crate::dnsserver::vpn::Route::system(),
    )
    .await
    .unwrap();
    assert_eq!(fs::read(&file).unwrap(), source);
    drop(file);
    for _ in 0..5 {
        assert!(fetch::fetch_at(
            &transport,
            addr,
            dir.path(),
            &crate::dnsserver::vpn::Route::system()
        )
        .await
        .is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    service.await.unwrap();
}
