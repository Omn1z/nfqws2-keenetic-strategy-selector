use super::*;

const NAME: &str = "office.test";

fn exact_raw(port: u16, others: Vec<Value>) -> Value {
    let mut raw = config::defaults();
    raw["default_upstream"] = upstream(port);
    raw["default_pool"] = json!(others);
    raw["rules"] = json!([]);
    raw["timeout_seconds"] = json!(1);
    raw["scheduler_enabled"] = json!(false);
    raw["fast_dns"] = json!(false);
    raw["awg_fallback"] = json!("off");
    raw["filtering"] = json!({"enabled":false});
    raw
}

fn upstream(port: u16) -> Value {
    json!({"address":format!("https://dns.test:{port}/dns-query"),"bootstrap_ips":["127.0.0.1"]})
}

fn answer(wire: &mut Vec<u8>, ttl: u32) {
    address_answer(wire, [192, 0, 2, 18].into(), ttl);
}

fn address_answer(wire: &mut Vec<u8>, address: std::net::IpAddr, ttl: u32) {
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[7] = 1;
    wire.extend([192, 12, 0, if address.is_ipv4() { 1 } else { 28 }, 0, 1]);
    wire.extend(ttl.to_be_bytes());
    match address {
        std::net::IpAddr::V4(ip) => {
            wire.extend([0, 4]);
            wire.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            wire.extend([0, 16]);
            wire.extend(ip.octets());
        }
    }
}

fn test_engine(raw: &Value, schedule: Arc<scheduler::Schedule>) -> Arc<Engine> {
    Engine::new(
        Config::from_value(raw).unwrap(),
        Arc::new(Mutex::new(Diagnostics::new(false))),
        schedule,
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        Default::default(),
    )
}

#[tokio::test]
async fn static_managed_origin_receipt_rejects_replacement_and_does_not_keep_engine_alive() {
    let raw = exact_raw(1, vec![]);
    let old = test_engine(&raw, Default::default());
    let active = ArchiveResolver::pinned_managed(old.clone());
    let receipt = active.managed_origin_receipt().unwrap();
    assert!(receipt.same(&active));
    let replacement = ArchiveResolver::pinned_managed(test_engine(&raw, Default::default()));
    assert!(!receipt.same(&replacement));
    assert!(ArchiveResolver::firmware()
        .managed_origin_receipt()
        .is_none());
    old.stopped.send_replace(true);
    assert!(!receipt.same(&active));
    let weak = Arc::downgrade(&old);
    drop(active);
    drop(old);
    assert!(weak.upgrade().is_none());
    assert!(!receipt.same(&replacement));
}

#[tokio::test]
async fn warm_named_transport_observes_only_local_managed_dns_and_retains_wire_ttl() {
    use std::time::Instant;

    const FAILURE: FailedRoute = FailedRoute { epoch: 23, generation: 9 };
    let expected = [
        "2001:db8:118::11".parse::<std::net::IpAddr>().unwrap(),
        "2001:db8:118::12".parse::<std::net::IpAddr>().unwrap(),
    ];
    let (port, cert, calls, server) = scripted_doh(true, None, move |wire, name, kind| {
        assert_eq!((name, kind), (NAME, 28));
        address_answer(wire, expected[0], 60);
        address_answer(wire, expected[1], 31);
        wire[7] = 2;
    }).await;
    #[derive(Default)]
    struct Capture {
        answers: Mutex<Vec<(Instant, ManagedOriginReceipt)>>,
    }
    impl RouteObserver for Capture {
        fn select(&self, _: &str, _: Option<std::net::IpAddr>) -> io::Result<Option<RouteMatch>> {
            Ok(None)
        }
        fn install(
            &self,
            _: RouteMatch,
            _: &str,
            _: DnsOrigin<'_>,
            _: &nfqws2_dns::RouteAnswer,
        ) -> io::Result<(bool, u64)> {
            unreachable!("no routed payload selectors in this fixture")
        }
        fn capture_warm_transport(&self, name: &str) -> Option<FailedRoute> {
            (name == NAME).then_some(FAILURE)
        }
        fn observe_warm_transport(&self, observed: WarmDnsObservation<'_>) {
            assert_eq!(observed.failure, FAILURE);
            assert_eq!(observed.name, NAME);
            nfqws2_dns::validate_answer(observed.query, observed.reply).unwrap();
            let answer = nfqws2_dns::route_answer(observed.reply).unwrap().unwrap();
            assert_eq!(answer.addresses, [
                "2001:db8:118::11".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8:118::12".parse::<std::net::IpAddr>().unwrap(),
            ]);
            assert_eq!(answer.ttl, 31);
            assert_eq!(observed.source.route, "nfqws");
            assert!(observed.source.upstream.starts_with("https://dns.test:"));
            self.answers.lock().unwrap().push((observed.anchor, observed.resolver));
        }
    }
    let capture = Arc::new(Capture::default());
    let observer = Arc::new(routing::Observer::default());
    observer.register(capture.clone());
    let engine = Engine::new(
        Config::from_value(&exact_raw(port, vec![])).unwrap(),
        Arc::new(Mutex::new(Diagnostics::new(false))),
        Default::default(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        observer,
    );
    engine.trust(cert);
    let query = nfqws2_dns::build_query(NAME, 28, 0x138).unwrap();
    let local = Some(std::net::Ipv4Addr::LOCALHOST.into());
    let listener = Bound::bind("127.0.0.1:0".parse().unwrap()).await.unwrap()
        .start(engine.clone(), Default::default());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&query, listener.addr).await.unwrap();
    let mut response = [0; 512];
    let (size, from) = timeout(Duration::from_secs(3), client.recv_from(&mut response)).await.unwrap().unwrap();
    assert_eq!(from, listener.addr);
    assert_eq!(response[3] & 15, 0);
    assert_eq!(nfqws2_dns::route_answer(&response[..size]).unwrap().unwrap().addresses, expected);
    let mut tcp = TcpStream::connect(listener.addr).await.unwrap();
    tcp.write_u16(query.len() as u16).await.unwrap();
    tcp.write_all(&query).await.unwrap();
    let size = timeout(Duration::from_secs(3), tcp.read_u16()).await.unwrap().unwrap();
    tcp.read_exact(&mut response[..size as usize]).await.unwrap();
    assert_eq!(response[3] & 15, 0);
    assert_eq!(nfqws2_dns::route_answer(&response[..size as usize]).unwrap().unwrap().addresses, expected);
    assert!(engine.exchange(&query, "client", "udp", Some([198, 51, 100, 20].into())).await.is_ok());
    assert!(engine.exchange(&query, "local", "api", local).await.is_ok());
    let resolver = ArchiveResolver::pinned_managed(engine);
    {
        let answers = capture.answers.lock().unwrap();
        let [(anchor, receipt)] = answers.as_slice() else { panic!("one fresh upstream observation expected") };
        assert!(*anchor <= Instant::now());
        assert!(receipt.same(&resolver));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    listener.stop().await;
    server.abort();
}

#[tokio::test]
async fn static_managed_timeout_requires_dispatched_doh_without_mixed_failures() {
    let gate = DohGate::new();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let listener = || TcpListener::bind("127.0.0.1:0");
    let (slow, cert, calls, slow_server) = serve_doh(
        listener().await.unwrap(),
        &key,
        true,
        Some(gate.clone()),
        "/dns-query",
        |wire, _, _| answer(wire, 15),
    );
    let (invalid, _, invalid_calls, invalid_server) = serve_doh(
        listener().await.unwrap(),
        &key,
        false,
        None,
        "/dns-query",
        |wire, _, _| {
            answer(wire, 15);
            wire[0] ^= 1;
        },
    );
    let (rejected, _, rejected_calls, rejected_server) =
        scripted_doh(false, None, |wire, _, _| answer(wire, 15)).await;
    let (negative, _, negative_calls, negative_server) = serve_doh(
        listener().await.unwrap(),
        &key,
        true,
        None,
        "/dns-query",
        |wire, _, _| {
            *wire = nfqws2_dns::response_error(wire, 3);
        },
    );
    let stalls = [None, Some(invalid), Some(rejected)];
    let query = nfqws2_dns::build_query(NAME, 1, 0x128).unwrap();
    for alternative in stalls {
        let engine = test_engine(
            &exact_raw(slow, alternative.map(upstream).into_iter().collect()),
            Default::default(),
        );
        engine.trust(cert.clone());
        let resolver = ArchiveResolver::pinned_managed(engine.clone());
        let request = resolver.fresh_managed_reply(&query);
        let (result, ()) = tokio::join!(request, gate.next_request());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(is_managed_upstream_timeout(&error), alternative.is_none());
        assert_eq!(engine.stats().queries, 0);
        assert_eq!(engine.cache.status().entries, 0);
    }
    assert_eq!(calls.load(Ordering::SeqCst), stalls.len());
    assert_eq!(invalid_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rejected_calls.load(Ordering::SeqCst), 0);
    let engine = test_engine(
        &exact_raw(negative, vec![upstream(slow)]),
        Default::default(),
    );
    engine.trust(cert);
    let resolver = ArchiveResolver::pinned_managed(engine);
    let reply = resolver.fresh_managed_reply(&query).await.unwrap();
    assert_eq!(reply[3] & 15, 3);
    assert_eq!(negative_calls.load(Ordering::SeqCst), 1);
    for server in [
        slow_server,
        invalid_server,
        rejected_server,
        negative_server,
    ] {
        server.abort();
    }
}

#[tokio::test]
async fn static_managed_scheduler_wait_expires_without_an_upstream_timeout() {
    let schedule = Arc::new(scheduler::Schedule::default());
    let engine = test_engine(&exact_raw(1, vec![]), schedule.clone());
    let resolver = ArchiveResolver::pinned_managed(engine.clone());
    let _held = schedule
        .slots
        .acquire_many(scheduler::LIMIT as u32)
        .await
        .unwrap();
    let query = nfqws2_dns::build_query(NAME, 1, 0x129).unwrap();
    assert!(timeout(
        Duration::from_millis(25),
        resolver.fresh_managed_reply(&query)
    )
    .await
    .is_err());
    assert_eq!(engine.stats().queries, 0);
    assert_eq!(engine.cache.status().entries, 0);
}

#[tokio::test]
async fn static_apply_reuses_confirmed_managed_positive_only_until_its_original_ttl() {
    check_static_apply_hint(RetryCase::Expiry).await;
}

#[tokio::test]
async fn static_apply_discards_hint_after_authority_changes() {
    check_static_apply_hint(RetryCase::Negative).await;
    check_static_apply_hint(RetryCase::Catalog).await;
    check_static_apply_hint(RetryCase::Methods).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RetryCase {
    Expiry,
    Negative,
    Catalog,
    Methods,
}

async fn check_static_apply_hint(case: RetryCase) {
    use crate::awg_rules::kernel::{static_apply_for_test, StaticApplyFixture};
    use nfqws2_awg_rules::kernel::{dns_request, DnsSnapshot, Operation};

    const FAILURE: &str = "fixture route writer failed";
    let gate = DohGate::new();
    let mode = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream_mode = mode.clone();
    let ttl = if case == RetryCase::Expiry { 4 } else { 30 };
    let (port, cert, calls, server) =
        scripted_doh(true, Some(gate.clone()), move |wire, name, kind| {
            assert_eq!(name, NAME);
            assert_eq!(kind, 1);
            if upstream_mode.load(Ordering::SeqCst) {
                *wire = nfqws2_dns::response_error(wire, 3);
            } else {
                answer(wire, ttl);
            }
        })
        .await;
    let dir = tempfile::tempdir().unwrap();
    let dns_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns_port = dns_listener.local_addr().unwrap().port();
    drop(dns_listener);
    let mut raw = exact_raw(port, vec![]);
    raw["listen_host"] = json!("127.0.0.1");
    raw["dns_port"] = json!(dns_port);
    let catalog_dir = dir.path().join("dns-blocklists");
    let write_catalog = |tag: &str| {
        let file = (0..1200)
            .map(|n| format!("||{tag}{n}.test^\n"))
            .collect::<String>();
        std::fs::write(catalog_dir.join("adguard-dns.txt"), file).unwrap();
    };
    if case == RetryCase::Catalog {
        std::fs::create_dir(&catalog_dir).unwrap();
        write_catalog("old");
        raw["filtering"] =
            json!({"enabled":true,"lists":["adguard-dns"],"custom_rules":[],"allowlist":[]});
    }
    std::fs::write(dir.path().join("dnsserver.json"), raw.to_string()).unwrap();
    let shared = state(&dir);
    let app = crate::http::router(shared.clone());
    request(&app, "/api/dnsserver/start", Some(json!({})), 200).await;
    let engine = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    engine.trust(cert);
    let catalog = engine
        .filter
        .as_ref()
        .and_then(|filter| filter.feed.clone());
    if let Some(catalog) = &catalog {
        let index = timeout(Duration::from_secs(3), catalog.query_snapshot())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(index.len(), 1200);
    }
    request(
        &app,
        "/api/awg2/routing/config",
        Some(json!({"mode":"zones","domain_source":"resolve","zones":[{
            "enabled":true,"name":"office","tunnel_id":"awg0","domains":[NAME],"include_subdomains":false
        }]})),
        200,
    )
    .await;
    let confirmed = Arc::new(DnsSnapshot {
        request: dns_request(&shared.store, Operation::Apply)
            .unwrap()
            .unwrap(),
        answers: std::collections::BTreeMap::from([(
            NAME.into(),
            vec!["192.0.2.18".parse().unwrap()],
        )]),
    });
    assert_eq!(confirmed.request.names, [NAME]);
    assert!(confirmed.request.dual_stack.is_empty() && confirmed.request.ipv6_only.is_empty());
    let fixture = Arc::new(StaticApplyFixture::default());
    let begin = |expect: Option<bool>| {
        let s = shared.clone();
        let confirmed = confirmed.clone();
        let fixture = fixture.clone();
        tokio::task::spawn_blocking(move || {
            let mut observed = None;
            let result =
                static_apply_for_test(&s, &fixture, &confirmed, |snapshot, reused, expiry| {
                    assert_eq!(snapshot, confirmed.as_ref());
                    assert_eq!(Some(reused), expect);
                    observed = Some(expiry);
                    // Exercise the actual failure publication and retain just this verified receipt.
                    Err(io::Error::other(FAILURE))
                });
            (result, observed)
        })
    };

    let capture = begin(Some(false));
    gate.next_request().await;
    gate.release(1);
    let (result, first_expiry) = capture.await.unwrap();
    assert_eq!(result.unwrap_err().to_string(), FAILURE);
    let first_expiry = first_expiry.unwrap();
    assert!(first_expiry > Instant::now());

    match case {
        RetryCase::Expiry => {
            let retry = begin(Some(true));
            gate.next_request().await;
            let (result, expiry) = retry.await.unwrap();
            assert_eq!(result.unwrap_err().to_string(), FAILURE);
            assert_eq!(expiry, Some(first_expiry));
            tokio::time::sleep_until(first_expiry.into()).await;
        }
        RetryCase::Negative => {
            mode.store(true, Ordering::SeqCst);
            let negative = begin(None);
            gate.next_request().await;
            gate.release(1);
            let (result, observed) = negative.await.unwrap();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
            assert_eq!(observed, None);
        }
        RetryCase::Catalog => {
            let catalog = catalog.unwrap();
            let old = catalog.snapshot().unwrap();
            write_catalog("new");
            catalog
                .restore_fixture(&catalog_dir, &shared.store)
                .unwrap();
            assert!(!Arc::ptr_eq(&old, &catalog.snapshot().unwrap()));
        }
        RetryCase::Methods => {
            // An identical final set cannot restore authority to an old lookup.
            engine.methods.apply(std::collections::HashSet::from([
                "https://unused.test/dns-query".into(),
            ]));
            engine.methods.apply(Default::default());
        }
    }

    let no_hint = begin(None);
    gate.next_request().await;
    let (result, observed) = no_hint.await.unwrap();
    let error = result.unwrap_err();
    // The test seam reports no committed-snapshot path as NotFound. The
    // network classifier is exercised independently in the transport test.
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(observed, None);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        if matches!(case, RetryCase::Catalog | RetryCase::Methods) {
            2
        } else {
            3
        }
    );
    assert_eq!(engine.stats().queries, 0);
    assert_eq!(engine.cache.status().entries, 0);
    shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn static_apply_reuses_whole_snapshot_with_matching_a_and_aaaa_and_typed_timeout() {
    check_static_batch_hint(FreshPairs::Matching).await;
}

#[tokio::test]
async fn static_apply_discards_batch_hint_on_negative_or_changed_aaaa_alongside_timeout() {
    check_static_batch_hint(FreshPairs::Negative).await;
    check_static_batch_hint(FreshPairs::Changed).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreshPairs {
    Matching,
    Negative,
    Changed,
}

const A: &str = "alpha.office.test";
const B: &str = "beta.office.test";
const C: &str = "charlie.office.test";
const D: &str = "delta.office.test";
const BATCH_PAIRS: [(&str, u16); 6] = [(A, 1), (A, 28), (B, 1), (B, 28), (C, 1), (D, 1)];

fn batch_address(name: &str, kind: u16) -> std::net::IpAddr {
    let index = 1 + [A, B, C, D].iter().position(|item| *item == name).unwrap() as u8;
    match kind {
        1 => [192, 0, 2, index].into(),
        28 => std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index.into()).into(),
        _ => panic!("unexpected query type {kind}"),
    }
}

struct BatchPanel {
    _dir: tempfile::TempDir,
    shared: Shared,
    engine: Arc<Engine>,
    request: nfqws2_awg_rules::kernel::DnsRequest,
    listen: SocketAddr,
}

impl BatchPanel {
    fn snapshot(
        &self,
        address: impl Fn(&str, u16) -> std::net::IpAddr,
    ) -> Arc<nfqws2_awg_rules::kernel::DnsSnapshot> {
        let mut answers = std::collections::BTreeMap::<String, Vec<std::net::IpAddr>>::new();
        for (name, kind) in BATCH_PAIRS {
            answers
                .entry(name.into())
                .or_default()
                .push(address(name, kind));
        }
        Arc::new(nfqws2_awg_rules::kernel::DnsSnapshot {
            request: self.request.clone(),
            answers,
        })
    }
}

async fn batch_panel(
    port: u16,
    cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    filtering: Option<Value>,
) -> BatchPanel {
    use nfqws2_awg_rules::kernel::{dns_request, Operation};
    let dir = tempfile::tempdir().unwrap();
    let mut raw = exact_raw(port, vec![]);
    raw["listen_host"] = json!("127.0.0.1");
    if let Some(filtering) = filtering {
        raw["filtering"] = filtering;
    }
    let (shared, listen) = start_batch_listener(&dir, raw).await;
    let app = crate::http::router(shared.clone());
    let engine = shared
        .dnsserver
        .state
        .lock()
        .await
        .active
        .as_ref()
        .unwrap()
        .engine();
    engine.trust(cert);
    request(
        &app,
        "/api/awg2/routing/config",
        Some(json!({"mode":"zones","domain_source":"resolve","zones":[
            {"enabled":true,"name":"dual","route":"direct","domains":[A,B],"include_subdomains":false},
            {"enabled":true,"name":"v4","tunnel_id":"awg0","domains":[C,D],"include_subdomains":false}
        ]})),
        200,
    )
    .await;
    let request = dns_request(&shared.store, Operation::Apply)
        .unwrap()
        .unwrap();
    assert_eq!(request.names, [A, B, C, D]);
    assert_eq!(request.dual_stack, [A, B]);
    assert!(request.ipv6_only.is_empty());
    BatchPanel {
        _dir: dir,
        shared,
        engine,
        request,
        listen,
    }
}

async fn start_batch_listener(dir: &tempfile::TempDir, mut raw: Value) -> (Shared, SocketAddr) {
    const ATTEMPTS: usize = 8;
    #[cfg(windows)]
    const ADDRESS_IN_USE: i32 = 10048;
    #[cfg(not(windows))]
    const ADDRESS_IN_USE: i32 = libc::EADDRINUSE;
    let busy = io::Error::from_raw_os_error(ADDRESS_IN_USE);
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
    for _ in 0..ATTEMPTS {
        let reserved = match Bound::bind(loopback).await {
            Ok(reserved) => reserved,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("DNS fixture could not reserve TCP/UDP: {error}"),
        };
        let addr = reserved.tcp.local_addr().unwrap();
        raw["dns_port"] = json!(addr.port());
        std::fs::write(dir.path().join("dnsserver.json"), raw.to_string()).unwrap();
        let shared = state(dir);
        drop(reserved);
        match start(State(shared.clone())).await {
            Ok(_) => return (shared, addr),
            Err(ApiError(code, message))
                if code == StatusCode::BAD_REQUEST
                    && message == format!("DNS listen {addr}: {busy}") => {}
            Err(ApiError(code, message)) => panic!("DNS fixture start returned {code}: {message}"),
        }
    }
    panic!("DNS fixture could not reserve and start TCP/UDP after {ATTEMPTS} attempts: {busy}");
}

async fn check_static_batch_hint(outcome: FreshPairs) {
    use crate::awg_rules::kernel::{static_apply_for_test, StaticApplyFixture};
    use std::collections::BTreeMap;
    const FAILURE: &str = "fixture route writer failed";
    const SHORTEST_TTL: u32 = 6;
    let phase = Arc::new(Mutex::new(None));
    let seen = Arc::new(Mutex::new(BTreeMap::<(String, u16), usize>::new()));
    let conflicts = Arc::new(AtomicUsize::new(0));
    let conflict_replies = conflicts.clone();
    let slow_v4 = DohGate::new();
    let slow_v6 = DohGate::new();
    let (v4_gate, v6_gate) = (slow_v4.clone(), slow_v6.clone());
    let (select_phase, reply_phase) = (phase.clone(), phase.clone());
    let queries = seen.clone();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (port, cert, _, server) = serve_doh_by_question(
        origin,
        &key,
        true,
        move |wire, name, kind| {
            assert_eq!(wire[10..12], [0, 0]); // Administrative queries have no ECS.
            assert!(
                BATCH_PAIRS.contains(&(name, kind)),
                "unexpected DNS question {name}/{kind}"
            );
            *queries
                .lock()
                .unwrap()
                .entry((name.to_owned(), kind))
                .or_default() += 1;
            match (name, kind, *select_phase.lock().unwrap()) {
                (A, 1, Some(_)) => Some(v4_gate.clone()),
                // Occupy both lanes before the later conflicting response.
                (A, 28, Some(FreshPairs::Negative | FreshPairs::Changed)) => Some(v6_gate.clone()),
                _ => None,
            }
        },
        "/dns-query",
        move |wire, name, kind| {
            let phase = *reply_phase.lock().unwrap();
            match (name, kind, phase) {
                (B, 28, Some(FreshPairs::Negative)) => {
                    *wire = nfqws2_dns::response_error(wire, 3);
                    conflict_replies.fetch_add(1, Ordering::SeqCst);
                }
                (B, 28, Some(FreshPairs::Changed)) => {
                    address_answer(wire, "2001:db8::beef".parse().unwrap(), 60);
                    conflict_replies.fetch_add(1, Ordering::SeqCst);
                }
                (D, 1, None) => address_answer(wire, batch_address(name, kind), SHORTEST_TTL),
                _ => address_answer(wire, batch_address(name, kind), 60),
            }
        },
    );
    let panel = batch_panel(port, cert, None).await;
    let (shared, engine) = (&panel.shared, &panel.engine);
    let confirmed = panel.snapshot(batch_address);
    let fixture = Arc::new(StaticApplyFixture::default());
    let begin = |expect| {
        let (shared, fixture, confirmed) = (shared.clone(), fixture.clone(), confirmed.clone());
        tokio::task::spawn_blocking(move || {
            let mut observed = None;
            let result =
                static_apply_for_test(&shared, &fixture, &confirmed, |snapshot, reused, expiry| {
                    assert_eq!(Some(reused), expect);
                    assert_eq!(snapshot, confirmed.as_ref());
                    observed = Some(expiry);
                    Err(io::Error::other(FAILURE))
                });
            (result, observed)
        })
    };
    let take_observed = || std::mem::take(&mut *seen.lock().unwrap());
    let expected =
        BTreeMap::from_iter(BATCH_PAIRS.map(|(name, kind)| ((name.to_owned(), kind), 1)));

    let started = Instant::now();
    let (capture, expiry) = begin(Some(false)).await.unwrap();
    assert_eq!(capture.unwrap_err().to_string(), FAILURE);
    assert_eq!(take_observed(), expected);
    let expiry = expiry.unwrap();
    let shortest = Duration::from_secs(SHORTEST_TTL.into());
    assert!(expiry >= started + shortest && expiry <= Instant::now() + shortest);

    *phase.lock().unwrap() = Some(outcome);
    let retry = begin((outcome == FreshPairs::Matching).then_some(true));
    if outcome == FreshPairs::Matching {
        slow_v4.next_request().await;
    } else {
        tokio::join!(slow_v4.next_request(), slow_v6.next_request());
        assert!(!seen.lock().unwrap().contains_key(&(B.to_owned(), 28)));
    }
    let (result, reused_expiry) = retry.await.unwrap();
    let observed = take_observed();
    if outcome == FreshPairs::Matching {
        assert_eq!(result.unwrap_err().to_string(), FAILURE);
        assert_eq!(reused_expiry, Some(expiry));
        assert_eq!(observed, expected);
    } else {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(reused_expiry, None);
        assert_eq!(observed.get(&(A.to_owned(), 1)), Some(&1));
        assert_eq!(observed.get(&(A.to_owned(), 28)), Some(&1));
        assert_eq!(observed.get(&(B.to_owned(), 28)), Some(&1));
        assert_eq!(conflicts.load(Ordering::SeqCst), 1);

        *phase.lock().unwrap() = Some(FreshPairs::Matching);
        let retry = begin(None);
        slow_v4.next_request().await;
        let (result, reused_expiry) = retry.await.unwrap();
        assert!(result.is_err());
        assert_eq!(
            reused_expiry, None,
            "a later timeout cannot revive the stale snapshot"
        );
        assert_eq!(take_observed(), expected);
        assert!(
            Instant::now() < expiry,
            "test must prove invalidation before the TTL expires"
        );
    }
    assert_eq!(engine.stats().queries, 0);
    assert_eq!(engine.cache.status().entries, 0);
    shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn static_changed_proposal_retries_the_whole_compensated_snapshot_at_original_ttl() {
    check_changed_proposal(FirstProposalFailure::Compensated, ProposalReply::Matching).await;
}

#[tokio::test]
async fn static_changed_proposal_discards_the_hint_on_old_unrelated_or_negative_answers() {
    for reply in [
        ProposalReply::Old,
        ProposalReply::Unrelated,
        ProposalReply::Negative,
    ] {
        check_changed_proposal(FirstProposalFailure::Compensated, reply).await;
    }
}

#[tokio::test]
async fn static_changed_proposal_cannot_retry_an_unverified_writer_failure() {
    for failure in [
        FirstProposalFailure::Preflight,
        FirstProposalFailure::AmbiguousRollback,
    ] {
        check_changed_proposal(failure, ProposalReply::Matching).await;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirstProposalFailure {
    Compensated,
    Preflight,
    AmbiguousRollback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProposalReply {
    Matching,
    Old,
    Unrelated,
    Negative,
}

fn proposal_address(name: &str, kind: u16) -> std::net::IpAddr {
    match (name, kind) {
        (A, 1) => [192, 0, 2, 101].into(),
        (B, 28) => "2001:db8::beef".parse().unwrap(),
        _ => batch_address(name, kind),
    }
}

async fn check_changed_proposal(first: FirstProposalFailure, reply: ProposalReply) {
    use crate::awg_rules::kernel::{
        install_route_observer_for_test, static_proposal_apply_for_test, StaticApplyFixture,
        StaticApplyFixtureFailure,
    };
    use std::collections::BTreeMap;

    const SHORTEST_TTL: u32 = 8;
    const FAILURE: &str = "fixture proposal install failed";
    const UNRELATED: &str = "cached.outside.test";
    let phase = Arc::new(Mutex::new(None));
    let (gate_phase, response_phase) = (phase.clone(), phase.clone());
    let seen = Arc::new(Mutex::new(BTreeMap::<(String, u16), usize>::new()));
    let queries = seen.clone();
    let unrelated = Arc::new(AtomicUsize::new(0));
    let unrelated_queries = unrelated.clone();
    let slow = DohGate::new();
    let gate = slow.clone();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (port, cert, _, server) = serve_doh_by_question(
        origin,
        &key,
        true,
        move |wire, name, kind| {
            assert_eq!(wire[10..12], [0, 0]);
            if (name, kind) == (UNRELATED, 1) {
                unrelated_queries.fetch_add(1, Ordering::SeqCst);
                return None;
            }
            assert!(BATCH_PAIRS.contains(&(name, kind)));
            *queries
                .lock()
                .unwrap()
                .entry((name.to_owned(), kind))
                .or_default() += 1;
            (gate_phase.lock().unwrap().is_some() && (name, kind) == (A, 1)).then(|| gate.clone())
        },
        "/dns-query",
        move |wire, name, kind| {
            let phase = *response_phase.lock().unwrap();
            match (name, kind, phase) {
                (UNRELATED, 1, _) => answer(wire, 60),
                (B, 28, Some(ProposalReply::Old)) => address_answer(wire, batch_address(B, 28), 60),
                (B, 28, Some(ProposalReply::Unrelated)) => {
                    address_answer(wire, "2001:db8::cafe".parse().unwrap(), 60);
                }
                (B, 28, Some(ProposalReply::Negative)) => {
                    *wire = nfqws2_dns::response_error(wire, 3)
                }
                (D, 1, None) => address_answer(wire, proposal_address(name, kind), SHORTEST_TTL),
                _ => address_answer(wire, proposal_address(name, kind), 60),
            }
        },
    );
    let panel = batch_panel(port, cert, None).await;
    install_route_observer_for_test(&panel.shared);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(panel.listen).await.unwrap();
    let mut tcp = TcpStream::connect(panel.listen).await.unwrap();
    let query = nfqws2_dns::build_query(UNRELATED, 1, 81).unwrap();
    let expected_addr = std::net::Ipv4Addr::new(192, 0, 2, 18);
    assert_eq!(
        nfqws2_dns::first_ipv4(&udp_query(&udp, &query).await).unwrap(),
        expected_addr
    );
    let confirmed = panel.snapshot(batch_address);
    let proposal = panel.snapshot(proposal_address);
    assert_ne!(proposal.answers, confirmed.answers);
    let fixture = Arc::new(StaticApplyFixture::default());
    let begin = |expect: Option<bool>| {
        let shared = panel.shared.clone();
        let confirmed = confirmed.clone();
        let (proposal, fixture) = (proposal.clone(), fixture.clone());
        tokio::task::spawn_blocking(move || {
            let mut observed = None;
            let result = static_proposal_apply_for_test(
                &shared,
                &fixture,
                &confirmed,
                |snapshot, reused, expiry| {
                    assert_eq!(
                        Some(reused),
                        expect,
                        "unexpected writer after {first:?} and {reply:?}"
                    );
                    assert_eq!(snapshot, proposal.as_ref());
                    observed = Some(expiry);
                    if reused {
                        return Ok(());
                    }
                    Err(match first {
                        FirstProposalFailure::Compensated => {
                            StaticApplyFixtureFailure::Compensated(io::Error::other(FAILURE))
                        }
                        FirstProposalFailure::Preflight => StaticApplyFixtureFailure::Unverified(
                            io::Error::new(io::ErrorKind::PermissionDenied, FAILURE),
                        ),
                        FirstProposalFailure::AmbiguousRollback => {
                            StaticApplyFixtureFailure::Unverified(io::Error::other(FAILURE))
                        }
                    })
                },
            );
            (result, observed)
        })
    };
    let expected =
        BTreeMap::from_iter(BATCH_PAIRS.map(|(name, kind)| ((name.to_owned(), kind), 1)));
    let take_observed = || std::mem::take(&mut *seen.lock().unwrap());
    let started = Instant::now();
    let (result, expiry) = begin(Some(false)).await.unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.to_string(), FAILURE);
    assert_eq!(
        error.kind(),
        if first == FirstProposalFailure::Preflight {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::Other
        }
    );
    assert_eq!(take_observed(), expected);
    let expiry = expiry.unwrap();
    let shortest = Duration::from_secs(SHORTEST_TTL.into());
    assert!(expiry >= started + shortest && expiry <= Instant::now() + shortest);
    let reply_after_failure = udp_query(&udp, &query).await;
    if first == FirstProposalFailure::Compensated {
        assert_eq!(reply_after_failure, nfqws2_dns::response_error(&query, 2));
    } else {
        assert_eq!(
            nfqws2_dns::first_ipv4(&reply_after_failure).unwrap(),
            expected_addr
        );
    }

    *phase.lock().unwrap() = Some(reply);
    let want_reuse = first == FirstProposalFailure::Compensated && reply == ProposalReply::Matching;
    let retry = begin(want_reuse.then_some(true));
    slow.next_request().await;
    let (result, used_expiry) = retry.await.unwrap();
    assert_eq!(take_observed(), expected);
    if want_reuse {
        result.unwrap();
        assert_eq!(used_expiry, Some(expiry));
    } else {
        assert!(result.is_err());
        assert_eq!(used_expiry, None);
    }
    let reply_after_retry = tcp_query(&mut tcp, &query).await;
    if first == FirstProposalFailure::Compensated && !want_reuse {
        assert_eq!(reply_after_retry, nfqws2_dns::response_error(&query, 2));
    } else {
        assert_eq!(
            nfqws2_dns::first_ipv4(&reply_after_retry).unwrap(),
            expected_addr
        );
    }

    // Neither rejection nor successful consumption can leave a reusable hint.
    if first == FirstProposalFailure::Compensated {
        *phase.lock().unwrap() = Some(ProposalReply::Matching);
        let retry = begin(None);
        slow.next_request().await;
        let (result, used_expiry) = retry.await.unwrap();
        assert!(result.is_err());
        assert_eq!(used_expiry, None);
        assert_eq!(take_observed(), expected);
        assert!(Instant::now() < expiry);
    }
    assert_eq!(panel.engine.stats().queries, 3);
    assert_eq!(panel.engine.cache.status().entries, 1);
    assert_eq!(unrelated.load(Ordering::SeqCst), 1);
    panel.shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn first_static_resolve_retries_compensated_whole_snapshot_with_original_ttl() {
    check_initial_static_retry(InitialFailure::Compensated).await;
}

#[tokio::test]
async fn first_static_resolve_requires_compensation_on_the_same_boot_without_foreign_routes() {
    for failure in [
        InitialFailure::BeforeWrite,
        InitialFailure::ForeignRoute,
        InitialFailure::UnknownRollback,
        InitialFailure::Reboot,
    ] {
        check_initial_static_retry(failure).await;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitialFailure {
    Compensated,
    BeforeWrite,
    ForeignRoute,
    UnknownRollback,
    Reboot,
}

#[derive(Default)]
struct InitialRoutes {
    owned: std::collections::BTreeSet<std::net::IpAddr>,
    foreign: std::collections::BTreeSet<std::net::IpAddr>,
    writes: usize,
}

async fn check_initial_static_retry(failure: InitialFailure) {
    use crate::awg_rules::kernel::{
        static_initial_apply_for_test, StaticApplyFixtureFailure, StaticInitialApplyFixture,
    };
    use nfqws2_awg_rules::kernel::{confirmed_static_dns_retry, scheduled, Schedule};
    use std::{collections::BTreeMap, sync::atomic::AtomicBool};

    const SHORTEST_TTL: u32 = 7;
    const FIRST_BOOT: &str = "11111111-1111-1111-1111-111111111111";
    const SECOND_BOOT: &str = "22222222-2222-2222-2222-222222222222";
    const FAILURE: &str = "fixture first install failed";
    let retrying = Arc::new(AtomicBool::new(false));
    let (gate_phase, reply_phase) = (retrying.clone(), retrying.clone());
    let seen = Arc::new(Mutex::new(BTreeMap::<(String, u16), usize>::new()));
    let upstream_queries = seen.clone();
    let slow = DohGate::new();
    let gate = slow.clone();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (port, cert, _, server) = serve_doh_by_question(
        origin,
        &key,
        true,
        move |wire, name, kind| {
            assert_eq!(wire[10..12], [0, 0]);
            assert!(BATCH_PAIRS.contains(&(name, kind)));
            *upstream_queries
                .lock()
                .unwrap()
                .entry((name.to_owned(), kind))
                .or_default() += 1;
            (gate_phase.load(Ordering::SeqCst) && (name, kind) == (A, 1)).then(|| gate.clone())
        },
        "/dns-query",
        move |wire, name, kind| {
            let ttl = if (name, kind) == (D, 1) && !reply_phase.load(Ordering::SeqCst) {
                SHORTEST_TTL
            } else {
                60
            };
            address_answer(wire, proposal_address(name, kind), ttl);
        },
    );
    let panel = batch_panel(port, cert, None).await;
    let assert_initial_store = || {
        assert!(
            confirmed_static_dns_retry(&panel.shared.store, &panel.request)
                .unwrap()
                .is_none()
        );
        assert!(matches!(scheduled(&panel.shared.store), Ok(Schedule::Idle)));
    };
    assert_initial_store();
    let snapshot = panel.snapshot(proposal_address);
    let first_route = proposal_address(A, 1);
    let mut routes = InitialRoutes::default();
    if failure == InitialFailure::ForeignRoute {
        routes.foreign.insert(first_route);
    }
    let routes = Arc::new(Mutex::new(routes));
    let fixture = Arc::new(StaticInitialApplyFixture::default());
    let begin = |boot: &'static str, expect: Option<bool>| {
        let (shared, request) = (panel.shared.clone(), panel.request.clone());
        let (fixture, snapshot, routes) = (fixture.clone(), snapshot.clone(), routes.clone());
        tokio::task::spawn_blocking(move || {
            let mut observed = None;
            let result = static_initial_apply_for_test(
                &shared,
                &fixture,
                &request,
                boot,
                |proposed, reused, expiry| {
                    assert_eq!(Some(reused), expect, "unexpected writer after {failure:?}");
                    assert_eq!(proposed, snapshot.as_ref());
                    observed = Some(expiry);
                    let mut routes = routes.lock().unwrap();
                    assert!(routes.owned.is_empty());
                    if reused {
                        assert!(routes.foreign.is_empty());
                        routes
                            .owned
                            .extend(proposed.answers.values().flatten().copied());
                        return Ok(());
                    }
                    let error = io::Error::other(FAILURE);
                    if failure == InitialFailure::BeforeWrite
                        || routes.foreign.contains(&first_route)
                    {
                        return Err(StaticApplyFixtureFailure::Unverified(error));
                    }
                    assert!(routes.owned.insert(first_route));
                    routes.writes += 1;
                    if failure == InitialFailure::UnknownRollback {
                        return Err(StaticApplyFixtureFailure::Unverified(error));
                    }
                    assert!(routes.owned.remove(&first_route));
                    routes.writes += 1;
                    assert!(routes.owned.is_empty() && routes.foreign.is_empty());
                    Err(StaticApplyFixtureFailure::Compensated(error))
                },
            );
            (result, observed)
        })
    };
    let expected =
        BTreeMap::from_iter(BATCH_PAIRS.map(|(name, kind)| ((name.to_owned(), kind), 1)));
    let take_observed = || std::mem::take(&mut *seen.lock().unwrap());
    let started = Instant::now();
    let (initial, expiry) = begin(FIRST_BOOT, Some(false)).await.unwrap();
    assert_eq!(initial.unwrap_err().to_string(), FAILURE);
    assert_eq!(take_observed(), expected);
    let expiry = expiry.unwrap();
    let ttl = Duration::from_secs(SHORTEST_TTL.into());
    assert!(expiry >= started + ttl && expiry <= Instant::now() + ttl);
    assert_initial_store();
    {
        let routes = routes.lock().unwrap();
        let writes = match failure {
            InitialFailure::BeforeWrite | InitialFailure::ForeignRoute => 0,
            InitialFailure::UnknownRollback => 1,
            InitialFailure::Compensated | InitialFailure::Reboot => 2,
        };
        assert_eq!(routes.writes, writes);
        assert_eq!(
            routes.owned.contains(&first_route),
            failure == InitialFailure::UnknownRollback
        );
        assert_eq!(
            routes.foreign.contains(&first_route),
            failure == InitialFailure::ForeignRoute
        );
    }

    retrying.store(true, Ordering::SeqCst);
    let boot = if failure == InitialFailure::Reboot {
        SECOND_BOOT
    } else {
        FIRST_BOOT
    };
    let can_retry = failure == InitialFailure::Compensated;
    let retry = begin(boot, can_retry.then_some(true));
    slow.next_request().await;
    let (result, observed_expiry) = retry.await.unwrap();
    assert_eq!(take_observed(), expected);
    if can_retry {
        result.unwrap();
        assert_eq!(observed_expiry, Some(expiry));
        assert_eq!(
            routes.lock().unwrap().owned,
            snapshot.answers.values().flatten().copied().collect()
        );

        let consumed = begin(FIRST_BOOT, None);
        slow.next_request().await;
        let (result, observed_expiry) = consumed.await.unwrap();
        assert!(result.is_err());
        assert_eq!(observed_expiry, None);
        assert_eq!(take_observed(), expected);
    } else {
        assert!(result.is_err());
        assert_eq!(observed_expiry, None);
    }
    assert!(
        Instant::now() < expiry,
        "safety boundary must be tested before the TTL expires"
    );
    assert_eq!(panel.engine.stats().queries, 0);
    assert_eq!(panel.engine.cache.status().entries, 0);
    panel.shared.dnsserver.shutdown().await;
    server.abort();
}

async fn publish_first_static_failure(panel: &BatchPanel, compensated: bool) {
    use crate::awg_rules::kernel::{
        static_initial_apply_for_test, StaticApplyFixtureFailure, StaticInitialApplyFixture,
    };

    let request = panel.request.clone();
    let state = panel.shared.clone();
    let expected = panel.snapshot(proposal_address);
    let error = tokio::task::spawn_blocking(move || {
        static_initial_apply_for_test(
            &state,
            &StaticInitialApplyFixture::default(),
            &request,
            "11111111-1111-1111-1111-111111111111",
            |snapshot, reused, _| {
                assert_eq!(snapshot, expected.as_ref());
                assert!(!reused);
                let error = io::Error::other("first route writer fixture");
                Err(if compensated {
                    StaticApplyFixtureFailure::Compensated(error)
                } else {
                    StaticApplyFixtureFailure::Unverified(error)
                })
            },
        )
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.to_string(), "first route writer fixture");
}

async fn udp_query(socket: &UdpSocket, wire: &[u8]) -> Vec<u8> {
    socket.send(wire).await.unwrap();
    let mut answer = vec![0u8; 1024];
    let size = timeout(Duration::from_secs(4), socket.recv(&mut answer))
        .await
        .unwrap()
        .unwrap();
    answer.truncate(size);
    answer
}

async fn tcp_query(socket: &mut TcpStream, wire: &[u8]) -> Vec<u8> {
    timeout(Duration::from_secs(4), async {
        socket.write_u16(wire.len() as u16).await.unwrap();
        socket.write_all(wire).await.unwrap();
        let size = socket.read_u16().await.unwrap() as usize;
        let mut answer = vec![0; size];
        socket.read_exact(&mut answer).await.unwrap();
        answer
    })
    .await
    .unwrap()
}

fn cname_answer(wire: &mut Vec<u8>, name: &str) {
    let target = nfqws2_dns::build_query(name, 1, 0).unwrap();
    let target = &target[12..target.len() - 4];
    wire[2..4].copy_from_slice(&[0x81, 0x80]);
    wire[7] = 1;
    wire.extend([192, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
    wire.extend((target.len() as u16).to_be_bytes());
    wire.extend(target);
}

#[tokio::test]
async fn cold_compensated_apply_fails_managed_udp_tcp_and_diagnostics_but_keeps_cache_and_filter() {
    use crate::awg_rules::kernel::{
        install_route_observer_for_test, publish_dns_operation_for_test,
    };
    use nfqws2_awg_rules::kernel::Operation;
    use std::collections::BTreeMap;

    const UNRELATED: &str = "cached.outside.test";
    const ALIAS: &str = "alias.outside.test";
    const NEGATIVE: &str = "missing.outside.test";
    const BLOCKED: &str = "blocked.outside.test";
    const INDIRECT: &str = "redirect.outside.test";
    let seen = Arc::new(Mutex::new(BTreeMap::<(String, u16), usize>::new()));
    let requests = seen.clone();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (port, cert, _, server) = serve_doh_by_question(
        origin,
        &key,
        true,
        move |wire, name, kind| {
            assert_eq!(wire[10..12], [0, 0]);
            *requests
                .lock()
                .unwrap()
                .entry((name.into(), kind))
                .or_default() += 1;
            None
        },
        "/dns-query",
        move |wire, name, kind| {
            if BATCH_PAIRS.contains(&(name, kind)) {
                address_answer(wire, proposal_address(name, kind), 60);
            } else {
                match (name, kind) {
                    (UNRELATED, 1) => answer(wire, 60),
                    (ALIAS, 5) => cname_answer(wire, UNRELATED),
                    (INDIRECT, 1) => cname_answer(wire, BLOCKED),
                    (NEGATIVE, 28) => *wire = nfqws2_dns::response_error(wire, 3),
                    _ => panic!("unexpected upstream question {name} {kind}"),
                }
            }
        },
    );
    let filtering = json!({
        "enabled":true,"lists":[],"allowlist":[],
        "custom_rules":[{"domain":BLOCKED,"category":"ads"}],
    });
    let panel = batch_panel(port, cert, Some(filtering)).await;
    install_route_observer_for_test(&panel.shared);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(panel.listen).await.unwrap();
    let mut tcp = TcpStream::connect(panel.listen).await.unwrap();
    let warm = nfqws2_dns::build_query(UNRELATED, 1, 41).unwrap();
    let initial = udp_query(&udp, &warm).await;
    assert_eq!(
        nfqws2_dns::first_ipv4(&initial).unwrap().octets(),
        [192, 0, 2, 18]
    );
    assert_eq!(panel.engine.cache.status().entries, 1);

    publish_first_static_failure(&panel, false).await;
    assert_eq!(tcp_query(&mut tcp, &warm).await[7], 1);
    assert_eq!(panel.engine.stats().cache_hits, 1);
    publish_first_static_failure(&panel, true).await;
    let assert_empty_servfail = |wire: &[u8], response: Vec<u8>| {
        assert_eq!(response, nfqws2_dns::response_error(wire, 2));
    };
    assert_empty_servfail(&warm, udp_query(&udp, &warm).await);
    let alias = nfqws2_dns::build_query(ALIAS, 5, 42).unwrap();
    assert_empty_servfail(&alias, tcp_query(&mut tcp, &alias).await);
    let app = crate::http::router(panel.shared.clone());
    let diagnostic = request(
        &app,
        "/api/dnsserver/test",
        Some(json!({"domain":NEGATIVE,"type":"AAAA"})),
        200,
    )
    .await;
    assert_eq!(diagnostic["ok"], false);
    assert_eq!(diagnostic["answers"], json!([]));
    assert_eq!(diagnostic["cached"], false);
    assert_eq!(diagnostic["error"], "политика DNS-маршрутизации не готова");

    for (id, name) in [(43, BLOCKED), (44, INDIRECT)] {
        let query = nfqws2_dns::build_query(name, 1, id).unwrap();
        assert_eq!(
            udp_query(&udp, &query).await,
            nfqws2_dns::blocked_reply(&query).unwrap()
        );
    }
    assert_eq!(panel.engine.stats().failures, 3);
    assert_eq!(panel.engine.stats().cache_hits, 1);
    assert_eq!(panel.engine.stats().blocked_total, 2);

    for op in [Operation::Refresh, Operation::Recover] {
        publish_dns_operation_for_test(&panel.shared, op).unwrap();
        assert_empty_servfail(&warm, udp_query(&udp, &warm).await);
    }
    publish_dns_operation_for_test(&panel.shared, Operation::Apply).unwrap();
    let recovered = tcp_query(&mut tcp, &warm).await;
    let ips = nfqws2_dns::first_ipv4(&recovered).unwrap();
    assert_eq!(ips.octets(), [192, 0, 2, 18]);
    assert_eq!(panel.engine.stats().cache_hits, 2);
    let recovered_alias = tcp_query(&mut tcp, &alias).await;
    assert_eq!(recovered_alias[3] & 15, 0);
    assert_eq!(recovered_alias[7], 1);

    publish_first_static_failure(&panel, true).await;
    assert_empty_servfail(&warm, udp_query(&udp, &warm).await);
    publish_dns_operation_for_test(&panel.shared, Operation::Teardown).unwrap();
    assert_eq!(udp_query(&udp, &warm).await[7], 1);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.get(&(UNRELATED.into(), 1)), Some(&1));
        assert_eq!(seen.get(&(ALIAS.into(), 5)), Some(&1));
        assert_eq!(seen.get(&(NEGATIVE.into(), 28)), Some(&1));
        assert_eq!(seen.get(&(BLOCKED.into(), 1)), None);
        assert_eq!(seen.get(&(INDIRECT.into(), 1)), Some(&1));
    }
    panel.shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn cold_managed_apply_fresh_off_scope_with_nodata_stays_pinned_and_has_no_client_cache() {
    use crate::awg_rules::kernel::{
        install_route_observer_for_test, prepare_failed_apply_for_test,
        publish_dns_operation_for_test,
    };
    use nfqws2_awg_rules::kernel::{dns_request, Operation};
    use std::collections::BTreeMap;

    const RECOVER: &str = "recover.outside.test";
    const RECOVERY_TTL: Duration = Duration::from_secs(11);
    let seen = Arc::new(Mutex::new(BTreeMap::<(String, u16), usize>::new()));
    let requests = seen.clone();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (port, cert, _, server) = serve_doh_by_question(
        origin,
        &key,
        true,
        move |wire, name, kind| {
            assert_eq!(wire[10..12], [0, 0]);
            *requests
                .lock()
                .unwrap()
                .entry((name.into(), kind))
                .or_default() += 1;
            None
        },
        "/dns-query",
        move |wire, name, kind| match (name, kind) {
            (RECOVER, 1) => {
                address_answer(wire, [192, 0, 2, 70].into(), RECOVERY_TTL.as_secs() as u32)
            }
            (RECOVER, 28) => *wire = nfqws2_dns::response_error(wire, 0),
            (name, kind) if BATCH_PAIRS.contains(&(name, kind)) => {
                address_answer(wire, proposal_address(name, kind), 60);
            }
            _ => panic!("unexpected upstream question {name} {kind}"),
        },
    );
    let panel = batch_panel(port, cert, None).await;
    install_route_observer_for_test(&panel.shared);
    publish_first_static_failure(&panel, true).await;
    let app = crate::http::router(panel.shared.clone());
    request(
        &app,
        "/api/awg2/routing/config",
        Some(json!({"mode":"zones","domain_source":"resolve","zones":[
            {"enabled":true,"name":"exact","route":"direct","domains":[RECOVER],"include_subdomains":false},
            {"enabled":true,"name":"source CIDR","route":"direct","domains":["198.51.100.0/24"],"source_ips":["192.0.2.0/24"]}
        ]})),
        200,
    )
    .await;
    let expected = dns_request(&panel.shared.store, Operation::Apply)
        .unwrap()
        .unwrap();
    assert_eq!(expected.names, [RECOVER]);
    assert_eq!(expected.dual_stack, [RECOVER]);

    let state = panel.shared.clone();
    let started = Instant::now();
    let (snapshot, expiry, check) =
        tokio::task::spawn_blocking(move || prepare_failed_apply_for_test(&state))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(snapshot.request, expected);
    assert_eq!(
        snapshot.answers,
        BTreeMap::from([(RECOVER.into(), vec![[192, 0, 2, 70].into()])])
    );
    assert!(expiry >= started + RECOVERY_TTL && expiry <= Instant::now() + RECOVERY_TTL);
    check(&panel.shared).unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.get(&(RECOVER.into(), 1)), Some(&1));
        assert_eq!(seen.get(&(RECOVER.into(), 28)), Some(&1));
    }
    assert_eq!(panel.engine.stats().queries, 0);
    assert_eq!(panel.engine.cache.status().entries, 0);

    publish_dns_operation_for_test(&panel.shared, Operation::Recover).unwrap();
    assert_eq!(
        check(&panel.shared).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(panel.listen).await.unwrap();
    let wire = nfqws2_dns::build_query(RECOVER, 1, 47).unwrap();
    assert_eq!(
        udp_query(&udp, &wire).await,
        nfqws2_dns::response_error(&wire, 2)
    );
    panel.shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn compensated_managed_refresh_uses_fresh_dns_and_reopens_only_for_verified_installed_set() {
    use crate::awg_rules::kernel::{
        install_route_observer_for_test, publish_dns_operation_for_test,
        refresh_static_dns_for_test, static_proposal_apply_for_test, StaticApplyFixture,
        StaticApplyFixtureFailure,
    };
    use nfqws2_awg_rules::kernel::Operation;
    use std::{collections::BTreeMap, sync::atomic::AtomicBool};

    const CACHE_NAME: &str = "outside.refresh.test";
    const FRESH_TTL: Duration = Duration::from_secs(11);
    let refreshing = Arc::new(AtomicBool::new(false));
    let refresh_reply = refreshing.clone();
    let seen = Arc::new(Mutex::new(BTreeMap::<(String, u16), usize>::new()));
    let requests = seen.clone();
    let worker_address = |name: &str, kind: u16| {
        if (name, kind) == (B, 28) {
            "2001:db8::70".parse().unwrap()
        } else {
            proposal_address(name, kind)
        }
    };
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let (port, cert, _, server) = serve_doh_by_question(
        origin,
        &key,
        true,
        move |wire, name, kind| {
            assert_eq!(wire[10..12], [0, 0]);
            assert!((name, kind) == (CACHE_NAME, 1) || BATCH_PAIRS.contains(&(name, kind)));
            *requests
                .lock()
                .unwrap()
                .entry((name.into(), kind))
                .or_default() += 1;
            None
        },
        "/dns-query",
        move |wire, name, kind| {
            if (name, kind) == (CACHE_NAME, 1) {
                answer(wire, 60);
            } else if refresh_reply.load(Ordering::SeqCst) {
                let ttl = if (name, kind) == (D, 1) {
                    FRESH_TTL.as_secs() as u32
                } else {
                    60
                };
                address_answer(wire, worker_address(name, kind), ttl);
            } else {
                address_answer(wire, proposal_address(name, kind), 60);
            }
        },
    );
    let panel = batch_panel(port, cert, None).await;
    install_route_observer_for_test(&panel.shared);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(panel.listen).await.unwrap();
    let wire = nfqws2_dns::build_query(CACHE_NAME, 1, 91).unwrap();
    assert_eq!(udp_query(&udp, &wire).await[7], 1);

    let state = panel.shared.clone();
    let confirmed = panel.snapshot(batch_address);
    let failed_proposal = panel.snapshot(proposal_address);
    let result = tokio::task::spawn_blocking(move || {
        static_proposal_apply_for_test(
            &state,
            &StaticApplyFixture::default(),
            &confirmed,
            |answer, reused, _| {
                assert_eq!(answer, failed_proposal.as_ref());
                assert!(!reused);
                Err(StaticApplyFixtureFailure::Compensated(io::Error::other(
                    "restored prior FIB",
                )))
            },
        )
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().to_string(), "restored prior FIB");
    let servfail = nfqws2_dns::response_error(&wire, 2);
    assert_eq!(udp_query(&udp, &wire).await, servfail);
    publish_dns_operation_for_test(&panel.shared, Operation::Refresh).unwrap();
    assert_eq!(udp_query(&udp, &wire).await, servfail);

    let expected_fresh = panel.snapshot(worker_address);
    assert_ne!(
        expected_fresh.answers,
        panel.snapshot(proposal_address).answers
    );
    refreshing.store(true, Ordering::SeqCst);
    for installed in [false, true] {
        let started = Instant::now();
        let (state, request, expected) = (
            panel.shared.clone(),
            panel.request.clone(),
            expected_fresh.clone(),
        );
        tokio::task::spawn_blocking(move || {
            refresh_static_dns_for_test(&state, request, |snapshot, expires| {
                assert_eq!(snapshot, expected.as_ref());
                assert!(expires >= started + FRESH_TTL && expires <= Instant::now() + FRESH_TTL);
                (Ok(()), installed)
            })
        })
        .await
        .unwrap()
        .unwrap();
        let reply = udp_query(&udp, &wire).await;
        if installed {
            assert_eq!(
                nfqws2_dns::first_ipv4(&reply).unwrap().octets(),
                [192, 0, 2, 18]
            );
        } else {
            assert_eq!(reply, servfail);
        }
    }
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.get(&(CACHE_NAME.into(), 1)), Some(&1));
        for (name, kind) in BATCH_PAIRS {
            assert_eq!(seen.get(&(name.into(), kind)), Some(&3));
        }
    }
    assert_eq!(panel.engine.stats().queries, 5);
    assert_eq!(panel.engine.cache.status().entries, 1);
    panel.shared.dnsserver.shutdown().await;
    server.abort();
}

async fn wait_for_pending_dns(shared: &Shared, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while crate::awg_rules::kernel::waiting_dns_queries_for_test(shared) != count {
        assert!(
            Instant::now() < deadline,
            "pending DNS query count did not change"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn managed_udp_tcp_wait_for_route_publication_without_refetching_or_blocking_filters() {
    use crate::awg_rules::kernel::{
        hold_dns_operation_for_test, install_route_observer_for_test, DnsPublicationFixture,
    };
    use nfqws2_awg_rules::kernel::Operation;

    const OUTSIDE: &str = "cached.pending.test";
    const BLOCKED: &str = "blocked.pending.test";
    let (port, cert, upstream, server) = local_doh().await;
    let filtering = json!({
        "enabled":true,"lists":[],"allowlist":[],
        "custom_rules":[{"domain":BLOCKED,"category":"ads"}],
    });
    let panel = batch_panel(port, cert, Some(filtering)).await;
    install_route_observer_for_test(&panel.shared);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blocked_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(panel.listen).await.unwrap();
    blocked_udp.connect(panel.listen).await.unwrap();
    let mut tcp = TcpStream::connect(panel.listen).await.unwrap();
    let warm = nfqws2_dns::build_query(OUTSIDE, 1, 31).unwrap();
    assert_eq!(udp_query(&udp, &warm).await[7], 1);
    assert_eq!(upstream.load(Ordering::SeqCst), 1);
    let blocked = nfqws2_dns::build_query(BLOCKED, 1, 32).unwrap();

    for (op, completion, ready) in [
        (Operation::Refresh, DnsPublicationFixture::Ready, true),
        (Operation::Apply, DnsPublicationFixture::Unreadable, false),
        (Operation::Apply, DnsPublicationFixture::Ready, true),
        (Operation::Apply, DnsPublicationFixture::Compensated, false),
        (Operation::Refresh, DnsPublicationFixture::Ready, false),
        (Operation::Apply, DnsPublicationFixture::Ready, true),
    ] {
        let publish = hold_dns_operation_for_test(&panel.shared, op);
        let bad_observation = matches!(completion, DnsPublicationFixture::Unreadable);
        let ((udp_reply, tcp_reply), ()) = tokio::join!(
            async { tokio::join!(udp_query(&udp, &warm), tcp_query(&mut tcp, &warm)) },
            async {
                wait_for_pending_dns(&panel.shared, 2).await;
                let response = udp_query(&blocked_udp, &blocked).await;
                assert_eq!(response, nfqws2_dns::blocked_reply(&blocked).unwrap());
                assert_eq!(upstream.load(Ordering::SeqCst), 1);
                let published = publish(completion);
                assert_eq!(published.is_err(), bad_observation);
            }
        );
        assert_eq!(
            crate::awg_rules::kernel::waiting_dns_queries_for_test(&panel.shared),
            0
        );
        for reply in [udp_reply, tcp_reply] {
            if ready {
                assert_eq!(&reply[..2], &warm[..2]);
                assert_eq!(
                    nfqws2_dns::first_ipv4(&reply).unwrap().octets(),
                    [192, 0, 2, 18]
                );
            } else {
                assert_eq!(reply, nfqws2_dns::response_error(&warm, 2));
            }
        }
        assert_eq!(panel.engine.cache.status().entries, 1);
    }
    assert_eq!(panel.engine.stats().failures, 6);
    assert_eq!(panel.engine.stats().blocked_total, 6);
    assert_eq!(panel.engine.stats().cache_hits, 6);
    panel.shared.dnsserver.shutdown().await;
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn managed_policy_wait_uses_absolute_wire_and_diagnostic_deadlines_and_stops_promptly() {
    use crate::awg_rules::kernel::{
        hold_dns_operation_for_test, install_route_observer_for_test, DnsPublicationFixture,
    };
    use nfqws2_awg_rules::kernel::Operation;
    use nfqws2_dns::Lookup;

    const HOST: &str = "timeout.pending.test";
    let dir = tempfile::tempdir().unwrap();
    let shared = state(&dir);
    install_route_observer_for_test(&shared);
    let cfg = Config::from_value(&exact_raw(1, vec![])).unwrap();
    let (scope, _, _) = cfg.servers(HOST);
    let scope = scope.to_owned();
    let engine = Engine::new(
        cfg,
        Arc::new(Mutex::new(Diagnostics::new(false))),
        Default::default(),
        shadow::Environment::unavailable(),
        Arc::new(vpn::Source::with(|| Ok(vec![]))),
        shared.dnsserver.observer.clone(),
    );
    let query = nfqws2_dns::build_query(HOST, 1, 1).unwrap();
    let Lookup::Miss(pending) = engine.cache.begin(&query, &scope).unwrap() else {
        panic!("fixture cache was not empty");
    };
    let mut wire = query.clone();
    answer(&mut wire, 120);
    engine
        .cache
        .finish(&query, pending, wire, true, None)
        .unwrap();
    let publish = hold_dns_operation_for_test(&shared, Operation::Apply);
    let begin = |transport: &'static str| {
        let (engine, query) = (engine.clone(), query.clone());
        tokio::spawn(async move { engine.exchange(&query, "diagnostic", transport, None).await })
    };
    let (udp, tcp, api) = (begin("udp"), begin("tcp"), begin("api"));
    wait_for_pending_dns(&shared, 3).await;
    tokio::time::advance(Duration::from_secs(26)).await;
    assert!(!udp.is_finished() && !tcp.is_finished() && !api.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    for result in [udp.await.unwrap(), tcp.await.unwrap()] {
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    }
    assert!(!api.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = api.await.unwrap();
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
    assert_eq!(
        crate::awg_rules::kernel::waiting_dns_queries_for_test(&shared),
        0
    );
    assert_eq!(engine.cache.status().entries, 1);
    assert_eq!(engine.stats().failures, 3);

    let waiting = begin("api");
    wait_for_pending_dns(&shared, 1).await;
    engine.stopped.send_replace(true);
    let result = waiting.await.unwrap();
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Interrupted));
    assert_eq!(
        crate::awg_rules::kernel::waiting_dns_queries_for_test(&shared),
        0
    );
    publish(DnsPublicationFixture::Ready).unwrap();
}
