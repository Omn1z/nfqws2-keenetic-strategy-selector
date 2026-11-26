use super::*;
use base64ct::{Base64, Encoding};
use std::{fs, net::TcpListener};

fn job(targets: Vec<String>, threads: usize) -> Request {
    Request {
        targets,
        threads,
        list_id: String::new(),
        mode: "current_https".into(),
    }
}
#[test]
fn only_explicit_domains_from_one_source_and_known_mode_are_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    db.transaction(|tx|tx.save("lists/saved.json",&json!({"name":"Sample","domains":["Example.test.","example.test"],"ips":["192.0.2.0/24"]}))).unwrap();
    let req = || Request {
        list_id: "saved".into(),
        ..job(vec![], 2)
    };
    let report = create(&db, "new", req()).unwrap();
    assert_eq!(report["targets"], json!(["example.test"]));
    assert_eq!(report["list_name"], "Sample");
    assert!(create(
        &db,
        "new",
        Request {
            targets: vec!["extra.test".into()],
            ..req()
        }
    )
    .is_err());
    for s in [
        "https://a.test/path",
        "-K /etc/config",
        "a.test:80",
        "*.a.test",
        "127.0.0.1",
        "a.test..",
    ] {
        assert!(create(&db, "new", job(vec![s.into()], 1)).is_err(), "{s}");
    }
    assert!(create(
        &db,
        "new",
        job((0..65).map(|i| format!("t{i}.test")).collect(), 8)
    )
    .is_err());
    assert!(serde_json::from_value::<Request>(
        json!({"threads":1,"mode":"current_https","strategy_ids":["old"]})
    )
    .is_err());
}
#[test]
fn selftest_preserves_argument_order_and_labels_with_validated_authorities() {
    let hosts = [
        "A.example",
        "a.example",
        "A.example.",
        "A.example",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "::1",
    ];
    let targets = selftest_targets(hosts.map(str::to_owned).to_vec()).unwrap();
    assert_eq!(
        targets.iter().map(|t| t.label.as_str()).collect::<Vec<_>>(),
        hosts
    );
    assert_eq!(
        targets
            .iter()
            .map(|t| t.authority.as_str())
            .collect::<Vec<_>>(),
        [
            "A.example",
            "a.example",
            "A.example.",
            "A.example",
            "localhost",
            "127.0.0.1",
            "[::1]",
            "[::1]"
        ]
    );
    for raw in [
        "https://localhost",
        "127.0.0.1:80",
        "[::1]:443",
        "--config",
        "*.test",
        "safe.example@other.example",
    ] {
        assert!(selftest_targets(vec![raw.into()]).is_err());
    }
}
#[test]
fn concurrency_can_change_during_a_run_and_cancellation_does_not_create_measurements() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let mut report = create(
        &db,
        "x",
        job((0..12).map(|i| format!("t{i}.test")).collect(), 1),
    )
    .unwrap();
    let control = Control {
        cancel: false.into(),
        threads: 1.into(),
    };
    let current = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let (ready, first) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let controller = &control;
        let workers = &current;
        scope.spawn(move || {
            first.recv_timeout(Duration::from_secs(3)).unwrap();
            controller.threads.store(3, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(3);
            while workers.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            controller.cancel.store(true, Ordering::Release);
        });
        measure(&mut report, &db, &control, &|host, c| {
            let n = current.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            if host == "t0.test" {
                let _ = ready.try_send(());
            }
            let deadline = Instant::now() + Duration::from_secs(4);
            while !c.cancel.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            current.fetch_sub(1, Ordering::SeqCst);
            Ok(None)
        })
        .unwrap();
    });
    assert_eq!(peak.load(Ordering::Relaxed), 3);
    assert_eq!(report["done"], 0);
    assert_eq!(report["checks"], json!([]));
}

#[test]
fn real_https_head_reports_the_server_status_and_first_byte_time() {
    let fixture = rcgen::generate_simple_self_signed(vec!["measurement.test".into()]).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let ca = tmp.path().join("ca.pem");
    fs::write(
        &ca,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            Base64::encode_string(fixture.cert.der())
        ),
    )
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![fixture.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(fixture.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(7);
        let stream = loop {
            if let Ok((socket, _)) = listener.accept() {
                break socket;
            }
            assert!(Instant::now() < deadline, "no fixture connection");
            thread::sleep(Duration::from_millis(5));
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let mut conn = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            stream,
        );
        let mut headers = BufReader::new(&mut conn);
        let mut line = String::new();
        headers.read_line(&mut line).unwrap();
        assert_eq!(line, "HEAD / HTTP/1.1\r\n");
        loop {
            line.clear();
            assert!(headers.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        thread::sleep(Duration::from_millis(30));
        conn.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
        conn.flush().unwrap();
    });
    let mut cmd = Command::new("curl");
    cmd.arg("--disable")
        .arg("--cacert")
        .arg(ca)
        .arg("--connect-to")
        .arg(format!("measurement.test:443:127.0.0.1:{}", addr.port()));
    let sample = measurement(
        cmd,
        "measurement.test",
        &Control {
            threads: 1.into(),
            cancel: false.into(),
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(sample["code"], 204, "{sample}");
    assert_eq!(sample["ok"], true);
    assert!(sample["ttfb_ms"].as_u64().unwrap() >= 25);
    server.join().unwrap();
}
