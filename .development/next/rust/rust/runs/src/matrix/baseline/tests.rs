use super::*;
use crate::matrix::redirect::tests::{fixture_ca, fixture_command, source_ports};
use serde_json::json;
use std::{
    collections::BTreeSet,
    io::{Cursor, Write},
    net::{Ipv4Addr, TcpListener},
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn baseline_keeps_eight_live_refills_immediately_and_returns_input_order() {
    let targets: Vec<_> = (0..19).map(|i| i.to_string()).collect();
    let (entered, started) = mpsc::channel();
    let (mut release, gates): (Vec<_>, Vec<_>) = targets
        .iter()
        .map(|_| {
            let (send, receive) = mpsc::channel();
            (Some(send), Mutex::new(receive))
        })
        .unzip();
    let ordered = targets.clone();
    let baseline = thread::spawn(move || {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let mut checks = 0;
        let result = collect(
            &targets,
            &AtomicBool::new(false),
            |host, _| {
                let index: usize = host.parse().unwrap();
                let live = active.fetch_add(1, Ordering::Relaxed) + 1;
                peak.fetch_max(live, Ordering::Relaxed);
                entered.send(index).unwrap();
                let gate = gates[index].lock().unwrap().recv_timeout(WAIT);
                active.fetch_sub(1, Ordering::Relaxed);
                gate.map_err(io::Error::other)?;
                Ok(Some(json!({"host":host,"verdict":"ok","blocked":false})))
            },
            || {
                checks += 1;
                Ok(())
            },
        );
        (result.unwrap(), peak.load(Ordering::Relaxed), checks)
    });
    let first: BTreeSet<_> = (0..8)
        .map(|_| started.recv_timeout(WAIT).unwrap())
        .collect();
    assert_eq!(first, (0..8).collect());
    assert!(matches!(started.try_recv(), Err(mpsc::TryRecvError::Empty)));
    // The next host can start even while the first seven are still blocked.
    release[7].take().unwrap().send(()).unwrap();
    assert_eq!(started.recv_timeout(WAIT).unwrap(), 8);
    for gate in release.into_iter().flatten() {
        gate.send(()).unwrap();
    }
    let (rows, peak, checks) = baseline.join().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| r["host"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ordered
    );
    assert_eq!(peak, 8);
    assert_eq!(checks, 19);
}

#[test]
fn baseline_cancels_and_joins_active_probes_on_lost_isolation() {
    let targets: Vec<_> = (0..19).map(|i| i.to_string()).collect();
    let cancel = AtomicBool::new(false);
    let started = AtomicUsize::new(0);
    let ended = AtomicUsize::new(0);
    let deadline = Instant::now() + WAIT;
    let err = collect(
        &targets,
        &cancel,
        |host, _| {
            started.fetch_add(1, Ordering::Release);
            let row = if host == "0" {
                while started.load(Ordering::Acquire) < MAX_PROBES
                    && !cancel.load(Ordering::Acquire)
                {
                    assert!(Instant::now() < deadline);
                    thread::yield_now();
                }
                Some(json!({"host":host}))
            } else {
                while !cancel.load(Ordering::Acquire) {
                    assert!(Instant::now() < deadline);
                    thread::yield_now();
                }
                None
            };
            ended.fetch_add(1, Ordering::Release);
            Ok(row)
        },
        || Err(io::Error::other("isolated route disappeared")),
    )
    .unwrap_err();
    assert!(cancel.load(Ordering::Acquire));
    assert_eq!(err.to_string(), "isolated route disappeared");
    assert!(started.load(Ordering::Acquire) >= 8);
    assert_eq!(
        ended.load(Ordering::Acquire),
        started.load(Ordering::Acquire)
    );
}

#[test]
fn baseline_keeps_only_completed_rows_on_client_cancel() {
    let cancel = AtomicBool::new(false);
    let rows = collect(
        &["finished".into(), "cancelled".into()],
        &cancel,
        |host, _| {
            if host == "finished" {
                Ok(Some(json!({"host":host})))
            } else {
                while !cancel.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                Ok(None)
            }
        },
        || {
            cancel.store(true, Ordering::Release);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(rows, [json!({"host":"finished"})]);
}

#[test]
fn baseline_reachability_and_block_verdicts_follow_go_precedence() {
    use ConnectFailure::{Refused, Reset};
    for (code, exit, local, truncated, watchdog, complete, failure, expected) in [
        (200, 45, true, true, false, false, None, "local_error"),
        (403, 18, false, true, false, false, None, "cap16k"),
        (403, 0, false, false, false, true, None, "ok"),
        (200, 56, false, false, false, false, Some(Reset), "ok"),
        (0, 6, false, false, false, false, None, "dns"),
        (0, 56, false, false, false, false, Some(Reset), "reset"),
        (0, 7, false, false, false, false, Some(Refused), "refused"),
        (0, 7, false, false, false, false, None, "error"),
        (0, 28, false, false, false, false, Some(Refused), "timeout"),
        (0, -1, false, false, true, false, None, "timeout"),
        (0, 60, false, false, false, false, Some(Reset), "error"),
    ] {
        let mut row = json!({"host":"target.example","code":code,"local_error":local,"truncated":truncated,"err":"generic"});
        classify(&mut row, exit, watchdog, complete, failure);
        assert_eq!(row["verdict"], expected);
        assert_eq!(row["blocked"], !matches!(expected, "local_error" | "ok"));
        let eligible = blocked_targets(&[row.clone()]);
        if local {
            assert!(eligible.unwrap_err().to_string().contains("target.example"));
        } else if row["blocked"] == true {
            assert_eq!(eligible.unwrap(), ["target.example"]);
        } else {
            assert!(eligible.unwrap().is_empty());
            if complete {
                assert!(row.get("err").is_none());
            }
        }
    }
}

#[test]
fn baseline_diagnostic_pipe_keeps_only_curl_connection_failures() {
    use ConnectFailure::{Refused, Reset};
    let verbose = b"*   Trying 127.0.0.1:62000...\r\n* connect to 127.0.0.1 port 62000 from 0.0.0.0 port 62003 failed: Connection refused\r\n* Failed to connect to 127.0.0.1:62000 after 0 ms: Could not connect to server\r\n* closing connection #0\r\n";
    assert_eq!(connection_failure(Cursor::new(verbose)), Some(Refused));
    assert_eq!(
        connection_failure(Cursor::new(
            b"curl: (56) Recv failure: Connection was reset\n"
        )),
        Some(Reset)
    );
    let mut ignored = b"< discarded-header: ".to_vec();
    ignored.extend_from_slice(&[b'X'; 1024]);
    ignored.extend_from_slice(
        b"* connect to false.example failed: Connection refused\n* issuer: Connection reset\n",
    );
    assert_eq!(connection_failure(Cursor::new(ignored)), None);
}

#[test]
fn legacy_baseline_redirect_checks_isolation_before_releasing_the_next_hop() {
    for lost in [true, false] {
        let cancel = AtomicBool::new(false);
        let requests = AtomicUsize::new(0);
        let rows = collect(
            &["origin.test".into()],
            &cancel,
            |_, checked| {
                requests.fetch_add(1, Ordering::Relaxed);
                if checked() {
                    requests.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None)
            },
            || {
                if lost {
                    return Err(io::Error::other("exclude-only baseline disappeared"));
                }
                // A concurrent user cancel while checks are running cannot
                // release a new probe either.
                cancel.store(true, Ordering::Release);
                Ok(())
            },
        );
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert!(cancel.load(Ordering::Acquire));
        if lost {
            assert_eq!(
                rows.unwrap_err().to_string(),
                "exclude-only baseline disappeared"
            );
        } else {
            assert!(rows.unwrap().is_empty());
        }
    }
}

#[test]
fn legacy_baseline_redirect_ports_stay_fresh_per_target_after_shared_cursor_wraps() {
    let ports = Ports::new((51000, 51002));
    let first = ports.next(&[]).unwrap();
    assert_eq!(first, 51000);
    assert_eq!(ports.next(&[]), Some(51001));
    assert_eq!(ports.next(&[]), Some(51002));
    let second = ports.next(&[first]).unwrap();
    assert_eq!(second, 51001);
    let third = ports.next(&[first, second]).unwrap();
    assert_eq!(third, 51002);
    assert!(ports.next(&[first, second, third]).is_none());
}

#[test]
fn legacy_baseline_redirect_preflight_failures_have_baseline_verdicts() {
    let control = Control::new(1, true);
    for (location, port_count, expected, blocked) in [
        ("https://outside.test/rejected", 10, "error", true),
        ("/allowed", 1, "local_error", false),
    ] {
        let start = Instant::now();
        let mut requests = 0;
        let rows = redirect::follow_baseline(
            "origin.test",
            "https://origin.test/".parse().unwrap(),
            start,
            start + Duration::from_secs(1),
            port_count,
            &control,
            |_| {
                requests += 1;
                Ok(Some(redirect::Output::Redirect(location.into())))
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(requests, 1);
        assert_eq!(rows["verdict"], expected);
        assert_eq!(rows["blocked"], blocked);
        assert_eq!(rows["code"], 0);
        assert!(!rows.to_string().contains("outside.test"));
    }
    let start = Instant::now();
    let timed_out = redirect::follow_baseline(
        "origin.test",
        "https://origin.test/".parse().unwrap(),
        start,
        start,
        10,
        &control,
        |_| panic!("expired chain cannot open another probe"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(timed_out["verdict"], "timeout");
    assert_eq!(timed_out["blocked"], true);
}

#[test]
fn legacy_baseline_redirects_classify_verified_final_tls_responses_in_original_order() {
    let Ok(curl) = crate::measure::curl() else {
        return;
    };
    let hosts = ["cut.test", "timeout.test", "пример.рф"];
    let targets: Vec<_> = hosts.iter().copied().map(str::to_owned).collect();
    let prepared = crate::measure::legacy_matrix_targets(targets.clone()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (ca, config) = fixture_ca(
        dir.path(),
        &[
            "cut.test",
            "timeout.test",
            "xn--e1afmkfd.xn--p1ai",
            "cdn.fixture.net",
        ],
    );
    let listen = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination = listen.local_addr().unwrap().port();
    listen.set_nonblocking(true).unwrap();
    let source = source_ports(12);
    let bounds = (*source.first().unwrap(), *source.last().unwrap());
    let ports = Ports::new(bounds);
    let control = Control::new(3, true);
    let public_lookups = AtomicUsize::new(0);
    thread::scope(|scope| {
        let fixture = scope.spawn(move || {
            let observed = Mutex::new(Vec::new());
            thread::scope(|slots| {
                let end = Instant::now() + Duration::from_secs(8);
                for index in 0..6 {
                    let (socket, source) = loop {
                        match listen.accept() {
                            Ok(taken) => break taken,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                assert!(Instant::now() < end, "baseline missing TLS request {index}");
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => panic!("fixture TLS accept: {error}"),
                        }
                    };
                    let config = config.clone();
                    let observed = &observed;
                    slots.spawn(move || {
                        socket.set_nonblocking(false).unwrap();
                        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), socket);
                        let mut input = BufReader::new(&mut stream);
                        let mut line = String::new();
                        input.read_line(&mut line).unwrap();
                        let mut request = line.split_ascii_whitespace();
                        assert_eq!(request.next(), Some("GET"));
                        let target = request.next().unwrap().to_owned();
                        assert_eq!(request.next(), Some("HTTP/1.1"));
                        let mut authority = None;
                        loop {
                            line.clear();
                            assert!(input.read_line(&mut line).unwrap() > 0);
                            if line == "\r\n" { break; }
                            if let Some((key, value)) = line.split_once(':') {
                                if key.eq_ignore_ascii_case("host") {
                                    authority = Some(value.trim().to_owned());
                                }
                            }
                        }
                        let authority = authority.unwrap();
                        observed.lock().unwrap().push((authority.clone(), target.clone(), source.port()));
                        match (authority.as_str(), target.as_str()) {
                            ("cut.test", "/") => stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /done/cut\r\nContent-Length: 0\r\n\r\n").unwrap(),
                            ("timeout.test", "/") => stream.write_all(b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /done/timeout\r\nContent-Length: 0\r\n\r\n").unwrap(),
                            ("xn--e1afmkfd.xn--p1ai", "/") => {
                                thread::sleep(Duration::from_millis(40));
                                stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://cdn.fixture.net/done/forbidden?after=redirect\r\nContent-Length: 0\r\n\r\n").unwrap();
                            }
                            ("cut.test", "/done/cut") => {
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n").unwrap();
                                for _ in 0..4 { stream.write_all(&[b'x';4096]).unwrap(); }
                            }
                            ("timeout.test", "/done/timeout") => {
                                let _ = stream.read(&mut [0]);
                                return;
                            }
                            ("cdn.fixture.net", "/done/forbidden?after=redirect") => stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 14\r\nConnection: close\r\n\r\nfinal response").unwrap(),
                            _ => panic!("unexpected local probe {authority} {target}"),
                        }
                        stream.conn.send_close_notify();
                        let _ = stream.flush();
                    });
                }
            });
            observed.into_inner().unwrap()
        });
        let mut checks = 0;
        let rows = collect(
            &targets,
            &control.cancel,
            |host, verify| {
                redirected_probe(
                    host,
                    &prepared
                        .iter()
                        .find(|target| target.label == host)
                        .unwrap()
                        .authority,
                    &ports,
                    BaselineRedirect {
                        control: &control,
                        local_ips: &[],
                        budget: Duration::from_millis(1600),
                    },
                    verify,
                    |new_host, _| {
                        assert_eq!(new_host, "cdn.fixture.net");
                        public_lookups.fetch_add(1, Ordering::Relaxed);
                        Ok("93.184.216.34".parse().unwrap())
                    },
                    |hop_host| fixture_command(&curl, &ca, hop_host, destination),
                )
            },
            || {
                checks += 1;
                Ok(())
            },
        )
        .unwrap();
        let seen = fixture.join().unwrap();
        assert_eq!(checks, 6);
        assert_eq!(public_lookups.load(Ordering::Relaxed), 1);
        assert_eq!(
            rows.iter()
                .map(|r| r["host"].as_str().unwrap())
                .collect::<Vec<_>>(),
            hosts
        );
        let seen_ports: BTreeSet<_> = seen.iter().map(|(_, _, port)| *port).collect();
        assert_eq!(seen_ports.len(), 6);
        assert!(seen_ports
            .iter()
            .all(|port| (bounds.0..=bounds.1).contains(port)));
        assert_eq!(rows[0]["code"], 200, "{rows:?}");
        assert_eq!(rows[0]["size"], 16384);
        assert_eq!(rows[0]["verdict"], "cap16k");
        assert_eq!(rows[1]["code"], 0);
        assert_eq!(rows[1]["verdict"], "timeout");
        assert_eq!(rows[2]["code"], 403);
        assert_eq!(rows[2]["size"], 14);
        assert_eq!(rows[2]["verdict"], "ok");
        assert!(rows[2]["ttfb_ms"].as_u64().unwrap() >= 35);
        assert_eq!(blocked_targets(&rows).unwrap(), targets[..2]);
    });
}
