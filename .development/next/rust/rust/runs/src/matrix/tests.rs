use super::*;

fn request() -> Request {
    serde_json::from_value(json!({"targets":["Example.test.","example.test"],"threads":2,"auto":true,
        "config":{"nfqws_bin":"nfqws2","wan_ifaces":["eth0"],"base_args":["--lua-init=@/safe/functions.lua"],
            "first_queue":200,"main_queue":300,"port_base":50000,"ports_per_worker":200},
        "strategies":[{"id":"a","strategy_id":"a","name":"A","args":"--filter-tcp=443 --lua-desync=fake"}]})).unwrap()
}

#[test]
fn matrix_plan_validates_candidates_and_accepts_both_catalog_id_fields() {
    let mut req = request();
    let report = create("new", &mut req).unwrap();
    assert_eq!(report["mode"], "strategy_matrix");
    assert_eq!(report["targets"], json!(["example.test"]));
    assert_eq!(report["auto"], true);
    req.strategies[0].args = "--filter-tcp=80 --filter-l7=http --lua-desync=multisplit".into();
    assert!(create("new", &mut req).is_err());
    let mut req = request();
    req.strategies[0].strategy_id = "other".into();
    assert!(create("new", &mut req).is_err());
    let mut req = request();
    req.strategies.push(req.strategies[0].clone());
    assert!(create("new", &mut req).is_err());
    let mut req = request();
    req.targets = vec!["https://example.test/".into()];
    assert!(create("new", &mut req).is_err());
}

#[test]
fn legacy_matrix_counts_dns_cross_product_preserves_literals_and_rejects_urls() {
    let mut req = request();
    req.legacy = true;
    req.targets = vec![
        "Saved.example".into(),
        "192.0.2.1".into(),
        "2001:db8::1".into(),
    ];
    req.dns = serde_json::from_value(json!([null, {"id":"named","name":"Verified DNS", "transport":"dot","addr":"dns.example"},null])).unwrap();
    let report = create("r76", &mut req).unwrap();
    assert_eq!(
        report["targets"],
        json!(["Saved.example", "192.0.2.1", "[2001:db8::1]"])
    );
    assert_eq!(report["total"], 3);
    let row = result_row(&req.strategies[0], req.dns[1].as_ref(), req.targets.len());
    assert_eq!(row["dns"], "Verified DNS");
    assert_eq!(row["dns_id"], "named");
    req.targets = vec!["example.test:8080".into()];
    assert!(create("r76", &mut req).is_err());
}

#[test]
fn legacy_idn_targets_preserve_display_labels_and_keep_ascii_authorities() {
    let mut req = request();
    req.legacy = true;
    let input = [
        "пример.рф",
        "Пример。РФ",
        "пример.рф.",
        "xn--e1afmkfd.xn--p1ai",
    ];
    req.targets = input.iter().copied().map(str::to_owned).collect();
    let report = create("r82", &mut req).unwrap();
    assert_eq!(report["targets"], json!(input));
    for (label, expected) in input.into_iter().zip([
        "xn--e1afmkfd.xn--p1ai",
        "xn--e1afmkfd.xn--p1ai",
        "xn--e1afmkfd.xn--p1ai.",
        "xn--e1afmkfd.xn--p1ai",
    ]) {
        let target = req.target(label);
        assert_eq!(target.label, label);
        assert_eq!(target.authority, expected);
    }
    for invalid in [
        "https://пример.рф",
        "пример.рф:443",
        "пример.рф/path",
        "*.пример.рф",
        ".пример.рф",
        "пример.рф?x",
        "пример@рф.local",
        "пример.рф\\other",
    ] {
        req.targets = vec![invalid.to_owned()];
        assert!(create("r82", &mut req).is_err(), "{invalid}");
    }
    req.legacy = false;
    req.targets = vec!["пример.рф".into()];
    assert!(create("r82", &mut req).is_err());
}

#[test]
fn queue_evidence_cannot_be_replaced_by_a_reachable_https_target() {
    let original = json!({"host":"example.test","ok":true,"size":40_000});
    let mut no_traffic = original.clone();
    check_queue_traffic(&mut no_traffic, 17, Ok(17));
    assert_eq!(no_traffic["ok"], false);
    assert!(no_traffic["err"].as_str().unwrap().contains("NFQUEUE"));
    let mut wrapped = original.clone();
    check_queue_traffic(&mut wrapped, u32::MAX, Ok(0));
    assert_eq!(wrapped["ok"], true);
    let mut vanished = original;
    check_queue_traffic(&mut vanished, 17, Err(io::ErrorKind::NotFound.into()));
    assert_eq!(vanished["ok"], false);
}

#[test]
fn body_measurement_rejects_headers_only_cuts_and_failed_transfers() {
    let finish = |bytes, code, exit, success, capped| {
        finish_probe(
            "example.test",
            "",
            code,
            bytes,
            Duration::from_millis(200),
            Some(Duration::from_millis(40)),
            capped,
            exit,
            success,
        )
    };
    assert_eq!(
        finish(0, "HTTP/1.1 204 No Content\r\n", 0, true, false)["ok"],
        false
    );
    assert_eq!(
        finish(16_384, "HTTP/1.1 200 OK\r\n", 18, false, false)["truncated"],
        true
    );
    assert_eq!(
        finish(16_384, "HTTP/1.1 200 OK\r\n", 18, false, false)["ok"],
        false
    );
    assert_eq!(
        finish(40_000, "HTTP/1.1 200 OK\r\n", 18, false, false)["ok"],
        false
    );
    assert_eq!(
        finish(40_000, "HTTP/1.1 200 OK\r\n", 0, true, false)["ok"],
        true
    );
    assert_eq!(
        finish(
            READ_CAP,
            "HTTP/1.1 206 Partial Content\r\n",
            -1,
            false,
            true
        )["ok"],
        true
    );
    assert_eq!(
        finish(READ_CAP, "HTTP/1.1 403 Forbidden\r\n", -1, false, true)["ok"],
        false
    );
    assert_eq!(finish(0, "", 45, false, false)["local_error"], true);
}

#[test]
fn metrics_are_finite_and_ranking_uses_download_speed_and_ttfb() {
    assert_eq!(
        parse_metrics("200 0.040 0.2 40000 200000 192.0.2.2").unwrap(),
        (200, 40, 200, 200000, "192.0.2.2".into())
    );
    for bad in [
        "200 NaN 0.2 10 10 192.0.2.2",
        "200 0.1 22 10 10 192.0.2.2",
        "200 0.1 0.2 10 inf 192.0.2.2",
        "200 0.1 0.2 10 20 ::1",
    ] {
        assert!(parse_metrics(bad).is_none(), "{bad}");
    }
    let strategy = request().strategies.remove(0);
    let mut row = result_row(&strategy, None, 1);
    row["per_target"] = json!([{"host":"example.test","ok":true,"speed_bps":200000,"ttfb_ms":40}]);
    let mut report = json!({"results":[row]});
    crate::summarize(&mut report).unwrap();
    assert_eq!(report["results"][0]["success"], true);
    assert_eq!(report["results"][0]["targets_ok"], 1);
    assert!(
        (report["results"][0]["coefficient"].as_f64().unwrap() - 200000.0 * 1000.0 / 1040.0).abs()
            < 0.01
    );
    report["results"][0]["error"] = "isolation changed".into();
    crate::summarize(&mut report).unwrap();
    assert_eq!(report["results"][0]["success"], false);
}

#[test]
fn cancellation_happens_before_a_probe_process_can_start() {
    let control = Arc::new(Control::new(1, true));
    commands(io::Cursor::new(b""), control.clone());
    let result = probe(
        Command::new("certainly-missing-curl"),
        "example.test",
        (50000, 50199),
        &control,
        ProbeLane::Candidate(None),
    )
    .unwrap();
    assert!(result.is_none());
}

#[test]
fn legacy_cancel_retains_verified_partial_candidate_and_interrupted_target() {
    for (cancel_at, interrupted, lost_isolation, retained, expected_ok) in [
        (0, false, false, true, 0),
        (1, false, false, true, 1),
        (2, true, false, true, 1),
        (1, false, true, false, 0),
    ] {
        let req = request();
        let control = Arc::new(Control::new(2, true));
        let hosts: [String; 3] = [
            "one.example".into(),
            "two.example".into(),
            "three.example".into(),
        ];
        let mut row = result_row(&req.strategies[0], None, hosts.len());
        let mut visited = Vec::new();
        if cancel_at == 0 {
            commands(io::Cursor::new(b""), control.clone());
        }
        capture_targets(&mut row, &hosts, &control, |host| {
            visited.push(host.to_owned());
            let at_cancel = visited.len() == cancel_at;
            if at_cancel {
                commands(io::Cursor::new(b""), control.clone());
            }
            let mut sample = if at_cancel && interrupted {
                interrupted_probe(host)
            } else {
                json!({"host":host,"ok":true,"code":200,"size":33000,"ttfb_ms":10,"speed_bps":10000})
            };
            check_queue_traffic(&mut sample, 12, Ok(13));
            Ok(Some(sample))
        }).unwrap();
        assert_eq!(visited, hosts[..cancel_at]);
        let isolation = if lost_isolation {
            Err(io::Error::other("isolated route disappeared"))
        } else {
            Ok(())
        };
        let row = complete_candidate(row, isolation, &control).unwrap();
        assert_eq!(row.is_some(), retained);
        let Some(row) = row else { continue };
        assert_eq!(row["targets_total"], 3);
        assert_eq!(row["targets_ok"], expected_ok);
        assert_eq!(row["success"], false);
        assert_eq!(row["per_target"].as_array().unwrap().len(), cancel_at);
        if expected_ok == 1 {
            assert_eq!(row["avg_ttfb_ms"], 10);
            assert_eq!(row["avg_speed_bps"], 10000);
            assert!(row["coefficient"].as_f64().unwrap() > 0.0);
        }
        if interrupted {
            assert_eq!(
                row["per_target"][1],
                json!({"host":"two.example","ok":false,"code":0,"size":0,"ttfb_ms":0,
                "total_ms":0,"speed_bps":0,"remote_ip":"","truncated":false,"err":"context canceled"})
            );
        }
    }
}

#[test]
fn legacy_cancel_only_preserves_rows_on_clean_parent_pipe_close() {
    let req = request();
    for (legacy, input, internal, retained) in [
        (true, &b"3\n"[..], false, true),
        (false, &b"3\n"[..], false, false),
        (true, &b"invalid\n"[..], false, false),
        (true, &b"2"[..], false, false),
        (true, &b""[..], true, false),
    ] {
        let control = Arc::new(Control::new(1, legacy));
        if internal {
            control.cancel.store(true, Ordering::Release);
        }
        commands(io::Cursor::new(input), control.clone());
        assert!(control.cancel.load(Ordering::Acquire));
        let row = result_row(&req.strategies[0], None, 2);
        assert_eq!(
            complete_candidate(row, Ok(()), &control).unwrap().is_some(),
            retained
        );
    }
}

const PROBE_FIXTURE_READY: &str = "NFQWS2_RUNS_TEST_CANCEL_PROBE_READY";

#[test]
fn cancellation_probe_child_fixture() {
    let Some(ready) = std::env::var_os(PROBE_FIXTURE_READY) else {
        return;
    };
    std::fs::write(ready, []).unwrap();
    thread::sleep(Duration::from_secs(10));
}

#[test]
fn legacy_cancel_reports_the_actually_started_probe_and_reaps_its_child() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("started");
    let control = Arc::new(Control::new(1, true));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "matrix::tests::cancellation_probe_child_fixture",
            "--",
        ])
        .env(PROBE_FIXTURE_READY, &ready);
    thread::scope(|scope| {
        let fixture = scope.spawn(|| {
            probe(
                command,
                "fixture.example",
                (50000, 50199),
                &control,
                ProbeLane::Candidate(None),
            )
        });
        let until = Instant::now() + Duration::from_secs(8);
        while !ready.is_file() && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        let cancelled = Instant::now();
        commands(io::Cursor::new(b""), control.clone());
        assert!(ready.is_file(), "fixture didn't reach actual child launch");
        let sample = fixture.join().unwrap().unwrap().unwrap();
        assert_eq!(sample, interrupted_probe("fixture.example"));
        assert!(
            cancelled.elapsed() < Duration::from_secs(4),
            "probe did not stop at cancellation"
        );
        let mut no_traffic = sample;
        check_queue_traffic(&mut no_traffic, 10, Ok(10));
        assert!(no_traffic["err"]
            .as_str()
            .unwrap()
            .starts_with("context canceled."));
        assert_eq!(no_traffic["ok"], false);
    });
}

#[test]
fn legacy_cancel_persists_partial_row_without_publishing_a_saved_strategy() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    db.transaction(|tx| {
        tx.save(
            "lists/saved.json",
            &json!({"id":"saved","successful_strategies":[]}),
        )
    })
    .unwrap();
    let req = request();
    let control = Arc::new(Control::new(1, true));
    let mut row = result_row(&req.strategies[0], None, 2);
    row["per_target"] = json!([{"host":"one.example","ok":true,"ttfb_ms":10,"speed_bps":10000}]);
    commands(io::Cursor::new(b""), control.clone());
    let row = complete_candidate(row, Ok(()), &control).unwrap().unwrap();
    let mut report = json!({"mode":"strategy_matrix","id":"cancelled","list_id":"saved","status":"cancelled","finished_at":1,"results":[row]});
    crate::save_completed(&db, &mut report).unwrap();
    let saved = crate::get(&db, "cancelled").unwrap();
    assert_eq!(saved["status"], "cancelled");
    assert_eq!(saved["done"], 1);
    assert_eq!(saved["results"][0]["targets_ok"], 1);
    let list: Value = db.read("lists/saved.json").unwrap();
    assert_eq!(list["successful_strategies"], json!([]));
}
