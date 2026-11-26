use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use tower::ServiceExt;

fn state(dir: &tempfile::TempDir) -> Shared {
    crate::http::AppState::open(
        nfqws2_config::Config {
            data_dir: dir.path().display().to_string(),
            ..Default::default()
        },
        dir.path(),
        true,
    )
    .unwrap()
}
fn flow() -> Value {
    json!({"iface":"awg0","flow":{"src":"10.0.0.5","dst":"192.0.2.80","proto":"tcp","sport":45678,"dport":443,"event":"new","packets":1,"bytes":60,"reply_bytes":0}})
}
fn fixture() -> Command {
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("powershell");
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"
            [Console]::Error.WriteLine('{"ready":true,"observed_interfaces":1}')
            [Console]::Error.WriteLine($env:N2S_AWG_EVENT)
            while ($null -ne ($update = [Console]::ReadLine())) {
                if ($update -ne 'set 1 awg0') { exit 1 }
                [Console]::Error.WriteLine($env:N2S_AWG_EVENT)
                [Console]::Error.WriteLine($env:N2S_AWG_CHANGED)
            }
        "#,
        ]);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args([
            "-c",
            r#"
            echo '{"ready":true,"observed_interfaces":1}' >&2
            printf '%s\n' "$N2S_AWG_EVENT" >&2
            while IFS= read -r line; do
                [ "$line" = 'set 1 awg0' ] || exit 1
                printf '%s\n' "$N2S_AWG_EVENT" "$N2S_AWG_CHANGED" >&2
            done"#,
        ]);
        c
    };
    cmd.env("N2S_AWG_EVENT", flow().to_string());
    let mut changed = flow();
    changed["generation"] = json!(1);
    cmd.env("N2S_AWG_CHANGED", changed.to_string());
    cmd
}
async fn api(s: &Shared, uri: &str, payload: Option<Value>) -> Value {
    let (method, body) = match payload {
        Some(v) => ("POST", Body::from(v.to_string())),
        None => ("GET", Body::empty()),
    };
    let response = crate::http::router(s.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let v = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, 200, "{method} {uri}: {v}");
    v
}
#[tokio::test]
async fn actual_process_frames_control_all_four_routes_and_clear_preserves_recording() {
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    assert!(!dir.path().join("awg.json").exists());
    assert_eq!(
        api(&s, "/api/awg2/trace/status", None).await["enabled"],
        false
    );
    assert!(!dir.path().join("awg.json").exists());
    nfqws2_awg_profile::edit_document(&s.store, |d| {
        d["servers"][0]["config"]["endpoint"] = json!("192.0.2.9");
        d["servers"][0]["config"]["unknown"] = json!(15);
        Ok(())
    })
    .unwrap();
    save(&s.store, true).unwrap();
    let (enabled, targets) = wanted(&s.store).unwrap();
    assert!(enabled);
    assert_eq!(targets.get("awg0").unwrap(), "awg0");
    let service = &s.trace.awg;
    let job = run(
        service,
        &mut fixture(),
        s.store.clone(),
        dir.path().into(),
        targets,
    )
    .await
    .unwrap();
    *service.job.lock().await = Some(job);
    timeout(Duration::from_secs(5), async {
        while service.status()["count"] != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let v = api(&s, "/api/awg2/trace/enabled", Some(json!({"enabled":true}))).await;
    assert_eq!(v["enabled"], true);
    assert_eq!(v["observed_interfaces"], 1);
    let list = api(&s, "/api/awg2/trace", None).await;
    let row = &list["entries"][0];
    assert_eq!(row["kind"], "flow");
    assert_eq!(row["tunnel_id"], "awg0");
    assert_eq!(row["dport"], 443);
    let since = format!("/api/awg2/trace?since={}", row["ts"].as_u64().unwrap());
    assert_eq!(api(&s, &since, None).await["entries"], json!([]));
    nfqws2_awg_profile::edit_document(&s.store, |d| {
        d["active_id"] = json!("renamed-tunnel");
        d["servers"][0]["id"] = json!("renamed-tunnel");
        Ok(())
    })
    .unwrap();
    timeout(Duration::from_secs(10), async {
        while service.status()["count"] == 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let added = api(&s, &since, None).await;
    assert_eq!(added["entries"].as_array().unwrap().len(), 1);
    assert_eq!(added["entries"][0]["tunnel_id"], "renamed-tunnel");
    let cleared = api(&s, "/api/awg2/trace/clear", Some(json!({}))).await;
    assert_eq!(cleared["count"], 0);
    assert_eq!(cleared["enabled"], true);
    let settings = api(
        &s,
        "/api/system/settings",
        Some(json!({"trace_mode":"off"})),
    )
    .await;
    assert_eq!(settings["trace_mode"], "off");
    let ended = api(&s, "/api/awg2/trace/status", None).await;
    assert_eq!(ended["enabled"], false);
    assert_eq!(ended["observed_interfaces"], 0);
    assert!(service.job.lock().await.is_none());
    assert!(!wanted(&s.store).unwrap().0);
    assert_eq!(
        nfqws2_awg_profile::read(&s.store).unwrap()["servers"][0]["config"]["unknown"],
        15
    );
}

#[tokio::test]
async fn conntrack_api_records_direct_state_and_ptr_without_a_capture_helper() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path().join("proc");
    std::fs::create_dir_all(proc.join("net")).unwrap();
    std::fs::create_dir_all(proc.join("sys/kernel/random")).unwrap();
    std::fs::write(
        proc.join("sys/kernel/random/boot_id"),
        "d6a640c3-1d1c-4a65-b253-f9ffb14df7ed\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("etc")).unwrap();
    std::fs::write(dir.path().join("etc/hosts"), "203.0.113.7 direct.example\n").unwrap();
    let rows = proc.join("net/nf_conntrack");
    let outgoing = "src=192.168.5.2 dst=203.0.113.7 sport=41000 dport=443 packets=1 bytes=60";
    let incoming = "src=203.0.113.7 dst=192.168.5.2 sport=443 dport=41000";
    std::fs::write(&rows, format!("ipv4 2 tcp 6 90 SYN_SENT {outgoing} [UNREPLIED] {incoming} packets=0 bytes=0 slan\n\
        ipv4 2 tcp 6 90 SYN_SENT src=192.168.5.2 dst=198.51.100.1 sport=41001 dport=443 [UNREPLIED] swan\n")).unwrap();
    let s = state(&dir);
    let status = api(&s, "/api/awg2/trace/status", None).await;
    assert_eq!(status["source"], "dns_and_conntrack");
    assert!(status.get("need_install").is_none());
    assert_eq!(status["enabled"], false);
    let toggle = "/api/awg2/trace/enabled";
    assert_eq!(
        api(&s, toggle, Some(json!({"enabled":true}))).await["enabled"],
        true
    );
    async fn wait_for_event(s: &Shared, event: &str) {
        timeout(Duration::from_secs(4), async {
            loop {
                if s.trace.awg.ring.lock().unwrap().entries.iter().any(|entry| {
                    matches!(&entry.fields, Fields::Flow { flow, .. } if flow.event == event)
                }) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        })
        .await
        .unwrap();
    }
    wait_for_event(&s, "host").await;
    std::fs::write(
        &rows,
        format!(
            "ipv4 2 tcp 6 90 ESTABLISHED {outgoing} {incoming} packets=1 bytes=72 [ASSURED] slan\n"
        ),
    )
    .unwrap();
    wait_for_event(&s, "replied").await;
    assert_eq!(
        api(&s, toggle, Some(json!({"enabled":false}))).await["enabled"],
        false
    );
    let list = api(&s, "/api/awg2/trace", None).await;
    let entries = list["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["decision"], "direct");
    assert_eq!(entries[0]["state"], "SYN_SENT");
    assert_eq!(entries[0]["unreplied"], true);
    assert!(entries[0].get("tunnel_iface").is_none());
    assert_eq!(entries[1]["decision"], "direct");
    assert_eq!(entries[1]["name"], "direct.example");
    assert_eq!(entries[2]["reply_bytes"], 72);
    assert_eq!(entries[2]["assured"], true);
}
#[tokio::test]
async fn dashboard_counts_dns_without_recording_and_clear_only_removes_rows() {
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    let service = &s.trace.awg;
    let name = "office.test";
    let src = Some("192.0.2.3".parse().unwrap());
    let query = nfqws2_dns::build_query(name, 1, 7).unwrap();
    let mut reply = nfqws2_dns::response_error(&query, 0);
    reply[7] = 2;
    for last in [7, 8] {
        reply.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, last]);
    }
    let answer = nfqws2_dns::trace_answer(&reply).unwrap();
    let counters = |dns, tunnel, blocked| json!({"dns":dns,"sni":0,"flow":0,"tunnel":tunnel,"direct":0,"blocked":blocked,"cdn_skip":0});
    assert_eq!(
        api(&s, "/api/dashboard", None).await["trace_counters"],
        counters(0, 0, 0)
    );
    service.record_dns(name, src, &answer, false, |_| ("tunnel", Some(2)));
    assert_eq!(
        api(&s, "/api/dashboard", None).await["trace_counters"],
        counters(2, 2, 0)
    );
    assert_eq!(api(&s, "/api/awg2/trace", None).await["entries"], json!([]));

    service.ring.lock().unwrap().recording = true;
    service.record_dns(name, src, &answer, false, |_| ("tunnel", Some(2)));
    let negative = nfqws2_dns::trace_answer(&nfqws2_dns::response_error(&query, 3)).unwrap();
    service.record_dns(name, src, &negative, false, |_| {
        panic!("classified a negative reply")
    });
    let list = api(&s, "/api/awg2/trace", None).await;
    let rows = list["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["src"], "192.0.2.3");
    assert_eq!(rows[0]["name"], name);
    assert_eq!(rows[0]["kind"], "dns");
    assert_eq!(rows[0]["qtype"], "A");
    assert_eq!(rows[0]["dst"], "198.51.100.7");
    assert_eq!(rows[0]["rule"], 2);
    assert_eq!(rows[1]["dst"], "198.51.100.8");
    assert_eq!(rows[2]["decision"], "blocked");
    assert!(rows[2].get("dst").is_none());
    assert_eq!(
        api(&s, "/api/awg2/trace/clear", Some(json!({}))).await["count"],
        0
    );
    assert_eq!(
        api(&s, "/api/dashboard", None).await["trace_counters"],
        counters(5, 4, 1)
    );
}

#[test]
fn a_tunnel_flow_uses_the_recent_dns_name_for_its_destination() {
    let service = Service::default();
    let ip = "192.0.2.80".parse().unwrap();
    let answer = nfqws2_dns::TraceAnswer {
        qtype: 1,
        addresses: vec![ip],
        sinkholed: false,
    };
    service.record_dns("Media.Example.", None, &answer, false, |_| ("direct", None));
    let mut ring = service.ring.lock().unwrap();
    assert!(ring.entries.is_empty());
    ring.recording = true;
    assert!(ring
        .update(flow(), &Targets::from([("awg0".into(), "one".into())]))
        .unwrap()
        .is_none());
    assert_eq!(ring.entries[0].name, "media.example");
    assert_eq!(ring.entries[0].kind, "flow");
    assert_eq!(
        ring.names
            .get(ip, Instant::now() + Duration::from_secs(30 * 60)),
        None
    );
}

#[tokio::test]
async fn reverse_flow_name_creates_a_host_event_and_obeys_recording_and_generation() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("etc")).unwrap();
    std::fs::write(dir.path().join("etc/hosts"), "192.0.2.80 PTR.Example.\n").unwrap();
    let mut ring = Ring::default();
    let targets = Targets::from([("awg0".into(), "one".into())]);
    assert!(ring.update(flow(), &targets).unwrap().is_none());
    ring.recording = true;
    let mut pending = ptr::Queue::new(ptr::Resolver::new(dir.path()));
    for generation in [1, 2] {
        let request = ring.update(flow(), &targets).unwrap().unwrap();
        pending.request(&mut ring, request, generation);
        let duplicate = ring.update(flow(), &targets).unwrap().unwrap();
        pending.request(&mut ring, duplicate, generation);
        let result = pending.next().await.unwrap();
        assert!(pending.is_empty());
        ring.resolved(result, 2);
    }
    assert_eq!(ring.entries.len(), 5);
    assert_eq!(ring.entries[0].name, "TLS tcp/443");
    let host = serde_json::to_value(ring.entries.back().unwrap()).unwrap();
    assert_eq!(host["event"], "host");
    assert_eq!(host["name"], "ptr.example");
    assert_eq!(host["tunnel_id"], "one");
    assert!(ring.update(flow(), &targets).unwrap().is_none());
}

#[tokio::test]
async fn bounded_frames_and_ring_discard_foreign_interfaces_and_extra_fields() {
    let targets = Targets::from([("awg0".into(), "one".into())]);
    let mut ring = Ring::default();
    assert_eq!(ring.status(false)["need_install"], true);
    assert_eq!(ring.status(false)["package"], PACKAGE);
    assert!(ring.status(true).get("need_install").is_none());
    let mut v = flow();
    v["iface"] = json!("wan0");
    assert!(ring.update(v, &targets).unwrap().is_none());
    assert!(ring.entries.is_empty());
    assert_eq!(ring.counters.flow, 0);
    ring.recording = true;
    let mut v = flow();
    v["flow"]["data"] = json!("not retained");
    for _ in 0..(CAP + 2) {
        let _ = ring.update(v.clone(), &targets).unwrap();
    }
    assert_eq!(ring.entries.len(), CAP);
    assert!(ring.entries.iter().map(|e| e.ts).is_sorted());
    assert!(ring.entries.iter().all(|e| e.ts % 32000 == 0));
    assert!(!serde_json::to_string(&ring.entries)
        .unwrap()
        .contains("retained"));
    assert!(ring
        .update(json!({"iface":"awg0","flow":{}}), &targets)
        .is_err());
    let long = vec![b'x'; 4097];
    let mut partial = Vec::new();
    assert!(frame(
        &mut BufReader::with_capacity(24, long.as_slice()),
        &mut partial
    )
    .await
    .is_err());
    assert!(partial.len() <= 4096);
    let mut partial = Vec::new();
    let mut r = BufReader::with_capacity(
        2,
        r#"{"a":4}
{"b":7}
"#
        .as_bytes(),
    );
    assert_eq!(frame(&mut r, &mut partial).await.unwrap()["a"], 4);
    assert_eq!(frame(&mut r, &mut partial).await.unwrap()["b"], 7);
}
