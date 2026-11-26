use nfqws2_runs::{get, save_completed, write_history};
use nfqws2_store::Store;
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    thread,
};
use tempfile::tempdir;

fn report(id: &str) -> Value {
    json!({
        "id":id,"list_id":"list","started_at":10,"finished_at":20,"status":"done","new_key":"kept",
        "results":[
            {"strategy_id":"partial","targets_total":2,"per_target":[{"host":"one.test","ok":true,"ttfb_ms":2,"speed_bps":2000}]},
            {"strategy_id":"failed","targets_total":1,"error":"measurement invalid","per_target":[{"host":"one.test","ok":true}]},
            {"strategy_id":"ok","dns":"Selected","name":"measurement","args":"changed","targets_total":2,"per_target":[
                {"host":"one.test","ok":true,"ttfb_ms":3,"speed_bps":100},
                {"host":"two.test","ok":true,"ttfb_ms":2,"speed_bps":201}
            ]}
        ]
    })
}

#[test]
fn save_recomputes_metrics_merges_latest_list_and_is_idempotent() {
    let dir = tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    db.transaction(|tx| {
        tx.save(
            "lists/list.json",
            &json!({
                "id":"list","name":"user-edit","extra":{"kept":true},"successful_strategies":[
                    {"strategy_id":"other","args":"same","coefficient":999,"metadata":"retained"},
                    {"strategy_id":"ok","args":"old","coefficient":500,"found_at":5}
                ]
            }),
        )
    })
    .unwrap();
    let mut doc = report("run");
    save_completed(&db, &mut doc).unwrap();
    let stored = get(&db, "run").unwrap();
    assert_eq!(stored, doc);
    assert_eq!(stored["done"], 3);
    assert_eq!(stored["results"][0]["strategy_id"], "ok");
    let best = &stored["results"][0];
    assert_eq!(best["targets_ok"], 2);
    assert_eq!(best["avg_ttfb_ms"], 2);
    assert_eq!(best["avg_speed_bps"], 150);
    assert_eq!(best["coefficient"], 150.0 * 1000.0 / 1002.0);
    assert_eq!(stored["results"][1]["success"], false);
    assert_eq!(stored["results"][2]["targets_ok"], 0);
    let before: Value = db.read("lists/list.json").unwrap();
    assert_eq!(before["name"], "user-edit");
    assert_eq!(before["extra"]["kept"], true);
    assert_eq!(before["successful_strategies"][0]["metadata"], "retained");
    let saved = &before["successful_strategies"][1];
    assert_eq!(saved["run_id"], "run");
    assert_eq!(saved["dns"], "Selected");
    assert!(saved.get("dns_id").is_none());
    save_completed(&db, &mut doc).unwrap();
    assert_eq!(db.read::<Value>("lists/list.json").unwrap(), before);
    let mut stale = report("older");
    stale["finished_at"] = 15.into();
    stale["results"][2]["args"] = "old arguments".into();
    save_completed(&db, &mut stale).unwrap();
    assert_eq!(db.read::<Value>("lists/list.json").unwrap(), before);
}

#[test]
fn retention_uses_on_disk_history_and_recovers_running_reports_on_read() {
    let dir = tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    fs::create_dir(dir.path().join("runs")).unwrap();
    for i in 0..30 {
        let id = format!("r{i}");
        fs::write(
            dir.path().join("runs").join(format!("{id}.json")),
            json!({"id":id,"started_at":i,"status":"running","extra":[i]}).to_string(),
        )
        .unwrap();
    }
    fs::write(dir.path().join("runs/bad.json"), "bad").unwrap();
    let mut doc =
        json!({"id":"latest","started_at":30,"finished_at":31,"results":[],"status":"cancelled"});
    save_completed(&db, &mut doc).unwrap();
    let mut stream = Vec::new();
    write_history(&db, &mut stream).unwrap();
    let keeps: Vec<Value> = serde_json::from_slice(&stream).unwrap();
    assert_eq!(keeps.len(), 30);
    assert_eq!(keeps[0]["id"], "latest");
    assert_eq!(
        keeps[1],
        json!({"id":"r29","started_at":29,"status":"error","error":"interrupted","extra":[29]})
    );
    assert_eq!(keeps.last().unwrap()["id"], "r1");
    assert!(!dir.path().join("runs/r0.json").exists());
    assert!(dir.path().join("runs/bad.json").is_file());
    assert_eq!(
        db.read::<Value>("runs/r29.json").unwrap()["status"],
        "running"
    );
    assert!(get(&db, "../id").is_err());
}

#[test]
fn concurrent_finishes_preserve_all_successful_measurements_and_metadata() {
    let dir = tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    db.transaction(|tx| tx.save("lists/list.json", &json!({"id":"list","name":"before"})))
        .unwrap();
    thread::scope(|scope| {
        for i in 0..5 {
            let db = &db;
            scope.spawn(move || {
                let id = format!("r{i}");
                let mut run = report(&id);
                run["results"][2]["strategy_id"] = id.into();
                save_completed(db, &mut run).unwrap();
            });
        }
        scope.spawn(|| {
            db.transaction(|tx| {
                let mut list: Value = db.read("lists/list.json")?;
                list["name"] = "edited".into();
                tx.save("lists/list.json", &list)
            })
            .unwrap()
        });
    });
    let list: Value = db.read("lists/list.json").unwrap();
    assert_eq!(list["name"], "edited");
    assert_eq!(list["successful_strategies"].as_array().unwrap().len(), 5);
}

#[test]
fn compact_cli_saves_reports_and_returns_typed_exit_codes() {
    let dir = tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_nfqws2-runs");
    let cmd = |verb: &str| {
        let mut proc = Command::new(bin);
        proc.arg(verb).arg(dir.path());
        proc
    };
    let mut child = cmd("save").stdin(Stdio::piped()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(report("test").to_string().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    let history = cmd("history").output().unwrap();
    let item = cmd("get").arg("test").output().unwrap();
    assert!(item.status.success() && history.status.success());
    let list: Vec<Value> = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(
        list,
        [serde_json::from_slice::<Value>(&item.stdout).unwrap()]
    );
    for (id, code) in [("missing", 4), ("../escape", 2)] {
        let out = cmd("get").arg(id).output().unwrap();
        assert!(out.stdout.is_empty());
        assert_eq!(out.status.code(), Some(code));
    }
}
