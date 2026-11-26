//! Stored run reports and aggregation of completed measurements.
mod cli;
pub use cli::cli;
use nfqws2_store::{valid_name, Store, Transaction};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    io::{self, Write},
    path::Path,
};
pub mod matrix;
pub mod measure;

const KEEP: usize = 30;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn filename(dir: &str, id: &str) -> io::Result<String> {
    if !valid_name(id) {
        return Err(invalid("invalid ID"));
    }
    Ok(format!("{dir}/{id}.json"))
}

/// Recover the public view of a run left unfinished by a previous panel process.
pub fn get(db: &Store, id: &str) -> io::Result<Value> {
    get_with_live(db, id, None)
}
pub fn get_with_live(db: &Store, id: &str, live: Option<(&str, &Path)>) -> io::Result<Value> {
    if let Some((active, dir)) = live {
        if id == active {
            let progress = Store::open(dir)?.read::<Value>("active.json")?;
            if progress["id"] != id {
                return Err(invalid("incorrect active run ID"));
            }
            return Ok(progress);
        }
    }
    let mut report: Value = db.read(&filename("runs", id)?)?;
    if !report.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid run report",
        ));
    }
    if report["status"] == "running" {
        report["status"] = "error".into();
        report["error"] = "interrupted".into();
    }
    Ok(report)
}

#[derive(Deserialize)]
struct Header {
    id: String,
    #[serde(default)]
    started_at: i64,
}

fn index(db: &Store) -> io::Result<Vec<(i64, String)>> {
    let mut index = Vec::new();
    for name in db.files("runs")? {
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if let Ok(header) = db.read::<Header>(&format!("runs/{name}")) {
            if header.id == id {
                index.push((header.started_at, id.to_owned()));
            }
        }
    }
    index.sort_unstable_by(|(a, id_a), (b, id_b)| b.cmp(a).then_with(|| id_a.cmp(id_b)));
    Ok(index)
}

/// Sorted index reads use the header only. At most one full report is retained
/// while exporting a history, even when every report contains per-target detail.
pub fn write_history(db: &Store, mut out: impl Write) -> io::Result<()> {
    write_history_with_live(db, &mut out, None)
}
pub fn write_history_with_live(
    db: &Store,
    mut out: impl Write,
    live: Option<(&str, &Path)>,
) -> io::Result<()> {
    let index = index(db)?;
    out.write_all(b"[")?;
    let mut first = true;
    for (_, id) in index {
        match get_with_live(db, &id, live) {
            Ok(report) => {
                if !first {
                    out.write_all(b",")?;
                }
                serde_json::to_writer(&mut out, &report)?;
                first = false;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    out.write_all(b"]")
}

/// Aggregate already captured measurements, preserving diagnostic fields and
/// the order of equally ranked rows used by the existing frontend.
fn score(row: &Value) -> f64 {
    row["coefficient"].as_f64().unwrap_or_default()
}
fn successful(row: &Value) -> bool {
    row["success"].as_bool() == Some(true)
}
fn rank(a: &Value, b: &Value) -> Ordering {
    successful(b)
        .cmp(&successful(a))
        .then_with(|| score(b).total_cmp(&score(a)))
}

pub fn summarize(report: &mut Value) -> io::Result<()> {
    let Some(result_rows) = report["results"].as_array_mut() else {
        return Err(invalid("results must be an array"));
    };
    for row in result_rows.iter_mut() {
        if !row.is_object() {
            return Err(invalid("invalid result"));
        }
        // A report may already contain an aggregate without raw measurements.
        let Some(samples) = row["per_target"].as_array() else {
            continue;
        };
        let mut count = 0u64;
        let (mut speed, mut ttfb) = (0u128, 0u128);
        if row["error"].as_str().is_none_or(str::is_empty) {
            for sample in samples
                .iter()
                .filter(|p| p["ok"] == true && p["host"].as_str().is_some_and(|h| !h.is_empty()))
            {
                count += 1;
                speed += sample["speed_bps"].as_u64().unwrap_or_default() as u128;
                ttfb += sample["ttfb_ms"].as_u64().unwrap_or_default() as u128;
            }
        }
        let n = u128::from(count.max(1));
        let (avg_speed, avg_ttfb) = ((speed / n) as u64, (ttfb / n) as u64);
        row["targets_ok"] = count.into();
        row["avg_ttfb_ms"] = avg_ttfb.into();
        row["avg_speed_bps"] = avg_speed.into();
        row["coefficient"] = (avg_speed as f64 * 1000.0 / (1000.0 + avg_ttfb as f64)).into();
        row["success"] = (count > 0 && Some(count) == row["targets_total"].as_u64()).into();
    }
    result_rows.sort_by(rank);
    report["done"] = result_rows.len().into();
    Ok(())
}

fn merge(db: &Store, tx: &Transaction<'_>, report: &Value) -> io::Result<()> {
    let Some(id) = report["list_id"].as_str().filter(|id| !id.is_empty()) else {
        return Ok(());
    };
    let file = filename("lists", id)?;
    let mut list: Value = match db.read(&file) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    if !list.is_object() {
        return Err(invalid("invalid target list"));
    }
    let mut best = BTreeMap::new();
    match list.get_mut("successful_strategies") {
        Some(Value::Array(old)) => {
            for item in old.drain(..) {
                let key = item["strategy_id"]
                    .as_str()
                    .ok_or_else(|| invalid("invalid saved result"))?;
                best.insert(key.to_owned(), item);
            }
        }
        None | Some(Value::Null) => (),
        _ => return Err(invalid("invalid saved results")),
    }
    let found_at = report["finished_at"]
        .as_i64()
        .ok_or_else(|| invalid("missing finished_at"))?;
    let mut changed = false;
    for r in report["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| successful(r))
    {
        let key = r["strategy_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid("missing strategy_id"))?;
        if let Some(prev) = best.get(key) {
            if r["args"] == prev["args"] && score(r) <= score(prev) {
                continue;
            }
            // Replaying an older report must not revert a newer definition.
            if r["args"] != prev["args"] && prev["found_at"].as_i64().unwrap_or_default() > found_at
            {
                continue;
            }
        }
        let mut saved = json!({
            "strategy_id":key,"name":r["name"],"args":r["args"],"avg_ttfb_ms":r["avg_ttfb_ms"],
            "avg_speed_bps":r["avg_speed_bps"],"coefficient":score(r),"found_at":found_at,"run_id":report["id"]
        });
        for field in ["dns", "dns_id"] {
            if r[field].as_str().is_some_and(|s| !s.is_empty()) {
                saved[field] = r[field].clone();
            }
        }
        best.insert(key.to_owned(), saved);
        changed = true;
    }
    if changed {
        let mut saved: Vec<_> = best.into_values().collect();
        saved.sort_by(|a, b| score(b).total_cmp(&score(a)));
        list["successful_strategies"] = saved.into();
        list["updated_at"] = list["updated_at"]
            .as_i64()
            .unwrap_or_default()
            .max(found_at)
            .into();
        tx.save(&file, &list)?;
    }
    Ok(())
}

/// Save a completed report, update its list under the store's interprocess
/// lock, and trim old reports. Retrying after an interrupted write is safe.
pub fn save_completed(db: &Store, report: &mut Value) -> io::Result<()> {
    let id = report["id"].as_str().ok_or_else(|| invalid("missing id"))?;
    let file = filename("runs", id)?;
    if !matches!(
        report["status"].as_str(),
        Some("done" | "cancelled" | "error")
    ) || report["finished_at"].as_i64().is_none()
    {
        return Err(invalid("expected a finished report"));
    }
    if let Some(list) = report["list_id"].as_str().filter(|s| !s.is_empty()) {
        filename("lists", list)?;
    }
    let current = report["mode"] == "current_https";
    if current {
        let done = report["checks"]
            .as_array()
            .ok_or_else(|| invalid("missing HTTPS checks"))?
            .len();
        report["done"] = done.into();
    } else {
        summarize(report)?;
    }
    db.transaction(|tx| {
        tx.save(&file, report)?;
        if !current {
            merge(db, tx, report)?;
        }
        for (_, expired) in index(db)?.into_iter().skip(KEEP) {
            tx.delete(&filename("runs", &expired)?)?;
        }
        Ok(())
    })
}
