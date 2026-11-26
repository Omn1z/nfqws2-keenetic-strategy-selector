use super::{lifecycle, running};
use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{extract::State, Json};
use nfqws2_store::{Store, Transaction};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io, path::Path, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};
pub(super) const FILE: &str = "automation.json";
pub(crate) mod candidates;
mod picker;
pub(super) use picker::pick_now;
pub(crate) use picker::{shutdown, Picker};
#[derive(Default)]
pub(crate) struct Health {
    last: Option<(String, u64, u64)>,
    unhealthy: u8,
    pub(super) retry_stop: bool,
}
impl Health {
    fn observe(&self, link: Option<&Value>, now: u64) -> (bool, u64) {
        let Some(c) = link else {
            return (false, 0);
        };
        let stamp = c["last_handshake"].as_u64().unwrap_or(0);
        let age = now.checked_sub(stamp).filter(|_| stamp != 0).unwrap_or(181);
        // The AWG supervisor has the peer's key lifetime and traffic samples.
        // Keep reporting the actual handshake age, even when RX proves liveness.
        if c["last_peer_activity"].is_u64() {
            return (c["connected"] == true, age);
        }
        let idle = self.last.as_ref().is_some_and(|(id, rx, t)| {
            c["id"] == id.as_str()
                && c["rx_bytes"].as_u64() == Some(*rx)
                && now.saturating_sub(*t) < 90
        });
        (age <= 180 && !(age > 90 && idle), age)
    }
    fn remember_peer(&mut self, link: Option<&Value>, now: u64) {
        self.last = link.map(|c| {
            (
                c["id"].as_str().unwrap_or("").into(),
                c["rx_bytes"].as_u64().unwrap_or(0),
                now,
            )
        });
    }
    fn tick(&mut self, link: Option<&Value>, now: u64) -> (bool, bool) {
        let (healthy, _) = self.observe(link, now);
        self.remember_peer(link, now);
        self.unhealthy = if healthy {
            0
        } else {
            self.unhealthy.saturating_add(1)
        };
        (healthy, self.unhealthy >= 2)
    }
}
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn read(db: &Store) -> io::Result<Value> {
    match db.read_limited::<Value>(FILE, 1 << 20) {
        Ok(v) if v.is_object() => Ok(v),
        Ok(_) => Err(invalid("неверный формат automation.json")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e),
    }
}
pub(super) fn write_state(tx: &Transaction<'_>, mut state: Value) -> io::Result<()> {
    // Go discards the entire document, including manual OFF, when mode is empty.
    if state["mode"].as_str().is_none_or(str::is_empty) {
        state["mode"] = json!("off");
    }
    if state["interval_h"].as_i64().is_none_or(|hours| hours <= 0) {
        state["interval_h"] = json!(24);
    }
    tx.save(FILE, &state)
}
fn mode(v: &Value) -> &str {
    match v["mode"].as_str() {
        // The Go loader migrates its historical implicit "auto" to "on".
        Some("auto") if v["rust_mode_explicit"] != true => "on",
        Some("on") => "on",
        Some("auto") => "auto",
        _ => "off",
    }
}
fn link(s: &Shared) -> io::Result<Option<Value>> {
    Ok(
        nfqws2_awg_profile::dashboard(&s.store, Path::new(&s.config.data_dir), &s.awg_runtime)?
            .into_iter()
            .find(|v| v["running"] == true),
    )
}
fn view(s: &Shared) -> io::Result<Value> {
    let v = read(&s.store)?;
    let connection = link(s)?;
    let (ok, age) = s
        .watchdog
        .lock()
        .unwrap()
        .observe(connection.as_ref(), nfqws2_awg_profile::now());
    let mut out = json!({"mode":mode(&v),"auto_pick":v["auto_pick"]==true,"auto_pick_supported":crate::runs::matrix_available(),"periodic_scan":v["periodic_scan"]==true,"interval_h":v["interval_h"].as_u64().filter(|n|*n>0).unwrap_or(24),"nfqws2_manual_off":lifecycle::manual_off(&s.store)?,
        "awg_healthy":ok,"handshake_age_sec":age,"nfqws2_running":running(&s.config,Path::new("/proc")),"pick_in_progress":s.auto_pick.running()});
    for k in [
        "last_pick_at",
        "last_pick_name",
        "last_pick_args",
        "last_pick_error",
    ] {
        if let Some(val) = v.get(k) {
            out[k] = val.clone();
        }
    }
    Ok(out)
}
pub(super) async fn status(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || view(&s).map(Json)).await
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Config {
    mode: String,
    auto_pick: bool,
    periodic_scan: bool,
    interval_h: i64,
}
fn save(db: &Store, input: &Config) -> io::Result<()> {
    if !matches!(input.mode.as_str(), "" | "off" | "on" | "auto") {
        return Err(invalid("неизвестный режим NFQWS2"));
    }
    db.transaction(|tx| {
        let mut v = read(db)?;
        if !input.mode.is_empty() {
            v["mode"] = json!(input.mode);
            v["rust_mode_explicit"] = json!(true);
        }
        if input.interval_h > 0 {
            v["interval_h"] = json!(input.interval_h);
        }
        v["auto_pick"] = json!(input.auto_pick);
        v["periodic_scan"] = json!(input.periodic_scan);
        write_state(tx, v)
    })
}
pub(super) async fn configure(
    State(s): State<Shared>,
    ApiJson(input): ApiJson<Config>,
) -> Result<Json<Value>, ApiError> {
    let lock = lifecycle::OPERATIONS.lock().await;
    blocking(move || {
        let _lock = lock;
        save(&s.store, &input)?;
        s.watchdog.lock().unwrap().unhealthy = 0;
        view(&s).map(Json)
    })
    .await
}
async fn step(s: Shared, first: bool) -> io::Result<(bool, io::Result<()>)> {
    let lock = lifecycle::OPERATIONS.lock().await;
    tokio::task::spawn_blocking(move || {
        let _lock = lock;
        let v = read(&s.store)?;
        let mode = mode(&v);
        let manual_off = v["nfqws2_manual_off"] == true;
        let periodic = v["auto_pick"] == true && v["periodic_scan"] == true;
        let sample_awg = !manual_off && (mode == "auto" || periodic);
        // Go observes RX once before its first scheduler tick.
        let initial = if first && sample_awg {
            link(&s).ok().flatten()
        } else {
            None
        };
        let live = if sample_awg { link(&s) } else { Ok(None) };
        let (healthy, fallback, retry) = {
            let mut w = s.watchdog.lock().unwrap();
            let now = nfqws2_awg_profile::now();
            if let Some(initial) = initial.as_ref() {
                w.remember_peer(Some(initial), now);
            }
            let (healthy, fallback) = if let (true, Ok(live)) = (sample_awg, &live) {
                w.tick(live.as_ref(), now)
            } else {
                (false, false)
            };
            (healthy, fallback, w.retry_stop)
        };
        if mode == "off" && !manual_off {
            return Ok((healthy, live.map(|_| ())));
        }
        let r = lifecycle::watchdog(&s, mode == "on" || mode == "auto" && fallback, retry);
        s.watchdog.lock().unwrap().retry_stop = manual_off && r.is_err();
        Ok((healthy, r.and(live.map(|_| ()))))
    })
    .await?
}
pub(crate) fn start(s: &Shared) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (stop, mut halt) = oneshot::channel();
    let weak = std::sync::Arc::downgrade(s);
    let task = tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_secs(30));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = String::new();
        let mut first = true;
        loop {
            tokio::select! {biased; _=&mut halt=>break,_=ticks.tick()=>{}}
            let Some(s) = weak.upgrade() else { break };
            let (healthy, service) = step(s.clone(), first)
                .await
                .unwrap_or_else(|e| (false, Err(e)));
            match service {
                Ok(()) => last.clear(),
                Err(e) => {
                    let msg = e.to_string();
                    if msg != last {
                        s.logs.append("automation", "warn", &msg);
                        last = msg;
                    }
                }
            }
            if let Err(e) = picker::scheduled(s.clone(), first, healthy).await {
                let msg = e.to_string();
                if msg != last {
                    s.logs.append("automation", "warn", &msg);
                    last = msg;
                }
            }
            first = false;
        }
    });
    (stop, task)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automation_uses_the_supervised_peer_health_with_an_old_handshake() {
        let mut health = Health::default();
        let mut link = json!({"id":"a","connected":true,"last_handshake":100,
            "last_peer_activity":515,"rx_bytes":9600});
        assert_eq!(health.observe(Some(&link), 520), (true, 420));
        assert_eq!(health.tick(Some(&link), 520), (true, false));
        link["connected"] = json!(false);
        assert_eq!(health.tick(Some(&link), 550), (false, false));
        assert_eq!(health.tick(Some(&link), 580), (false, true));
        link["connected"] = json!(true);
        assert_eq!(health.tick(Some(&link), 590), (true, false));
    }
    #[test]
    fn a_second_unhealthy_sample_triggers_fallback() {
        let mut h = Health::default();
        let mut link = json!({"id":"a","rx_bytes":22,"last_handshake":100});
        assert_eq!(h.tick(Some(&link), 140), (true, false));
        assert_eq!(h.tick(Some(&link), 192), (false, false));
        assert_eq!(h.tick(Some(&link), 222), (false, true));
        link["rx_bytes"] = json!(23);
        assert_eq!(h.tick(Some(&link), 240), (true, false));
        assert_eq!(h.tick(None, 270), (false, false));
        assert_eq!(h.tick(None, 300), (false, true));
    }
    #[test]
    fn initial_rx_baseline_prevents_a_periodic_pick_for_a_stale_external_peer() {
        let mut health = Health::default();
        let mut peer = json!({"id":"legacy","rx_bytes":12,"last_handshake":100});
        health.remember_peer(Some(&peer), 225);
        assert_eq!(health.tick(Some(&peer), 226), (false, false));
        peer["rx_bytes"] = json!(13);
        assert_eq!(health.tick(Some(&peer), 256), (true, false));
    }
    #[test]
    fn patch_preserves_manual_stop_history_and_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        db.transaction(|tx|tx.save(FILE,&json!({"mode":"auto","auto_pick":true,"last_pick_at":10,"nfqws2_manual_off":true,"foreign":3}))).unwrap();
        assert_eq!(mode(&read(&db).unwrap()), "on");
        save(
            &db,
            &Config {
                mode: "auto".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let v = read(&db).unwrap();
        assert_eq!(mode(&v), "auto");
        assert_eq!(v["nfqws2_manual_off"], true);
        assert_eq!(v["last_pick_at"], 10);
        assert_eq!(v["foreign"], 3);
        save(
            &db,
            &Config {
                auto_pick: true,
                ..Default::default()
            },
        )
        .unwrap();
        let next = read(&db).unwrap();
        assert_eq!(next["auto_pick"], true);
        assert_eq!(next["last_pick_at"], 10);
        assert_eq!(next["foreign"], 3);
    }
}
