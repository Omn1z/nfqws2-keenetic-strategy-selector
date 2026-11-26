use super::{frame, reap, stop, Entry, Fields, Job, Ring};
use nfqws2_awg_rules::kernel::LegacySni;
use serde::Deserialize;
use std::{
    collections::{HashSet, VecDeque},
    io,
    net::IpAddr,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::BufReader,
    process::Command,
    sync::{oneshot, watch, Mutex as AsyncMutex},
    time::sleep,
};

const DESTINATION_TTL: Duration = Duration::from_secs(3600);
const DESTINATION_CAP: usize = 16384;
const RETRY: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) struct Capture {
    policy: watch::Sender<Option<LegacySni>>,
    job: AsyncMutex<Option<Job>>,
}
impl Capture {
    pub(super) fn publish(&self, policy: Option<LegacySni>) {
        self.policy.send_if_modified(|current| {
            if current.is_none() && policy.is_none() {
                return false;
            }
            *current = policy;
            true
        });
    }

    pub(super) async fn start(&self, ring: Arc<Mutex<Ring>>) {
        let mut slot = self.job.lock().await;
        if slot.as_ref().is_some_and(|j| !j.task.is_finished()) {
            // A package may have just been installed. Interrupt the retry wait.
            self.policy.send_modify(|_| {});
            return;
        }
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(supervise(ring, self.policy.subscribe(), shutdown));
        *slot = Some(Job { stop, task });
    }

    pub(super) async fn shutdown(&self) {
        stop(self.job.lock().await.take()).await;
    }
}

async fn supervise(
    ring: Arc<Mutex<Ring>>,
    mut policy: watch::Receiver<Option<LegacySni>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    while matches!(
        shutdown.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ) {
        let active = policy.borrow_and_update().as_ref().is_some_and(current);
        if active {
            if let Some(path) = super::super::helper().ok().filter(|path| path.is_file()) {
                let mut cmd = Command::new(path);
                cmd.arg("awg-sni");
                let result = session(&mut cmd, &ring, &mut policy, &mut shutdown).await;
                let mut trace = ring.lock().unwrap();
                trace.sni_interfaces = 0;
                trace.sni_limited = false;
                if let Err(e) = result {
                    trace.sni_error = e.to_string().chars().take(220).collect();
                } else {
                    trace.sni_error.clear();
                    continue;
                }
            }
        } else {
            ring.lock().unwrap().sni_error.clear();
        }
        tokio::select! {
            _ = &mut shutdown => return,
            updated = policy.changed() => { if updated.is_err() {return;} }
            _ = sleep(RETRY), if active => (),
        }
    }
}

fn current(policy: &LegacySni) -> bool {
    let end = policy.trial_expires();
    end == 0 || nfqws2_awg_profile::now() < end
}

async fn expire_at(until: u64) {
    if until == 0 {
        std::future::pending::<()>().await;
    } else {
        sleep(Duration::from_secs(
            until.saturating_sub(nfqws2_awg_profile::now()),
        ))
        .await;
    }
}

#[derive(Deserialize)]
struct Hello {
    name: String,
    dst: IpAddr,
}

#[derive(Default)]
struct Recent {
    addresses: HashSet<IpAddr>,
    expires: VecDeque<(Instant, IpAddr)>,
}
impl Recent {
    fn has(&mut self, ip: IpAddr, now: Instant) -> bool {
        while self.expires.front().is_some_and(|(end, _)| *end <= now) {
            if let Some((_, expired)) = self.expires.pop_front() {
                self.addresses.remove(&expired);
            }
        }
        self.addresses.contains(&ip)
    }

    fn remember(&mut self, ip: IpAddr, now: Instant) {
        if self.addresses.len() == DESTINATION_CAP {
            if let Some((_, oldest)) = self.expires.pop_front() {
                self.addresses.remove(&oldest);
            }
        }
        self.addresses.insert(ip);
        self.expires.push_back((now + DESTINATION_TTL, ip));
    }

    fn record(
        &mut self,
        ring: &mut Ring,
        hello: Hello,
        now: Instant,
        decide: impl FnOnce(&str, IpAddr) -> (&'static str, Option<usize>),
    ) -> io::Result<()> {
        if hello.name.is_empty()
            || hello.name.len() > 253
            || !hello
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !hello.dst.is_ipv4()
        {
            return Err(io::Error::other(
                "неверное событие SNI от модуля трассировки",
            ));
        }
        if self.has(hello.dst, now) {
            return Ok(());
        }
        let (decision, rule) = decide(&hello.name, hello.dst);
        if rule.is_some() && decision != "cdn-skip" {
            self.remember(hello.dst, now);
        }
        ring.names.remember(hello.dst, &hello.name, now);
        ring.record("sni", decision, |ts| {
            let reason = match (decision, rule) {
                ("cdn-skip", _) => "общий CDN — глобальное исключение direct не добавлено".into(),
                ("direct", Some(n)) => format!("правило #{n} (direct, SNI carve-out)"),
                ("tunnel", Some(n)) => format!("правило #{n} (tunnel) → awg2_sni"),
                _ => "нет совпадения".into(),
            };
            Entry {
                ts,
                kind: "sni",
                decision,
                reason,
                name: hello.name,
                fields: Fields::Sni {
                    dst: hello.dst,
                    rule,
                },
            }
        });
        Ok(())
    }
}

async fn session(
    cmd: &mut Command,
    ring: &Mutex<Ring>,
    policy: &mut watch::Receiver<Option<LegacySni>>,
    shutdown: &mut oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut reader = BufReader::new(child.stderr.take().unwrap());
    let mut partial = Vec::new();
    let mut recent = Recent::default();
    let ready_by = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut ready = false;
    let result = async {
        loop {
            let Some(until) = policy.borrow().as_ref().filter(|p| current(p)).map(LegacySni::trial_expires) else {
                return Ok(());
            };
            tokio::select! {
                biased;
                _ = &mut *shutdown => return Ok(()),
                updated = policy.changed() => {
                    if updated.is_err() { return Ok(()); }
                    recent = Recent::default();
                }
                _ = expire_at(until) => return Ok(()),
                _ = tokio::time::sleep_until(ready_by), if !ready => return Err(io::ErrorKind::TimedOut.into()),
                value = frame(&mut reader, &mut partial) => {
                    let mut v = value?;
                    if let Some(error) = v["error"].as_str() {
                        return Err(io::Error::other(error.chars().take(220).collect::<String>()));
                    }
                    let selected = policy.borrow_and_update();
                    if selected.has_changed() {
                        recent = Recent::default();
                    }
                    let Some(selected) = selected.as_ref().filter(|p| current(p)) else { return Ok(()); };
                    let mut r = ring.lock().unwrap();
                    if v["ready"] == true {
                        ready = true;
                        r.sni_interfaces = v["observed_interfaces"].as_u64().unwrap_or_default().min(8);
                        r.sni_limited = v["limited"] == true;
                        r.sni_error.clear();
                    } else if ready {
                        let hello = serde_json::from_value(v["sni"].take())?;
                        recent.record(&mut r, hello, Instant::now(), |name, dst| selected.decision(name, dst))?;
                    }
                }
            }
        }
    }.await;
    reap(&mut child).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn counts_without_recording_and_remembers_only_matched_destinations() {
        let mut ring = Ring::default();
        let mut recent = Recent::default();
        let ip = "198.51.100.7".parse().unwrap();
        let hello = || Hello {
            name: "office.test".into(),
            dst: ip,
        };
        let now = Instant::now();
        let direct = |_: &str, _| ("direct", Some(1));
        recent.record(&mut ring, hello(), now, direct).unwrap();
        recent.record(&mut ring, hello(), now, direct).unwrap();
        assert_eq!(ring.counters.sni, 1);
        assert_eq!(ring.counters.direct, 1);
        assert!(ring.entries.is_empty());
        assert_eq!(ring.names.get(ip, now), Some("office.test"));

        ring.recording = true;
        let later = now + DESTINATION_TTL;
        for _ in 0..2 {
            recent
                .record(&mut ring, hello(), later, |_, _| ("cdn-skip", None))
                .unwrap();
        }
        assert_eq!(ring.counters.sni, 3);
        let row = serde_json::to_value(&ring.entries[0]).unwrap();
        assert_eq!(row["kind"], "sni");
        assert_eq!(row["dst"], "198.51.100.7");
        assert_eq!(row["decision"], "cdn-skip");
        assert!(row.get("src").is_none());
        assert!(row.get("qtype").is_none());
    }

    fn legacy_policy(dir: &tempfile::TempDir) -> LegacySni {
        let db = nfqws2_store::Store::open(dir.path()).unwrap();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing_revision"] = json!(4);
            let main = &mut doc["servers"][0]["config"];
            main["enabled"] = json!(true);
            main["client"]["enabled"] = json!(true);
            main["routing"] = json!({"mode":"full","active":true,"sni_routing":true,
                "domain_source":"resolve","zones":[{"enabled":true,"route":"direct","tunnel_id":"copied","domains":["office.test"]}]});
            let copy = json!({"id":"copied","config":{"endpoint":"","peers":[],"enabled":false,"client":{"enabled":false}}});
            doc["servers"].as_array_mut().unwrap().push(copy);
            Ok(())
        }).unwrap();
        let plan = json!({"prefixes":{"0.0.0.0/0":"awg0"},"targets":{"awg0":{"id":"awg0",
             "public_key":"a".repeat(44),"mtu":1420}},"revision":4,"go_ipv4":true,
            "legacy_full":"ipv4_only","full_endpoints":["198.51.100.10"]});
        db.transaction(|tx| tx.save_runtime("awg-static-ipv4.json", &json!({
            "boot":"34343434-3434-3434-3434-343434343434","installed":plan,"committed":plan,"preparing":[],"expires":0
        }))).unwrap();
        nfqws2_awg_rules::kernel::observations(&db)
            .unwrap()
            .1
            .unwrap()
            .unwrap()
    }

    fn helper_fixture() -> Command {
        #[cfg(windows)]
        let mut cmd = {
            let mut cmd = Command::new("powershell");
            cmd.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                r#"
                [Console]::Error.WriteLine($env:FIXTURE_READY)
                [Console]::Error.WriteLine($env:FIXTURE_SNI)
                [Console]::Error.WriteLine($env:FIXTURE_SNI)
                while ($null -ne [Console]::ReadLine()) {}
            "#,
            ]);
            cmd
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut cmd = Command::new("sh");
            cmd.args([
                "-c",
                r#"
                printf '%s\n' "$FIXTURE_READY" "$FIXTURE_SNI" "$FIXTURE_SNI" >&2
                while IFS= read -r line; do :; done
            "#,
            ]);
            cmd
        };
        cmd.env(
            "FIXTURE_READY",
            json!({"ready":true,"observed_interfaces":1}).to_string(),
        );
        cmd.env(
            "FIXTURE_SNI",
            json!({"sni":{"name":"office.test","dst":"198.51.100.7"}}).to_string(),
        );
        cmd
    }

    #[tokio::test]
    async fn a_child_records_legacy_sni_and_exits_when_the_policy_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut policy) = watch::channel(Some(legacy_policy(&dir)));
        let (_stop, mut shutdown) = oneshot::channel();
        let ring = Arc::new(Mutex::new(Ring {
            recording: true,
            ..Ring::default()
        }));
        let capture_ring = ring.clone();
        let job = tokio::spawn(async move {
            session(
                &mut helper_fixture(),
                &capture_ring,
                &mut policy,
                &mut shutdown,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if ring.lock().unwrap().counters.sni == 1 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        tx.send_replace(None);
        tokio::time::timeout(Duration::from_secs(3), job)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let rows = serde_json::to_value(&ring.lock().unwrap().entries).unwrap();
        let rows: &[Value] = rows.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["rule"], 1);
        assert_eq!(rows[0]["decision"], "direct");
    }
}
