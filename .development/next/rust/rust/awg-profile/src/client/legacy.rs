use super::*;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
mod takeover;
#[cfg(target_os = "linux")]
pub(super) use takeover::{process_start, start_time, SignalTarget};

#[derive(Default)]
pub(super) struct Pending {
    rows: BTreeMap<String, PendingRow>,
    checked: Option<Instant>,
    awaiting_confirmation: bool,
}
impl Pending {
    fn interval(&self) -> Duration {
        Duration::from_secs(if self.awaiting_confirmation { 5 } else { 30 })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PendingRow {
    iface: String,
    message: String,
    identity: Option<[u8; 32]>,
}
pub(super) enum Presence {
    Vacant,
    #[cfg(any(target_os = "linux", test))]
    Matching([u8; 32]),
    Occupied,
}

fn wanted(row: &Value) -> bool {
    let client = &row["config"]["client"];
    row["config"]["enabled"] == true
        && client["enabled"] == true
        && client.get("rust_managed").is_none()
        && !super::settings::has_saved_edit(row)
}

#[cfg(any(target_os = "linux", test))]
fn another_panel(proc_root: &std::path::Path, own: u32) -> io::Result<bool> {
    for entry in std::fs::read_dir(proc_root)? {
        let entry = entry?;
        let pid = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<u32>().ok());
        if !pid.is_some_and(|pid| pid != own) {
            continue;
        }
        let exe = match std::fs::read_link(entry.path().join("exe")) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
            if matches!(
                name.trim_end_matches(" (deleted)"),
                "n2s" | "nfqws2-strategy"
            ) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(any(unix, test))]
fn identity(private: [u8; 32], public: [u8; 32]) -> [u8; 32] {
    use curve25519_dalek::scalar::clamp_integer;
    Sha256::new()
        .chain_update(clamp_integer(private))
        .chain_update(public)
        .finalize()
        .into()
}

#[cfg(any(unix, test))]
pub(super) fn reported_identity(response: &[u8]) -> Option<[u8; 32]> {
    let text = std::str::from_utf8(response).ok()?;
    let key = |field: &str| {
        let mut lines = text.lines().filter_map(|v| v.strip_prefix(field));
        let raw = lines.next()?;
        if lines.next().is_some() || raw.len() != 64 || !raw.is_ascii() {
            return None;
        }
        let mut actual = [0u8; 32];
        for (i, byte) in actual.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).ok()?;
        }
        (actual != [0; 32]).then_some(actual)
    };
    Some(identity(key("private_key=")?, key("public_key=")?))
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn matching_peer(spec: &Spec, response: &[u8]) -> Option<[u8; 32]> {
    let expected = expected_identity(spec)?;
    let mut status = json!({});
    (crate::runtime::uapi(response, crate::now(), &mut status).is_ok()
        && status["running"] == true
        && reported_identity(response) == Some(expected))
    .then_some(expected)
}

#[cfg(any(target_os = "linux", test))]
fn expected_identity(spec: &Spec) -> Option<[u8; 32]> {
    let key =
        |name: &str| conf::key(spec.conf.lines().find_map(|l| l.strip_prefix(name))?, false).ok();
    Some(identity(key("PrivateKey = ")?, key("PublicKey = ")?))
}

impl Runtime {
    pub(super) fn adopt_legacy_edit(
        &self,
        db: &Store,
        spec: &Spec,
    ) -> io::Result<Option<Box<dyn Tunnel>>> {
        #[cfg(target_os = "linux")]
        if let Presence::Matching(proof) = self.legacy_presence(spec)? {
            return Ok(takeover::confirmed(self, db, spec, proof));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (db, spec);
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn replay_legacy_edit(
        &self,
        db: &Store,
        before: &Spec,
        legacy: &super::settings::RoutedLegacyPredecessor,
    ) -> io::Result<Option<Managed>> {
        let Some(tunnel) = takeover::replay(self, db, before, legacy.receipt_sha256)? else {
            return Ok(None);
        };
        Ok(Some(Managed {
            tunnel,
            iface: before.iface.clone(),
            fingerprint: Sha256::digest(before.conf.as_bytes()).into(),
            recovery: Default::default(),
        }))
    }

    pub(super) fn legacy_due(&self) -> bool {
        self.clients.1.try_lock().is_ok_and(|p| {
            !p.rows.is_empty() && p.checked.is_none_or(|time| time.elapsed() >= p.interval())
        })
    }

    pub(super) fn legacy_status(&self, id: &str) -> Option<String> {
        Some(
            self.clients
                .1
                .try_lock()
                .ok()?
                .rows
                .get(id)?
                .message
                .clone(),
        )
    }

    #[cfg(any(unix, test))]
    pub(super) fn legacy_activity(&self, iface: &str, live: &mut Value, response: &[u8]) -> bool {
        let Ok(pending) = self.clients.1.lock() else {
            return false;
        };
        if let Some(row) = pending.rows.values().find(|r| r.iface == iface) {
            if row.identity.is_some() && reported_identity(response) == row.identity {
                return true;
            }
            live["connected"] = json!(false);
            live["running"] = json!(false);
            live["status_unavailable"] = json!(true);
            live["error"] = json!("идентичность сохранённого пира не подтверждена");
            for field in ["last_handshake", "rx_bytes", "tx_bytes"] {
                live[field] = json!(0);
            }
            live["endpoint"] = json!("");
        }
        false
    }

    pub(super) fn legacy_presence(&self, spec: &Spec) -> io::Result<Presence> {
        if !self.present(&spec.iface)? {
            return Ok(Presence::Vacant);
        }
        #[cfg(target_os = "linux")]
        {
            use std::{
                fs,
                os::unix::fs::{FileTypeExt, MetadataExt},
            };
            let path = self
                .root
                .join("var/run/amneziawg")
                .join(format!("{}.sock", spec.iface));
            // The original daemon inherits its listener from a process that
            // then exits. SO_PEERCRED alone cannot identify its current owner.
            let socket = fs::symlink_metadata(&path)
                .is_ok_and(|m| m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() });
            if socket && self.root.join("sys/class/net").join(&spec.iface).exists() {
                let bytes =
                    crate::runtime::request(&path, b"get=1\n\n", Duration::from_millis(350), None)?;
                if let Some(identity) = matching_peer(spec, &bytes) {
                    return Ok(Presence::Matching(identity));
                }
            }
        }
        Ok(Presence::Occupied)
    }

    pub(super) fn restore_legacy(
        &self,
        db: &Store,
        doc: &Value,
        initial: bool,
        mut inspect: impl FnMut(&Spec) -> io::Result<Presence>,
        mut start: impl FnMut(Spec) -> io::Result<Box<dyn Tunnel>>,
        events: &mut Vec<String>,
    ) -> io::Result<()> {
        let lock = || {
            self.clients
                .1
                .lock()
                .map_err(|_| io::Error::other("состояние переноса AWG недоступно"))
        };
        let previous = {
            let mut p = lock()?;
            if !initial && p.checked.is_some_and(|t| t.elapsed() < p.interval()) {
                return Ok(());
            }
            p.checked = Some(Instant::now());
            #[cfg(target_os = "linux")]
            {
                p.awaiting_confirmation = takeover::trial_in_progress(db);
            }
            p.rows.clone()
        };
        let mut pending = BTreeMap::new();
        #[cfg(target_os = "linux")]
        let mut other_panel = None;
        let rows = doc["servers"]
            .as_array()
            .ok_or_else(|| invalid("нет списка подключений AWG"))?;
        let mut counts = HashMap::new();
        for name in rows.iter().filter_map(|r| iface(r, doc).ok()) {
            *counts.entry(name).or_insert(0usize) += 1;
        }
        for row in rows {
            let id = s(row, "id");
            if !initial && !previous.contains_key(id) {
                continue;
            }
            if !wanted(row) {
                #[cfg(target_os = "linux")]
                if self.root == std::path::Path::new("/")
                    && (row["config"]["enabled"] == false
                        || row["config"]["client"]["enabled"] == false)
                {
                    let retire = || {
                        let mut owned = self
                            .clients
                            .0
                            .lock()
                            .map_err(|_| invalid("менеджер туннелей недоступен"))?;
                        let current = read(db)?;
                        if find(&current, id)? != row {
                            return Ok(());
                        }
                        if routes_use(&current, id) {
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        if let Some(tunnel) = owned.get_mut(id).filter(|m| m.tunnel.inherited()) {
                            tunnel.tunnel.stop()?;
                            owned.remove(id);
                            return Ok(());
                        }
                        takeover::retire_disabled(self, db, &current, row)
                    };
                    if let Err(error) = retire() {
                        let failure = PendingRow {
                            iface: iface(row, doc).unwrap_or_default(),
                            identity: None,
                            message: error.to_string(),
                        };
                        if previous.get(id) != Some(&failure) {
                            events.push(format!("{id}: {}", failure.message));
                        }
                        pending.insert(id.to_owned(), failure);
                    }
                }
                continue;
            }
            #[allow(unused_mut)]
            let mut identity = None;
            let result = (|| {
                let spec = specification(doc, row)?;
                if counts.get(&spec.iface) != Some(&1) {
                    return Err(invalid("несколько профилей назначены одному интерфейсу"));
                }
                match inspect(&spec)? {
                    #[cfg(any(target_os = "linux", test))]
                    Presence::Matching(proof) => {
                        identity = Some(proof);
                        #[cfg(target_os = "linux")]
                        if let Some(tunnel) = takeover::confirmed(self, db, &spec, proof) {
                            let mut owned = self
                                .clients
                                .0
                                .lock()
                                .map_err(|_| invalid("менеджер туннелей недоступен"))?;
                            if find(&read(db)?, id)? == row {
                                owned.entry(id.to_owned()).or_insert_with(|| {
                                    let recovery = supervisor::Recovery::from_inherited(
                                        tunnel.as_ref(),
                                        row,
                                        doc,
                                    );
                                    Managed {
                                        iface: spec.iface.clone(),
                                        fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                                        recovery,
                                        tunnel,
                                    }
                                });
                                return Ok(None);
                            }
                        }
                        Err(invalid("сохранённый пир работает под прежним управлением, ожидается освобождение интерфейса"))
                    }
                    Presence::Occupied => Err(invalid(
                        "интерфейс занят, идентичность сохранённого пира не подтверждена",
                    )),
                    Presence::Vacant => {
                        #[cfg(target_os = "linux")]
                        if self.root == std::path::Path::new("/") {
                            let competing = match other_panel {
                                Some(v) => v,
                                None => {
                                    let v =
                                        another_panel(&self.root.join("proc"), std::process::id())?;
                                    other_panel = Some(v);
                                    v
                                }
                            };
                            if competing {
                                return Err(invalid(
                                    "другая панель n2s уже работает, перенос отложен",
                                ));
                            }
                            takeover::retire_vacant(self, db, &spec)?;
                        }
                        let mut launch_failed = false;
                        let result = self
                            .clients
                            .up_profile(db, Some(id), false, Some(row), |s| {
                                let result = start(s);
                                launch_failed = result.is_err();
                                result
                            });
                        let Err(reason) = result else { return Ok(None) };
                        // A collision that appeared during startup stays external.
                        if !launch_failed || !matches!(inspect(&spec)?, Presence::Vacant) {
                            return Err(reason);
                        }
                        self.arm_retry(spec, &reason, || set_enabled(db, id, row, true, None))?;
                        Ok(Some(reason))
                    }
                }
            })();
            if let Err(e) = result {
                let failure = PendingRow {
                    iface: iface(row, doc).unwrap_or_default(),
                    identity,
                    message: e.to_string(),
                };
                if previous.get(id) != Some(&failure) {
                    events.push(format!("{id}: {}", failure.message));
                }
                pending.insert(id.to_owned(), failure);
            } else if let Ok(Some(reason)) = result {
                events.push(format!(
                    "{id}: запуск отложен, повтор по настройкам восстановления: {reason}"
                ));
            } else if !initial {
                events.push(format!("{id}: восстановлено сохранённое подключение"));
            }
        }
        lock()?.rows = pending;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_ignores_its_own_pid_and_defers_to_an_installed_panel() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        for name in ["self", "12", "98"] {
            fs::create_dir(dir.path().join(name)).unwrap();
        }
        fs::write(dir.path().join("12/exe"), "own").unwrap();
        assert!(!another_panel(dir.path(), 12).unwrap());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/opt/usr/bin/n2s (deleted)", dir.path().join("98/exe"))
                .unwrap();
            assert!(another_panel(dir.path(), 12).unwrap());
        }
    }

    fn profile(id: &str, name: &str, enabled: bool, standby: bool) -> Value {
        let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
        cfg["enabled"] = json!(true);
        cfg["client_iface"] = json!(name);
        cfg["client"]["enabled"] = json!(enabled);
        cfg["client"]["standby"] = json!(standby);
        json!({"id":id,"config":cfg})
    }

    #[test]
    fn migration_preserves_disabled_profiles_reserves_and_unverified_interfaces() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("engine"));
        let mut primary = profile("primary", "awg0", true, false);
        primary["config"]["client"]["fallback_tunnel_ids"] = json!(["reserve"]);
        primary["applied_config"] = primary["config"].clone();
        primary["applied_config"]["client_iface"] = json!("awg99");
        primary["applied_config"]["enabled"] = json!(false);
        let mut disabled_server = profile("disabled", "awg5", true, false);
        disabled_server["config"]["enabled"] = json!(false);
        edit_document(&db, |doc| {
            doc["servers"] = json!([
                primary,
                profile("reserve", "awg1", true, true),
                profile("stopped", "awg2", false, false),
                profile("foreign", "awg3", true, false),
                profile("another", "awg4", true, false),
                disabled_server
            ]);
            doc["active_id"] = json!("stopped");
            Ok(())
        })
        .unwrap();
        let before = read(&db).unwrap();
        let mut started = vec![];
        let probe = format!(
            "private_key={}\npublic_key={}\n",
            "01".repeat(32),
            "02".repeat(32)
        );
        let mut events = vec![];
        runtime
            .restore_legacy(
                &db,
                &before,
                true,
                |spec| {
                    Ok(match spec.id.as_str() {
                        "primary" => {
                            assert_eq!(spec.iface, "awg0");
                            Presence::Matching(reported_identity(probe.as_bytes()).unwrap())
                        }
                        "reserve" | "another" => Presence::Vacant,
                        "foreign" => Presence::Occupied,
                        _ => panic!("disabled client inspected"),
                    })
                },
                |spec| {
                    started.push(spec.id);
                    Ok(Box::new(supervisor::Stopped))
                },
                &mut events,
            )
            .unwrap();
        assert_eq!(started, ["another"]);
        let migrated = read(&db).unwrap();
        assert_eq!(migrated["active_id"], "stopped");
        for id in ["primary", "stopped", "disabled", "foreign"] {
            assert!(find(&migrated, id).unwrap() == find(&before, id).unwrap());
        }
        for id in ["reserve", "another"] {
            assert_eq!(
                find(&migrated, id).unwrap()["config"]["client"]["rust_managed"],
                true
            );
        }
        assert_eq!(events.len(), 2);
        let mut live = json!({"running":true,"connected":true,"rx_bytes":33});
        runtime.legacy_activity("awg3", &mut live, probe.as_bytes());
        assert_eq!(live["running"], false);
        assert_eq!(live["rx_bytes"], 0);
        let mut live = json!({"connected":true});
        runtime.legacy_activity("awg0", &mut live, probe.as_bytes());
        assert_eq!(live["connected"], true);
        runtime.legacy_activity("awg0", &mut live, b"public_key=changed\n");
        assert_eq!(live["connected"], false);
        // The data file can change while a legacy tunnel is still running.
        edit_document(&db, |d| {
            d["servers"][3]["config"]["client"]["enabled"] = json!(false);
            Ok(())
        })
        .unwrap();
        runtime.clients.1.lock().unwrap().checked = None;
        runtime
            .restore_legacy(
                &db,
                &read(&db).unwrap(),
                false,
                |_| Ok(Presence::Vacant),
                |spec| {
                    started.push(spec.id);
                    Ok(Box::new(supervisor::Stopped))
                },
                &mut events,
            )
            .unwrap();
        assert_eq!(started, ["another", "primary"]);
        assert!(runtime.clients.1.lock().unwrap().rows.is_empty());
        let finished = read(&db).unwrap();
        assert_eq!(
            find(&finished, "primary").unwrap()["config"]["client"]["rust_managed"],
            true
        );
        assert_eq!(
            find(&finished, "primary").unwrap()["config"]["client"]["fallback_tunnel_ids"],
            json!(["reserve"])
        );
        assert_eq!(
            find(&finished, "foreign").unwrap()["config"]["client"]["enabled"],
            false
        );
        assert!(find(&finished, "foreign").unwrap()["config"]["client"]
            .get("rust_managed")
            .is_none());
    }

    #[test]
    fn duplicate_assignment_and_racing_user_stop_never_start_an_engine() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("engine"));
        edit_document(&db, |doc| {
            doc["servers"] = json!([
                profile("a", "awg0", true, false),
                profile("b", "awg0", true, true),
                profile("c", "awg1", true, false)
            ]);
            Ok(())
        })
        .unwrap();
        let mut events = vec![];
        runtime
            .restore_legacy(
                &db,
                &read(&db).unwrap(),
                true,
                |spec| {
                    assert_eq!(spec.id, "c");
                    edit_document(&db, |doc| {
                        doc["servers"][2]["config"]["client"]["enabled"] = json!(false);
                        Ok(())
                    })?;
                    Ok(Presence::Vacant)
                },
                |_| panic!("ambiguous or cancelled restore"),
                &mut events,
            )
            .unwrap();
        assert_eq!(events.len(), 3);
        for row in read(&db).unwrap()["servers"].as_array().unwrap() {
            assert!(row["config"]["client"].get("rust_managed").is_none());
        }
    }

    #[test]
    fn startup_failure_arms_failover_only_if_the_interface_is_still_vacant() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("engine"));
        let mut primary = profile("a", "awg0", true, false);
        primary["config"]["client"]["fallback_tunnel_ids"] = json!(["b"]);
        edit_document(&db, |d| {
            d["servers"] = json!([
                primary,
                profile("b", "awg1", true, true),
                profile("c", "awg2", true, false)
            ]);
            Ok(())
        })
        .unwrap();
        let mut checked_c = false;
        runtime
            .restore_legacy(
                &db,
                &read(&db).unwrap(),
                true,
                |spec| {
                    let collision = spec.id == "c" && checked_c;
                    checked_c |= spec.id == "c";
                    Ok(if collision {
                        Presence::Occupied
                    } else {
                        Presence::Vacant
                    })
                },
                |_| Err(io::Error::other("WAN недоступен")),
                &mut vec![],
            )
            .unwrap();
        let doc = read(&db).unwrap();
        assert_eq!(
            find(&doc, "a").unwrap()["config"]["client"]["rust_managed"],
            true
        );
        assert!(find(&doc, "c").unwrap()["config"]["client"]
            .get("rust_managed")
            .is_none());
        let mut owned = runtime.clients.0.lock().unwrap();
        assert!(!owned.contains_key("c") && !owned["a"].recovery.authenticated(crate::now()));
        failover::reconcile(
            &doc,
            &mut owned,
            crate::now() + 30,
            &crate::recovery_settings(&Value::Null),
            &mut vec![],
            None,
            |s| {
                assert_eq!(s.id, "b");
                Ok(Box::new(supervisor::Stopped))
            },
        )
        .unwrap();
        assert!(owned.contains_key("b"));
    }

    #[test]
    fn status_requires_exact_local_and_remote_keys_and_a_complete_single_peer_reply() {
        let row = profile("a", "awg0", true, false);
        let spec = specification(&json!({"servers":[row]}), &row).unwrap();
        let msg = uapi_message(&spec.conf, "192.0.2.28:5123".parse().unwrap()).unwrap();
        let private = msg.lines().find(|s| s.starts_with("private_key=")).unwrap();
        let public = msg.lines().find(|s| s.starts_with("public_key=")).unwrap();
        let resp = format!("{private}\n{public}\nendpoint=192.0.2.28:5123\nerrno=0\n\n");
        assert!(matching_peer(&spec, resp.as_bytes()).is_some());
        for other in [
            resp.replace(private, "private_key=bad"),
            resp.replace(public, "public_key=bad"),
            resp.replace("errno=0", "errno=1"),
            resp.replace(private, &format!("{private}\n{private}")),
            resp.replace(public, &format!("{public}\n{public}")),
        ] {
            assert!(matching_peer(&spec, other.as_bytes()).is_none());
        }
    }
}
