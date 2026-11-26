use super::Deployment;
use crate::s;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Mutex};

const LIMIT: usize = 32;

#[derive(PartialEq, Eq)]
pub(super) struct Target {
    id: [u8; 32],
    destination: [u8; 32],
}

impl Target {
    pub(super) fn new(id: &str, cfg: &Value) -> Self {
        let conn = &cfg["conn"];
        let mut hash = Sha256::new();
        for part in [
            s(conn, "host"),
            s(conn, "user"),
            s(conn, "known_key"),
            s(cfg, "interface"),
            s(cfg, "public_key"),
            s(cfg, "install"),
            s(cfg, "protocol"),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(conn["port"].as_u64().unwrap_or(22).to_le_bytes());
        hash.update([u8::from(cfg["traffic_obfuscation"] != false)]);
        Self {
            id: Sha256::digest(id).into(),
            destination: hash.finalize().into(),
        }
    }
}

// Only Deployment's validated and bounded public fields enter the cache.
#[derive(Default)]
pub(crate) struct History(Mutex<VecDeque<(Target, Value)>>);

impl History {
    pub(super) fn record(&self, target: Target, report: &Deployment) {
        let mut latest = self.0.lock().unwrap_or_else(|err| err.into_inner());
        latest.retain(|(old, _)| old.id != target.id);
        if latest.len() == LIMIT {
            latest.pop_front();
        }
        latest.push_back((target, report.response()["result"].take()));
    }

    pub(crate) fn status(&self, row: &Value) -> Option<Value> {
        let latest = self.0.lock().ok()?;
        if latest.is_empty() {
            return None;
        }
        let target = Target::new(s(row, "id"), &row["config"]);
        Some(latest.iter().find(|(old, _)| *old == target)?.1.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Remote;
    use super::*;
    use crate::{edit_document, read, runtime::Runtime, status};
    use nfqws2_store::Store;
    use serde_json::json;
    use std::io;

    #[test]
    fn polling_returns_last_attempt_for_the_same_server_without_private_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
        edit_document(&db, |doc| {
            let cfg = &mut doc["servers"][0]["config"];
            cfg["protocol"] = json!("wireguard");
            cfg["install"] = json!("userspace");
            cfg["wan_iface"] = json!("ens3");
            cfg["conn"]["host"] = json!("vpn.example.test");
            cfg["conn"]["known_key"] = json!("test-pin");
            cfg["conn"]["password"] = json!("private-test-credential");
            Ok(())
        })
        .unwrap();
        assert!(status(&db, &runtime).unwrap()["last_deploy"].is_null());
        // A temporary root rejects the attempt before starting any SSH process.
        assert_eq!(runtime.deploy_profile(&db, None, &[])["ok"], false);
        let last = &status(&db, &runtime).unwrap()["last_deploy"];
        assert_eq!(last["ok"], false);
        assert_eq!(last["steps"][1]["ok"], false);
        assert_eq!(last["wan_iface"], "ens3");
        let row = &read(&db).unwrap()["servers"][0];
        let target = || Target::new(s(row, "id"), &row["config"]);
        let mut report = Deployment::new(super::super::Backend::Userspace);
        report.wan(&row["config"]);
        report
            .apply(Remote::parse("ok verify 1").unwrap(), &row["config"])
            .unwrap();
        report.finish(Ok(Some(io::Error::other("private-test-credential"))));
        runtime.deploy_history.record(target(), &report);
        let last = &status(&db, &runtime).unwrap()["last_deploy"];
        assert_eq!(*last, report.response()["result"]);
        assert_eq!(last["ok"], true);
        assert_eq!(last["listening"], true);
        assert_eq!(last["handshake"], true);
        assert_eq!(last["steps"][5]["ok"], false);
        assert!(!last.to_string().contains("private-test-credential"));
        for (path, replacement) in [
            ("/id", json!("another")),
            ("/config/conn/host", json!("replacement.test")),
            ("/config/conn/port", json!(2222)),
            ("/config/conn/known_key", json!("changed")),
            ("/config/interface", json!("wg9")),
            ("/config/public_key", json!("other")),
        ] {
            let mut other = row.clone();
            *other.pointer_mut(path).unwrap() = replacement;
            assert!(runtime.deploy_history.status(&other).is_none(), "{path}");
        }
        assert!(Runtime::new(dir.path(), dir.path().join("no-engine"))
            .deploy_history
            .status(row)
            .is_none());
    }

    #[test]
    fn cache_replaces_a_profile_and_evicts_the_oldest_attempt() {
        let history = History::default();
        let row = |i: usize| json!({"id":i.to_string(),"config":{"interface":"wg0"}});
        let record = |r: &Value| {
            let mut report = Deployment::new(super::super::Backend::WireGuard);
            report
                .apply(Remote::parse("ok verify 0").unwrap(), &r["config"])
                .unwrap();
            report.finish(Ok(None));
            history.record(Target::new(s(r, "id"), &r["config"]), &report);
        };
        for i in 0..LIMIT {
            record(&row(i));
        }
        let mut changed = row(0);
        changed["config"]["interface"] = json!("wg1");
        record(&changed);
        record(&row(LIMIT));
        assert!(history.status(&row(0)).is_none());
        assert!(history.status(&row(1)).is_none());
        assert!(history.status(&changed).is_some());
        assert!(history.status(&row(LIMIT)).is_some());
        assert_eq!(history.0.lock().unwrap().len(), LIMIT);
    }
}
