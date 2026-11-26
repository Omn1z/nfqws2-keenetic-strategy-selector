use super::{eligible, remote_apply, render, Runtime};
use crate::{active, edit_document, invalid, peers, remote, s, PeerInput};
use nfqws2_store::Store;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;

#[derive(Serialize)]
enum Change {
    Add(Box<PeerInput>),
    Remove(String),
}
impl Change {
    fn edit(self, cfg: &mut Value) -> io::Result<Value> {
        match self {
            Self::Add(input) => {
                let router = input.is_router;
                peers::append(cfg, *input, router)
            }
            Self::Remove(id) => {
                peers::discard(cfg, &id)?;
                Ok(json!({"id":id}))
            }
        }
    }
}

struct Pending {
    server: String,
    request: String,
    config: Value,
    text: String,
    previous: [u8; 32],
}

// If confirmation was lost, the generated key material remains in the desired
// profile. Only the requested peer is copied into the confirmed configuration.
fn resume(row: &Value, id: &str, add: bool) -> io::Result<(Value, Value)> {
    let cfg = &row["config"];
    let mut target = row["applied_config"].clone();
    eligible(&target)?;
    if !super::userspace::deployed(&target)
        || super::userspace::tool(&target) != super::userspace::tool(cfg)
        || ["interface", "public_key"]
            .iter()
            .any(|k| target[*k] != cfg[*k])
        || ["host", "port", "known_key"]
            .iter()
            .any(|k| target["conn"][*k] != cfg["conn"][*k])
    {
        return Err(invalid(
            "удалённый сервер изменился после начала синхронизации пиров",
        ));
    }
    target["conn"] = cfg["conn"].clone();
    let peer = if add {
        let peer = cfg["peers"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["id"] == id))
            .ok_or_else(|| invalid("сохранённый пир не найден"))?;
        target["peers"]
            .as_array_mut()
            .ok_or_else(|| invalid("нет списка применённых пиров"))?
            .push(peer.clone());
        if peer["is_router"] == true {
            target["client"]["peer_id"] = json!(id);
        }
        peers::redacted(peer.clone())
    } else {
        peers::discard(&mut target, id)?;
        json!({"id":id})
    };
    Ok((peer, target))
}

fn change(
    db: &Store,
    op: Change,
    apply: impl FnOnce(&Value, &str, &[u8; 32]) -> io::Result<()>,
) -> io::Result<(Value, io::Result<()>)> {
    use base64ct::{Base64, Encoding};
    let (peer, pending) = edit_document(db, |doc| {
        let server = s(active(doc)?, "id").to_owned();
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == server)
            .unwrap();
        if row["config"]["install"] == "imported" {
            return Err(invalid(
                "импортированный профиль не управляет удалённым сервером",
            ));
        }
        let waiting = row["applied_config"].is_object();
        if !waiting && row["config"]["deployed_at"].as_u64().unwrap_or(0) == 0 {
            return Ok((op.edit(&mut row["config"])?, None));
        }
        eligible(&row["config"])?;
        remote::validate(&row["config"])?;
        if !super::userspace::deployed(&row["config"]) {
            return Err(invalid(
                "для синхронизации нужен развёрнутый управляемый VPN-сервер",
            ));
        }
        let request = Base64::encode_string(&Sha256::digest(serde_json::to_vec(&op)?));
        let (peer, config) = if waiting {
            if row["native_peer_change"]["request"] != request {
                return Err(invalid(
                    "сначала завершите развёртывание или повторите сохранённое изменение пира",
                ));
            }
            resume(
                row,
                s(&row["native_peer_change"], "peer_id"),
                matches!(op, Change::Add(_)),
            )?
        } else {
            let before = row["config"].clone();
            let peer = op.edit(&mut row["config"])?;
            row["applied_config"] = before;
            row["native_peer_change"] = json!({"request":request,"peer_id":peer["id"]});
            (peer, row["config"].clone())
        };
        let text = render(&config)?;
        let previous = Sha256::digest(render(&row["applied_config"])?).into();
        Ok((
            peer,
            Some(Pending {
                server,
                request,
                config,
                text,
                previous,
            }),
        ))
    })?;
    let Some(pending) = pending else {
        return Ok((peer, Ok(())));
    };
    let confirm = apply(&pending.config, &pending.text, &pending.previous)
        .and_then(|_| {
            edit_document(db, |doc| {
                let row = doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r["id"] == pending.server)
                    .ok_or_else(|| invalid("профиль удалён во время синхронизации пиров"))?;
                if row["native_peer_change"]["request"] != pending.request {
                    return Err(invalid("подтверждаемая операция с пиром изменилась"));
                }
                let fields = row.as_object_mut().unwrap();
                fields.remove("native_peer_change");
                if fields["config"] == pending.config {
                    fields.remove("applied_config");
                } else {
                    fields.insert("applied_config".into(), pending.config);
                }
                Ok(())
            })
        })
        .map_err(|err| {
            io::Error::other(format!(
                "изменение пира сохранено, применение не подтверждено: {err}"
            ))
        });
    Ok((peer, confirm))
}
impl Runtime {
    fn change_peer(&self, db: &Store, op: Change) -> io::Result<(Value, io::Result<()>)> {
        let _guard = self.deployment_guard()?;
        change(db, op, |cfg, text, previous| {
            if self.root != std::path::Path::new("/") {
                return Err(invalid("SSH доступен только из рабочей системы роутера"));
            }
            let tool = super::userspace::sync_tool(cfg)?;
            remote_apply(cfg, text, Some(previous), tool, true)?.result()
        })
    }
    pub fn add_profile_peer(&self, db: &Store, input: PeerInput) -> Value {
        match self.change_peer(db, Change::Add(Box::new(input))) {
            Ok((peer, Ok(()))) => json!({"ok":true,"peer":peer}),
            Ok((peer, Err(e))) => json!({"ok":false,"peer":peer,"error":e.to_string()}),
            Err(e) => json!({"ok":false,"peer":{},"error":e.to_string()}),
        }
    }
    pub fn remove_profile_peer(&self, db: &Store, id: String) -> io::Result<()> {
        self.change_peer(db, Change::Remove(id))?.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read;
    use base64ct::{Base64, Encoding};
    fn fixture() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        edit_document(&db, |doc| {
            let cfg = &mut doc["servers"][0]["config"];
            cfg["protocol"] = json!("wireguard");
            cfg["conn"]["host"] = json!("managed.test");
            cfg["conn"]["known_key"] =
                json!(format!("ssh-ed25519 {}", Base64::encode_string(&[5; 32])));
            Ok(())
        })
        .unwrap();
        super::super::run(&db, None, |_, _, _, _| Ok(super::super::Backend::WireGuard)).unwrap();
        (dir, db)
    }
    fn add(name: &str) -> Change {
        Change::Add(Box::new(PeerInput {
            name: name.into(),
            ..Default::default()
        }))
    }

    #[test]
    fn deployed_go_awg_peer_sync_verifies_the_original_remote_file_hash() {
        let (_dir, db) = fixture();
        edit_document(&db, |doc| {
            let c = &mut doc["servers"][0]["config"];
            c["protocol"] = "awg".into();
            c["wan_iface"] = "ens3".into();
            c["traffic_obfuscation"] = true.into();
            c.as_object_mut().unwrap().remove("native_vpn_tool");
            c.as_object_mut().unwrap().remove("native_vpn_method");
            Ok(())
        })
        .unwrap();
        let before = read(&db).unwrap()["servers"][0]["config"].clone();
        let previous = Sha256::digest(render(&before).unwrap().as_bytes());
        let (_, result) = change(&db, add("phone"), |cfg, text, old| {
            assert_eq!(old.as_slice(), previous.as_slice());
            assert_eq!(super::super::userspace::tool(cfg), "awg");
            assert!(text.starts_with("[Interface]\n") && text.matches("[Peer]\n").count() == 2);
            Ok(())
        })
        .unwrap();
        result.unwrap();
    }
    #[test]
    fn unconfirmed_peer_reuses_identity_and_retains_previous_applied_snapshot_across_restart() {
        let (dir, db) = fixture();
        let before = read(&db).unwrap()["servers"][0]["config"].clone();
        let (peer, ack) = change(&db, add("tablet"), |_, _, _| {
            Err(io::Error::other("timeout"))
        })
        .unwrap();
        assert!(ack.is_err());
        assert_eq!(peer["private_key"], "");
        assert_eq!(peer["psk"], "");
        let id = s(&peer, "id").to_owned();
        let row = read(&db).unwrap()["servers"][0].clone();
        assert_eq!(row["applied_config"], before);
        let stored = row["config"]["peers"][1].clone();
        assert_ne!(stored["private_key"], "");
        assert_ne!(stored["psk"], "");
        drop(db);
        let db = Store::open(dir.path()).unwrap();
        assert!(change(&db, add("other"), |_, _, _| panic!("unrelated request")).is_err());
        let (retried, ack) = change(&db, add("tablet"), |cfg, text, previous| {
            assert_eq!(
                previous.as_slice(),
                Sha256::digest(render(&before).unwrap()).as_slice()
            );
            assert_eq!(cfg["peers"][1], stored);
            assert!(!text.contains(s(&stored, "private_key")));
            assert!(text.contains(s(&stored, "public_key")));
            Ok(())
        })
        .unwrap();
        ack.unwrap();
        assert_eq!(retried, peer);
        let row = read(&db).unwrap()["servers"][0].clone();
        assert!(row["applied_config"].is_null());
        assert!(row["native_peer_change"].is_null());
        assert_eq!(row["config"]["peers"].as_array().unwrap().len(), 2);
        assert!(change(&db, Change::Remove(id.clone()), |_, _, _| Err(
            io::Error::other("lost confirmation")
        ))
        .unwrap()
        .1
        .is_err());
        assert_eq!(
            read(&db).unwrap()["servers"][0]["applied_config"]["peers"][1],
            stored
        );
        change(&db, Change::Remove(id), |cfg, _, _| {
            assert_eq!(cfg["peers"].as_array().unwrap().len(), 1);
            Ok(())
        })
        .unwrap()
        .1
        .unwrap();
        let row = read(&db).unwrap()["servers"][0].clone();
        assert_eq!(row["config"]["peers"], before["peers"]);
        assert!(row["applied_config"].is_null());
    }
    #[test]
    fn guards_target_identity_pending_settings_and_concurrent_changes() {
        let (_dir, db) = fixture();
        let before = read(&db).unwrap()["servers"][0].clone();
        for (field, bad) in [
            ("install", json!("imported")),
            ("native_vpn_tool", json!("unknown")),
            ("conn", json!({"known_key":""})),
            ("protocol", json!("awg")),
        ] {
            edit_document(&db, |doc| {
                let row = &mut doc["servers"][0];
                *row = before.clone();
                row["config"][field] = bad;
                row["config"]["traffic_obfuscation"] = json!(true);
                Ok(())
            })
            .unwrap();
            assert!(change(&db, add("blocked"), |_, _, _| panic!("foreign profile")).is_err());
        }
        edit_document(&db, |doc| {
            doc["servers"][0] = before;
            Ok(())
        })
        .unwrap();
        let (_, ack) = change(&db, add("laptop"), |_, _, _| {
            edit_document(&db, |doc| {
                doc["servers"][0]["config"]["mtu"] = json!(1300);
                Ok(())
            })
        })
        .unwrap();
        ack.unwrap();
        let row = read(&db).unwrap()["servers"][0].clone();
        assert_eq!(row["config"]["mtu"], 1300);
        assert_eq!(row["applied_config"]["mtu"], 1420);
        assert_eq!(row["config"]["peers"], row["applied_config"]["peers"]);
        assert!(change(&db, add("other"), |_, _, _| panic!(
            "unrelated pending settings"
        ))
        .is_err());
    }
}
