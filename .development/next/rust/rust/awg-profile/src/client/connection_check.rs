use super::*;
use std::{
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
#[cfg(target_os = "linux")]
mod probe;

const PERMANENT_WAIT: &str = "постоянный двойной туннель ожидает внешнее подключение";

fn checked(before: &Value, after: &Value, nested_verified: bool) -> bool {
    let num = |v: &Value, k: &str| v[k].as_u64().unwrap_or(0);
    let connected =
        after["connected"] == true && (after["nested_transport"] != true || nested_verified);
    after["running"] == true
        && num(after, "last_handshake") > 0
        && (connected
            || num(after, "rx_bytes") > num(before, "rx_bytes")
            || num(after, "last_handshake") > num(before, "last_handshake"))
}
fn measure(
    tunnel: &mut dyn Tunnel,
    iface: &str,
    out: &mut Value,
    required_transport_mark: Option<u64>,
    nested_verified: bool,
    data: impl FnOnce(&str) -> io::Result<IpAddr>,
) -> io::Result<()> {
    let before = tunnel.snapshot()?;
    if required_transport_mark.is_some_and(|mark| {
        before["running"] != true || before["socket_mark"].as_u64() != Some(mark)
    }) {
        return Err(invalid(PERMANENT_WAIT));
    }
    tunnel.probe()?;
    let start = Instant::now();
    let ip = data(iface);
    out["latency_ms"] = json!(start.elapsed().as_millis() as u64);
    if let Ok(address) = &ip {
        out["egress_ip"] = json!(address);
        out["data_ok"] = json!(true);
    }
    let after = tunnel.snapshot()?;
    if let Some(ep) = after["endpoint"].as_str().filter(|s| !s.is_empty()) {
        out["endpoint"] = json!(ep);
    }
    out["handshake"] = json!(checked(&before, &after, nested_verified));
    ip?;
    if out["handshake"] != true {
        return Err(invalid("HTTPS ответил, но handshake AWG не подтверждён"));
    }
    Ok(())
}
#[cfg(any(test, target_os = "linux"))]
fn trace_ip(text: &str) -> io::Result<IpAddr> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("ip="))
        .find_map(|v| v.parse().ok())
        .ok_or_else(|| invalid("HTTPS-проверка не вернула внешний IP"))
}
pub(super) fn outgoing_ip(iface: &str) -> io::Result<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        probe::run(iface, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
        Err(io::ErrorKind::Unsupported.into())
    }
}
fn cancelled(flag: &AtomicBool) -> io::Result<()> {
    if flag.load(Ordering::Acquire) {
        Err(io::ErrorKind::Interrupted.into())
    } else {
        Ok(())
    }
}
impl Runtime {
    pub fn test_profile(&self, db: &Store, id: &str, wan: &[String], cancel: &AtomicBool) -> Value {
        self.test_profile_inner(db, id, wan, cancel, None)
    }

    pub fn test_profile_with_transport(
        &self,
        db: &Store,
        id: &str,
        wan: &[String],
        cancel: &AtomicBool,
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> Value {
        self.test_profile_inner(db, id, wan, cancel, Some(&refresh))
    }

    fn test_profile_inner(
        &self,
        db: &Store,
        id: &str,
        wan: &[String],
        cancel: &AtomicBool,
        refresh: Option<&RefreshTransport<'_>>,
    ) -> Value {
        let mut out = json!({"server_id":id,"success":false,"handshake":false,"data_ok":false,"latency_ms":0,"endpoint":"","checked_at":crate::now()});
        let result = (|| {
            let mut owners = self
                .clients
                .0
                .try_lock()
                .map_err(|_| invalid("менеджер туннелей занят"))?;
            cancelled(cancel)?;
            let doc = read(db)?;
            let row = find(&doc, id)?;
            let cfg = wire(row);
            let endpoint = s(cfg, "endpoint");
            out["endpoint"] = json!(endpoint);
            if row["config"]["enabled"] != true
                || endpoint.trim().is_empty()
                || (cfg["install"] != "imported" && cfg["deployed_at"].as_u64().unwrap_or(0) == 0)
            {
                return Err(invalid(
                    "включите подключение и сохраните рабочий профиль перед проверкой",
                ));
            }
            let dev = iface(row, &doc)?;
            let data = |dev: &str| {
                cancelled(cancel)?;
                #[cfg(target_os = "linux")]
                {
                    probe::run(dev, Some(cancel))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    outgoing_ip(dev)
                }
            };
            // The local client intent applies even with a pending server config.
            let permanent = row["config"]["client"]["double_tunnel_mode"] == "permanent";
            if let Some(m) = owners.get_mut(id) {
                if m.tunnel.alive() {
                    let mark = if permanent {
                        Some(u64::from(nested_socket_selector(&m.iface)?.0))
                    } else {
                        None
                    };
                    let verified = self.nested_verified(&m.iface);
                    return measure(m.tunnel.as_mut(), &m.iface, &mut out, mark, verified, data);
                }
            }
            if permanent {
                return Err(invalid(PERMANENT_WAIT));
            }
            if row.get(super::settings::PENDING_ROUTED_MTU).is_some() && routes_use(&doc, id) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if self.present(&dev)? {
                return Err(invalid("интерфейс занят другим процессом"));
            }
            // A test may temporarily start an ordinary standby. Keep the
            // saved intent, active selection and watchdog's ownership intact.
            let mut sample = row.clone();
            for key in ["config", "applied_config"] {
                if sample[key].is_object() {
                    sample[key]["client"]["standby"] = json!(false);
                }
            }
            let inherited = refresh.map(|_| self.capture_inherited_transport(&doc, &owners, wan));
            let prepare = |proof: TransportBypassProof<'_>| {
                cancelled(cancel)?;
                if let Some(refresh) = refresh {
                    supervisor::check_recovery_row(db, row)?;
                    refresh(proof)?;
                    supervisor::check_recovery_row(db, row)?;
                }
                cancelled(cancel)
            };
            cancelled(cancel)?;
            let mut temp = self.start_temporary(
                specification(&doc, &sample)?,
                wan,
                false,
                Some(&prepare as &RefreshTransport<'_>).zip(inherited.as_ref()),
            )?;
            let measured = measure(temp.as_mut(), &dev, &mut out, None, false, data);
            let cleanup = temp.stop();
            match (measured, cleanup) {
                (Err(e), Err(c)) => Err(io::Error::other(format!(
                    "{e}. Остановка временного туннеля: {c}"
                ))),
                (r, Ok(())) => r,
                (Ok(()), Err(c)) => Err(c),
            }
        })();
        match result {
            Ok(()) => out["success"] = json!(true),
            Err(e) => out["error"] = json!(e.to_string()),
        };
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct TestTunnel {
        before: Value,
        after: Value,
        probed: bool,
    }
    impl Tunnel for TestTunnel {
        fn alive(&mut self) -> bool {
            true
        }
        fn stop(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn probe(&mut self) -> io::Result<()> {
            self.probed = true;
            Ok(())
        }
        fn snapshot(&self) -> io::Result<Value> {
            Ok(if self.probed {
                &self.after
            } else {
                &self.before
            }
            .clone())
        }
    }
    #[test]
    fn permanent_requires_the_live_own_iface_transport_mark_before_probing() {
        let mark = u64::from(nested_socket_selector("awg1").unwrap().0);
        let after = json!({"running":true,"connected":true,"last_handshake":812});
        let mut tun = TestTunnel {
            before: json!({"running":true,"socket_mark":mark + 1}),
            after,
            probed: false,
        };
        let mut out = json!({});
        let error = measure(&mut tun, "awg1", &mut out, Some(mark), false, |_| {
            panic!("a permanent tunnel with the wrong selector must not send probe traffic");
        })
        .unwrap_err();
        assert_eq!(error.to_string(), PERMANENT_WAIT);
        assert!(!tun.probed);
        tun.before["socket_mark"] = json!(mark);
        measure(&mut tun, "awg1", &mut out, Some(mark), false, |_| {
            "203.0.113.24".parse().map_err(io::Error::other)
        })
        .unwrap();
        assert!(tun.probed);
        assert_eq!(out["handshake"], true);
    }
    #[test]
    fn tests_require_saved_availability_and_applied_wire_eligibility() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let runtime = Runtime::new(dir.path(), "amneziawg-go".into());
        let endpoint = "203.0.113.24:51820";
        let config = json!({"enabled":true, "install":"imported", "endpoint":"192.0.2.7:51820"});
        let applied = json!({"enabled":true, "install":"userspace", "endpoint":endpoint});
        for (saved, wire) in [
            (
                json!({"enabled":false, "install":"imported", "endpoint":endpoint}),
                Value::Null,
            ),
            (
                json!({"enabled":true, "install":"userspace", "endpoint":endpoint}),
                Value::Null,
            ),
            (config, applied),
        ] {
            crate::edit_document(&db, |doc| {
                *doc = json!({"active_id":"draft","servers":[{
                    "id":"draft", "config":saved, "applied_config":wire
                }]});
                Ok(())
            })
            .unwrap();
            let cancel = AtomicBool::new(false);
            let result = runtime.test_profile_with_transport(&db, "draft", &[], &cancel, |_| {
                panic!("an ineligible test must stop before planning a launch");
            });
            assert_eq!(result["endpoint"], endpoint);
            assert_eq!(result["handshake"], false);
            assert_eq!(result["data_ok"], false);
            assert_eq!(result["success"], false);
            assert_eq!(result["latency_ms"], 0);
            assert!(result.get("egress_ip").is_none());
            assert_eq!(
                result["error"],
                "включите подключение и сохраните рабочий профиль перед проверкой"
            );
        }
    }
    #[test]
    fn manual_nested_handshake_uses_current_path_or_fresh_peer_evidence() {
        let before = json!({"last_handshake":812,"rx_bytes":7});
        let mut after = json!({
            "running":true,"nested_transport":true,"connected":true,"last_handshake":812,"rx_bytes":7
        });
        assert!(!checked(&before, &after, false));
        assert!(checked(&before, &after, true));
        after["rx_bytes"] = json!(8);
        assert!(checked(&before, &after, false));
        after["rx_bytes"] = json!(7);
        after["last_handshake"] = json!(813);
        assert!(checked(&before, &after, false));
        after["last_handshake"] = json!(812);
        after["nested_transport"] = json!(false);
        assert!(checked(&before, &after, false));
    }
    #[test]
    fn reports_independent_data_and_peer_evidence() {
        let mut tun = TestTunnel {
            before: json!({"rx_bytes":2}),
            after: json!({"running":true,"last_handshake":812,"rx_bytes":7,"endpoint":"127.0.0.1:1000"}),
            probed: false,
        };
        let mut out = json!({});
        measure(&mut tun, "awg1", &mut out, None, false, |dev| {
            assert_eq!(dev, "awg1");
            trace_ip("fl=abcd\nip=203.0.113.12\ntls=TLSv1.3\n")
        })
        .unwrap();
        assert_eq!(out["handshake"], true);
        assert_eq!(out["data_ok"], true);
        assert_eq!(out["egress_ip"], "203.0.113.12");
        tun.probed = false;
        tun.after["last_handshake"] = json!(0);
        assert!(
            measure(&mut tun, "awg1", &mut out, None, false, |_| trace_ip(
                "ip=::1"
            ))
            .is_err()
        );
        assert_eq!(out["handshake"], false);
        assert!(trace_ip("ip=invalid").is_err());
    }
}
