//! Exact UDP exclusions from verified active AWG transports.
#[cfg(target_os = "linux")]
use super::s;
use super::SocketAddr;
#[cfg(any(target_os = "linux", test))]
use super::{conf, endpoint_index, live_transport_endpoint};
use super::{Managed, Value};
use crate::runtime::Runtime;
use nfqws2_store::Store;
use std::collections::HashMap;
use std::io;

#[cfg(any(target_os = "linux", test))]
fn named_port(endpoint: &str) -> Option<u16> {
    let (host, port) = conf::endpoint(endpoint).ok()?;
    host.parse::<std::net::IpAddr>().is_err().then_some(port)
}

#[cfg(any(target_os = "linux", test))]
fn named_native_candidate(spec: &super::Spec, m: &Managed) -> Option<(SocketAddr, u32)> {
    let port = named_port(&spec.endpoint)?;
    let sample = crate::client::settings::owned_routed_sample(spec, m, &spec.iface, None).ok()?;
    (sample.connected
        && sample.endpoint.port() == port
        && super::canonical_transport(sample.endpoint) == Some(sample.endpoint)
        && matches!(sample.socket_mark, 0 | crate::DIRECT_SOCKET_MARK))
    .then_some((sample.endpoint, sample.socket_mark))
}

#[cfg(any(target_os = "linux", test))]
fn candidate(
    pool: &[String],
    live: &Value,
    cached: impl Fn(&str) -> Option<SocketAddr>,
) -> Option<SocketAddr> {
    if live["running"] != true || live["status_unavailable"] == true || live["socket_mark"] != 0 {
        return None;
    }
    let primary = pool.first()?;
    let (host, port) = conf::endpoint(primary).ok()?;
    if host.parse::<std::net::IpAddr>().is_ok()
        || cached(primary).is_some()
        || endpoint_index(pool, live, cached).is_some()
    {
        return None;
    }
    live_transport_endpoint(live).filter(|endpoint| endpoint.port() == port)
}

#[cfg(any(target_os = "linux", test))]
fn uses_wan(
    address: SocketAddr,
    mark: u32,
    wan: &[String],
    netifd: Option<&str>,
    require_same_device: bool,
    call: impl Fn(&str, &[&str]) -> io::Result<String>,
) -> bool {
    let ip = address.ip();
    let ip_text = ip.to_string();
    let family = if ip.is_ipv4() { "-4" } else { "-6" };
    let tool = if std::path::Path::new("/opt/libexec/ip-full").is_file() {
        "/opt/libexec/ip-full"
    } else {
        "ip"
    };
    let lookup = |mark: u32| {
        let mark_text = mark.to_string();
        let mut args = vec![family, "route", "get", ip_text.as_str()];
        if mark != 0 {
            args.extend(["mark", mark_text.as_str()]);
        }
        let route = call(tool, &args).ok()?;
        crate::client::physical_wan(&route, ip, wan, netifd).map(str::to_owned)
    };
    lookup(mark).is_some_and(|actual| {
        !require_same_device || mark == 0 || lookup(0).as_deref() == Some(actual.as_str())
    })
}

impl Runtime {
    /// Read exact live tuples from inherited engines and managed named profiles.
    /// The observation does not update DNS or select a new endpoint.
    pub fn inherited_transport_endpoints(
        &self,
        db: &Store,
        wan: &[String],
    ) -> io::Result<Vec<SocketAddr>> {
        #[cfg(target_os = "linux")]
        {
            use std::{path::Path, sync::TryLockError};

            if self.root != Path::new("/") {
                return Ok(Vec::new());
            }
            let owned = self.clients.0.try_lock().map_err(|e| match e {
                TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
                TryLockError::Poisoned(_) => io::Error::other("менеджер туннелей недоступен"),
            })?;
            if owned.is_empty() {
                return Ok(Vec::new());
            }
            let doc = crate::read(db)?;
            Ok(self.inherited_transport_from(&doc, &owned, wan))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (db, wan);
            Ok(Vec::new())
        }
    }

    pub(super) fn inherited_transport_from(
        &self,
        doc: &Value,
        owned: &HashMap<String, Managed>,
        wan: &[String],
    ) -> Vec<SocketAddr> {
        #[cfg(target_os = "linux")]
        {
            use crate::client::saved_specification;
            use nfqws2_router_command::{Runner, System};
            use sha2::{Digest, Sha256};
            use std::{
                collections::BTreeSet,
                path::Path,
                time::{Duration, Instant},
            };
            if self.root != Path::new("/") {
                return Vec::new();
            }
            let mut candidates = doc["servers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|row| {
                    let m = owned.get(s(row, "id"))?;
                    let client = &row["config"]["client"];
                    let inherited = m.tunnel.inherited();
                    let eligible = if inherited {
                        row["config"]["enabled"] == true
                            && client["enabled"] == true
                            && client.get("rust_managed").is_none()
                            && client["double_tunnel_mode"] != "permanent"
                    } else {
                        crate::client::settings::direct_endpoint_profile(row)
                            && named_port(s(&row["config"], "endpoint")).is_some()
                            && m.tunnel.nested_iface().is_none()
                    };
                    eligible.then_some((row, m, inherited))
                })
                .peekable();
            if candidates.peek().is_none() {
                return Vec::new();
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut addresses = BTreeSet::new();
            let call =
                |bin: &str, args: &[&str]| System.run_bounded(bin, args, deadline, 128 << 10);
            let netifd = if wan.is_empty() {
                call("ubus", &["call", "network.interface", "dump"]).ok()
            } else {
                None
            };
            for (row, m, inherited) in candidates {
                if Instant::now() >= deadline {
                    break;
                }
                let Ok(spec) = saved_specification(doc, row, false) else {
                    continue;
                };
                let transport = if inherited {
                    if spec.iface != m.iface
                        || Sha256::digest(spec.conf.as_bytes()).as_slice() != m.fingerprint
                    {
                        continue;
                    }
                    let Ok(live) = m.tunnel.snapshot() else {
                        continue;
                    };
                    candidate(
                        &super::pool(row),
                        &live,
                        crate::endpoint::cached_endpoint_address,
                    )
                    .map(|address| (address, 0))
                } else {
                    named_native_candidate(&spec, m)
                };
                let Some((address, mark)) = transport else {
                    continue;
                };
                if uses_wan(address, mark, wan, netifd.as_deref(), false, call) {
                    addresses.insert(address);
                }
            }
            addresses.into_iter().collect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (doc, owned, wan);
            Vec::new()
        }
    }

    pub(in crate::client) fn verifies_live_wan(
        &self,
        address: SocketAddr,
        mark: u32,
        wan: &[String],
    ) -> bool {
        self.verifies_live_wan_path(address, mark, wan, false)
    }

    pub(in crate::client) fn verifies_live_wan_path(
        &self,
        address: SocketAddr,
        mark: u32,
        wan: &[String],
        require_same_device: bool,
    ) -> bool {
        #[cfg(target_os = "linux")]
        {
            use nfqws2_router_command::{Runner, System};
            use std::{
                path::Path,
                time::{Duration, Instant},
            };

            if self.root != Path::new("/") || !matches!(mark, 0 | crate::DIRECT_SOCKET_MARK) {
                return false;
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            let call =
                |bin: &str, args: &[&str]| System.run_bounded(bin, args, deadline, 128 << 10);
            let netifd = if wan.is_empty() {
                call("ubus", &["call", "network.interface", "dump"]).ok()
            } else {
                None
            };
            uses_wan(
                address,
                mark,
                wan,
                netifd.as_deref(),
                require_same_device,
                call,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (address, mark, wan, require_same_device);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inherited_ip_move_requires_marked_and_plain_routes_to_agree_on_the_selected_wan() {
        let endpoint = "[2001:db8::41]:2408".parse().unwrap();
        let wan = ["wan.1".into(), "wan.2".into()];
        let mark = crate::DIRECT_SOCKET_MARK;
        let verify = |marked, plain, compare, actual_mark| {
            uses_wan(endpoint, actual_mark, &wan, None, compare, |_, args| {
                let selected = match args {
                    ["-6", "route", "get", "2001:db8::41", "mark", "536870912"] => marked,
                    ["-6", "route", "get", "2001:db8::41"] => plain,
                    _ => unreachable!(),
                };
                Ok(format!("2001:db8::41 dev {selected}"))
            })
        };
        assert!(verify("wan.2", "wan.2", true, mark));
        assert!(!verify("wan.2", "wan.1", true, mark));
        assert!(!verify("wan.2", "awg1", true, mark));
        assert!(verify("wan.2", "wan.1", false, mark));
        assert!(verify("awg1", "wan.1", true, 0));
    }

    #[test]
    fn named_managed_bypass_uses_current_owner_instead_of_the_dns_cache() {
        use crate::client::{settings::RoutedMtuSample, NestedOuter, Spec, Tunnel};
        use sha2::{Digest, Sha256};

        struct Engine(SocketAddr, u32);
        impl Tunnel for Engine {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn probe(&mut self) -> io::Result<()> {
                unreachable!()
            }
            fn snapshot(&self) -> io::Result<Value> {
                unreachable!()
            }
            fn verified_routed_mtu(
                &self,
                _: &Spec,
                outer: Option<&NestedOuter>,
                connected: bool,
            ) -> io::Result<RoutedMtuSample> {
                assert!(outer.is_none() && connected);
                Ok(RoutedMtuSample {
                    endpoint: self.0,
                    effective_mtu: 1420,
                    socket_mark: self.1,
                    connected,
                    outer_endpoint: None,
                })
            }
        }
        let selected = "192.0.2.189:2408".parse().unwrap();
        let spec = Spec {
            id: "test".into(),
            iface: "awg1".into(),
            conf: "Endpoint = Host.Test:2408\n".into(),
            endpoint: "Host.Test:2408".into(),
            permanent: false,
            outer: None,
        };
        let mark = crate::DIRECT_SOCKET_MARK;
        let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
        let mut managed = Managed {
            iface: spec.iface.clone(),
            fingerprint,
            tunnel: Box::new(Engine(selected, mark)),
            recovery: Default::default(),
        };
        assert_eq!(
            named_native_candidate(&spec, &managed),
            Some((selected, mark))
        );
        managed.fingerprint = [0; 32];
        assert!(named_native_candidate(&spec, &managed).is_none());
        managed.fingerprint = fingerprint;
        managed.tunnel = Box::new(Engine("192.0.2.189:2409".parse().unwrap(), mark));
        assert!(named_native_candidate(&spec, &managed).is_none());
        managed.tunnel = Box::new(Engine(selected, 0xa0000010));
        assert!(named_native_candidate(&spec, &managed).is_none());
    }

    #[test]
    fn cold_idle_tuple_requires_the_same_port_and_excludes_explicit_backups() {
        let pool = vec!["primary.test:2408".into(), "192.0.2.2:2408".into()];
        let mut live = json!({"running":true,"socket_mark":0,"endpoint":"[::ffff:192.0.2.5]:2408","connected":false,"last_handshake":1});
        let addr = "192.0.2.5:2408".parse().unwrap();
        assert_eq!(candidate(&pool, &live, |_| None), Some(addr));
        assert!(candidate(&pool, &live, |_| Some(addr)).is_none());
        assert_eq!(live["last_handshake"], 1);
        assert_eq!(live["connected"], false);
        for value in [
            "192.0.2.5:2409",
            "192.0.2.2:2408",
            "[fe80::1%2]:2408",
            "127.0.0.1:2408",
        ] {
            live["endpoint"] = json!(value);
            assert!(candidate(&pool, &live, |_| None).is_none());
        }
        live["endpoint"] = json!("192.0.2.5:2408");
        live["socket_mark"] = json!(0x20000000);
        assert!(candidate(&pool, &live, |_| None).is_none());
        live["socket_mark"] = json!(0);
        live["status_unavailable"] = json!(true);
        assert!(candidate(&pool, &live, |_| None).is_none());
    }
}
