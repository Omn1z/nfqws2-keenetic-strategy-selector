use super::*;

pub(in crate::client) struct Peer {
    pub(super) iface: String,
    pub(super) direct: bool,
    healthy: bool,
    failed: bool,
}

pub(super) fn peers(
    owned: &mut HashMap<String, Managed>,
    now: u64,
    settings: &Value,
    doc: &Value,
) -> HashMap<String, Peer> {
    let timeout = settings["handshake_timeout_seconds"].as_u64().unwrap_or(20);
    owned
        .iter_mut()
        .map(|(id, m)| {
            let healthy = m.tunnel.alive() && m.recovery.authenticated(now);
            let has_endpoints = find(doc, id).is_ok_and(|row| pool(row).len() > 1);
            (
                id.clone(),
                Peer {
                    iface: m.iface.clone(),
                    healthy,
                    direct: healthy && m.tunnel.nested_iface().is_none(),
                    failed: m.recovery.needs_reserve(now, timeout, has_endpoints),
                },
            )
        })
        .collect()
}

#[derive(Default)]
pub(super) struct Reserves {
    connection_up: bool,
    available: bool,
}
pub(super) fn reserves(
    graph: &FailoverGraph<'_>,
    doc: &Value,
    id: &str,
    peers: &HashMap<String, Peer>,
) -> io::Result<Reserves> {
    let mut state = Reserves::default();
    if graph.nested(id).is_none() {
        return Ok(state);
    }
    let enabled = |id: &str| {
        find(doc, id).is_ok_and(|r| {
            r["config"]["enabled"] == true && r["config"]["client"]["enabled"] == true
        })
    };
    let available = |id: &str| enabled(id) && peers.get(id).is_none_or(|p| !p.failed || p.healthy);
    for id in graph
        .for_rule(id, &[])?
        .into_iter()
        .skip(1)
        .filter(|id| enabled(id))
    {
        state.connection_up |= peers.get(id).is_some_and(|p| p.healthy);
        state.available |= available(id);
    }
    for chain in doc["rust_static_routing"]["reserve_chains"][id]
        .as_array()
        .into_iter()
        .flatten()
    {
        let ids: Vec<String> = serde_json::from_value(chain.clone()).map_err(io::Error::other)?;
        state.available |= graph.for_rule(id, &ids)?.into_iter().skip(1).any(available);
    }
    Ok(state)
}

#[derive(Default)]
pub(in crate::client) struct State {
    wanted: bool,
    active: bool,
    trial: u64,
    direct_until: u64,
    repair_at: u64,
    verify_at: u64,
    egress: Option<IpAddr>,
    error: String,
}
pub(super) struct Inputs<'a> {
    pub mode: Option<&'a str>,
    pub outer: Option<&'a str>,
    pub active: Option<&'a str>,
    pub peer_healthy: bool,
    pub direct_failed: bool,
    pub exhausted: bool,
    pub reconnect: bool,
    pub reserves: Reserves,
    pub now: u64,
    pub timeout: u64,
}
#[derive(Debug, PartialEq)]
pub(super) enum Choice {
    Keep,
    Wait,
    Pause,
    Outer,
    Check,
    Direct,
}
impl State {
    pub(in crate::client) fn wants_outer(&self) -> bool {
        self.wanted
    }
    pub(in crate::client) fn prefers_ordinary(&self, mode: &str) -> bool {
        mode == "automatic" && self.wanted && self.verified()
    }
    pub(in crate::client) fn reserve_health(
        &self,
        mode: &str,
        now: u64,
        timeout: u64,
        verified: &mut bool,
        failed: &mut bool,
    ) {
        if self.verified() && mode == "automatic" {
            // The Go automatic policy keeps evaluating ordinary reserves while
            // the inner peer uses its verified nested path.
            *verified = false;
            *failed = true;
        } else if self.wanted
            && matches!(mode, "preferred" | "automatic" | "permanent")
            && self.trial != 0
            && !self.failed(now, timeout)
        {
            *failed = false;
        }
    }
    pub(in crate::client) fn status(
        &self,
        outer: Option<&str>,
        authenticated: bool,
        out: &mut Value,
    ) {
        let active = outer.is_some() && authenticated && self.verified();
        out["double_tunnel_active"] = json!(active);
        if active {
            out["double_tunnel_ip"] = json!(self.egress);
        }
        if !self.error.is_empty() {
            out["double_tunnel_error"] = json!(self.error);
        }
    }
    pub(super) fn verified(&self) -> bool {
        self.active && self.egress.is_some()
    }
    pub(super) fn usable(&self) -> bool {
        !self.active || self.verified()
    }
    pub(super) fn failed(&self, now: u64, timeout: u64) -> bool {
        self.trial != 0 && now.saturating_sub(self.trial) >= 2 * timeout
    }
    pub(super) fn direct_trial(&mut self, now: u64, timeout: u64) {
        self.direct_until = now.saturating_add(timeout);
        self.wanted = false;
    }
    pub(super) fn start_failed(&mut self, now: u64, timeout: u64, e: &io::Error) {
        self.error = e.to_string();
        self.active = false;
        self.direct_trial(now, timeout);
    }
    pub(super) fn launched(&mut self, now: u64, nested: bool) {
        self.active = nested;
        self.egress = None;
        self.verify_at = 0;
        self.repair_at = 0;
        self.trial = if nested { now } else { 0 };
    }
    pub(super) fn adopt_saved(&mut self, now: u64) {
        if !self.active {
            self.launched(now, true);
        }
    }
    pub(super) fn choose(&mut self, i: Inputs<'_>) -> Choice {
        if i.mode == Some("permanent") {
            self.wanted = true;
            if i.outer.is_none() {
                self.active = true;
                self.egress = None;
                self.error = "ожидание прямого подключения внешнего туннеля".into();
                return Choice::Pause;
            }
            if i.active != i.outer || i.reconnect && self.failed(i.now, i.timeout) {
                if i.now < self.direct_until {
                    return Choice::Pause;
                }
                return Choice::Outer;
            }
            return Choice::Check;
        }
        if i.active.is_none() && (i.mode.is_none() || i.peer_healthy) {
            *self = Self::default();
            return Choice::Keep;
        }
        let automatic = i.mode == Some("automatic");
        let early = automatic || i.mode == Some("preferred");
        let reserve_precedes = match i.mode {
            Some("automatic") => i.reserves.connection_up,
            Some("preferred") => false,
            _ => i.reserves.available,
        };
        if let Some(active) = i.active {
            if i.mode.is_none() || reserve_precedes || i.reconnect && self.failed(i.now, i.timeout)
            {
                return Choice::Direct;
            }
            self.wanted = true;
            if Some(active) == i.outer {
                return Choice::Check;
            }
            self.egress = None;
            self.error = "ожидание прямого подключения внешнего туннеля".into();
            return if self.failed(i.now, i.timeout) {
                Choice::Direct
            } else {
                Choice::Wait
            };
        }
        self.wanted = !reserve_precedes
            && i.now >= self.direct_until
            && if early { i.direct_failed } else { i.exhausted };
        if !self.wanted {
            return Choice::Keep;
        }
        if i.outer.is_some() {
            return Choice::Outer;
        }
        if self.trial == 0 {
            self.trial = i.now;
        }
        self.error = "ожидание прямого подключения внешнего туннеля".into();
        if early && !self.failed(i.now, i.timeout) {
            Choice::Wait
        } else {
            Choice::Keep
        }
    }
    pub(super) fn check(
        &mut self,
        now: u64,
        tunnel: &mut dyn Tunnel,
        iface: &str,
        healthy: bool,
        verify: impl FnOnce(&str) -> io::Result<IpAddr>,
    ) {
        if now >= self.repair_at {
            if let Err(e) = tunnel.repair_nested() {
                self.egress = None;
                self.error = e.to_string();
                return;
            }
            self.repair_at = now.saturating_add(30);
        }
        if !healthy {
            self.egress = None;
            return;
        }
        if self.egress.is_none() && now >= self.verify_at {
            match verify(iface) {
                Ok(ip) => {
                    self.egress = Some(ip);
                    self.error.clear();
                }
                Err(e) => {
                    self.error = e.to_string();
                    self.verify_at = now.saturating_add(5);
                }
            }
        }
    }
}
impl Runtime {
    pub fn prefers_ordinary_routing(&self, config: &Value, iface: &str, socket_mark: u32) -> bool {
        socket_mark >> 28 == 0xa
            && config["client"]["double_tunnel_mode"] == "automatic"
            && self.nested_verified(iface)
    }

    #[cfg(not(unix))]
    pub(in crate::client) fn nested_verified(&self, _: &str) -> bool {
        false
    }

    #[cfg(unix)]
    fn nested_identity(&self, iface: &str) -> Option<(u64, u64, u32)> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let m = std::fs::symlink_metadata(
            self.root
                .join("var/run/amneziawg")
                .join(format!("{iface}.sock")),
        )
        .ok()?;
        let index =
            std::fs::read_to_string(self.root.join("sys/class/net").join(iface).join("ifindex"))
                .ok()?;
        let index = index.trim().parse().ok()?;
        (m.file_type().is_socket() && index != 0).then_some((m.dev(), m.ino(), index))
    }
    #[cfg(unix)]
    pub(in crate::client) fn nested_verified(&self, iface: &str) -> bool {
        self.nested_identity(iface).is_some_and(|actual| {
            self.clients
                .2
                .lock()
                .is_ok_and(|map| map.get(iface) == Some(&actual))
        })
    }
    pub(in crate::client) fn record_nested(&self, iface: &str, verified: bool) {
        #[cfg(unix)]
        let identity = verified.then(|| self.nested_identity(iface)).flatten();
        #[cfg(not(unix))]
        let identity = {
            let _ = verified;
            None
        };
        if let Ok(mut interfaces) = self.clients.2.lock() {
            if let Some(current) = identity {
                interfaces.insert(iface.to_owned(), current);
            } else {
                interfaces.remove(iface);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_status_prefers_a_live_reserve_while_the_inner_link_remains_verified() {
        struct Awake(Option<&'static str>);
        impl Tunnel for Awake {
            fn alive(&mut self) -> bool {
                true
            }
            fn stop(&mut self) -> io::Result<()> {
                panic!("reading failover status stopped a peer")
            }
            fn probe(&mut self) -> io::Result<()> {
                panic!("reading failover status probed a peer")
            }
            fn snapshot(&self) -> io::Result<Value> {
                Ok(json!({"connected": true}))
            }
            fn nested_iface(&self) -> Option<&str> {
                self.0
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        let mut doc = json!({"servers": [
            {"id":"primary","config":{"enabled":true,"client":{"enabled":true,"rust_managed":true,
                "fallback_tunnel_ids":["backup"],"double_tunnel_id":"outer","double_tunnel_mode":"automatic"}}},
            {"id":"backup","config":{"enabled":true,"client":{"enabled":true,"rust_managed":true}}},
            {"id":"outer","config":{"enabled":true,"client":{"enabled":true,"rust_managed":true}}}
        ]});
        let now = crate::now();
        {
            let mut clients = runtime.clients.0.lock().unwrap();
            for (id, iface, outer) in [("primary", "awg0", Some("awg2")), ("backup", "awg1", None)] {
                clients.insert(id.into(), Managed {
                    iface: iface.into(),
                    fingerprint: [0; 32],
                    tunnel: Box::new(Awake(outer)),
                    recovery: Recovery {
                        healthy_at: now,
                        nested: if outer.is_some() {
                            State { active: true, wanted: true, egress: Some("198.51.100.9".parse().unwrap()), ..Default::default() }
                        } else {
                            State::default()
                        },
                        ..Default::default()
                    },
                });
            }
        }
        assert_eq!(runtime.failover_view(&doc)["primary"]["active_tunnel_id"], "backup");
        doc["servers"][0]["config"]["client"]["double_tunnel_mode"] = json!("preferred");
        assert_eq!(runtime.failover_view(&doc)["primary"]["active_tunnel_id"], "primary");
        doc["servers"][0]["config"]["client"]["double_tunnel_mode"] = json!("automatic");
        runtime.clients.0.lock().unwrap().get_mut("backup").unwrap().recovery.healthy_at = 0;
        assert_eq!(runtime.failover_view(&doc)["primary"]["active_tunnel_id"], "primary");
    }

    #[cfg(unix)]
    #[test]
    fn verified_nested_path_expires_when_the_socket_or_interface_changes() {
        let root = tempfile::tempdir().unwrap();
        let sockets = root.path().join("var/run/amneziawg");
        let dev = root.path().join("sys/class/net/awg2");
        std::fs::create_dir_all(&sockets).unwrap();
        std::fs::create_dir_all(&dev).unwrap();
        let path = sockets.join("awg2.sock");
        let _original = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::write(dev.join("ifindex"), "9\n").unwrap();
        let rt = Runtime::new(root.path(), root.path().join("engine"));
        rt.record_nested("awg2", true);
        assert!(rt.nested_verified("awg2"));
        let automatic = json!({"client":{"double_tunnel_mode":"automatic"}});
        let preferred = json!({"client":{"double_tunnel_mode":"preferred"}});
        let (mark, _) = crate::nested_socket_selector("awg2").unwrap();
        assert!(rt.prefers_ordinary_routing(&automatic, "awg2", mark));
        assert!(!rt.prefers_ordinary_routing(&automatic, "awg2", 0));
        assert!(!rt.prefers_ordinary_routing(&preferred, "awg2", mark));
        std::fs::write(dev.join("ifindex"), "10\n").unwrap();
        assert!(!rt.nested_verified("awg2"));
        assert!(!rt.prefers_ordinary_routing(&automatic, "awg2", mark));
        rt.record_nested("awg2", true);
        std::fs::remove_file(&path).unwrap();
        let _other = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(!rt.nested_verified("awg2"));
        assert!(!rt.prefers_ordinary_routing(&automatic, "awg2", mark));
    }
    fn direct(mode: &str) -> Inputs<'_> {
        Inputs {
            mode: Some(mode),
            outer: Some("awg0"),
            active: None,
            peer_healthy: false,
            direct_failed: true,
            exhausted: false,
            reconnect: true,
            reserves: Reserves::default(),
            now: 100,
            timeout: 20,
        }
    }
    #[test]
    fn connected_direct_is_preserved_and_automatic_and_last_resort_use_their_own_order() {
        let mut state = State::default();
        assert_eq!(
            state.choose(Inputs {
                peer_healthy: true,
                ..direct("automatic")
            }),
            Choice::Keep
        );
        assert!(!state.wants_outer());
        assert_eq!(state.choose(direct("last_resort")), Choice::Keep);
        assert_eq!(
            state.choose(Inputs {
                exhausted: true,
                reserves: Reserves {
                    available: true,
                    connection_up: false
                },
                ..direct("last_resort")
            }),
            Choice::Keep
        );
        assert_eq!(
            state.choose(Inputs {
                exhausted: true,
                ..direct("last_resort")
            }),
            Choice::Outer
        );
        assert_eq!(state.choose(direct("automatic")), Choice::Outer);
        assert_eq!(
            state.choose(Inputs {
                outer: None,
                ..direct("automatic")
            }),
            Choice::Wait
        );
        assert!(state.wants_outer());
        assert_eq!(
            state.choose(Inputs {
                outer: None,
                now: 141,
                ..direct("automatic")
            }),
            Choice::Keep
        );
        assert_eq!(
            state.choose(Inputs {
                reserves: Reserves {
                    available: true,
                    connection_up: true
                },
                ..direct("automatic")
            }),
            Choice::Keep
        );
        state.direct_trial(150, 20);
        assert_eq!(
            state.choose(Inputs {
                now: 155,
                ..direct("automatic")
            }),
            Choice::Keep
        );
    }
    struct TunnelFixture {
        repair: bool,
    }
    impl Tunnel for TunnelFixture {
        fn repair_nested(&mut self) -> io::Result<()> {
            if self.repair {
                Ok(())
            } else {
                Err(io::ErrorKind::NotConnected.into())
            }
        }
        fn alive(&mut self) -> bool {
            true
        }
        fn probe(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn stop(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn snapshot(&self) -> io::Result<Value> {
            unreachable!()
        }
    }
    #[test]
    fn nested_requires_confirmed_peer_https_and_owned_routes_before_traffic() {
        let mut state = State::default();
        let mut tunnel = TunnelFixture { repair: true };
        state.launched(100, true);
        state.check(101, &mut tunnel, "awg1", false, |_| panic!("no handshake"));
        assert!(!state.usable());
        state.check(105, &mut tunnel, "awg1", true, |_| {
            Err(io::ErrorKind::TimedOut.into())
        });
        assert!(!state.usable());
        state.check(110, &mut tunnel, "awg1", true, |iface| {
            assert_eq!(iface, "awg1");
            Ok("192.0.2.123".parse().unwrap())
        });
        let mut status = json!({});
        state.status(Some("awg0"), true, &mut status);
        assert_eq!(status["double_tunnel_ip"], "192.0.2.123");
        assert_eq!(status["double_tunnel_active"], true);
        tunnel.repair = false;
        state.check(132, &mut tunnel, "awg1", true, |_| panic!("lost routes"));
        assert!(!state.usable());
        state.status(Some("awg0"), true, &mut status);
        assert_eq!(status["double_tunnel_active"], false);
        assert_eq!(
            state.choose(Inputs {
                active: Some("awg0"),
                now: 145,
                ..direct("automatic")
            }),
            Choice::Direct
        );
    }
    #[test]
    fn permanent_never_selects_a_direct_path_and_preferred_prioritizes_nested() {
        let mut s = State::default();
        assert_eq!(
            s.choose(Inputs {
                outer: None,
                peer_healthy: true,
                ..direct("permanent")
            }),
            Choice::Pause
        );
        assert!(s.wants_outer());
        assert_eq!(
            s.choose(Inputs {
                peer_healthy: true,
                ..direct("permanent")
            }),
            Choice::Outer
        );
        s.launched(100, true);
        assert_eq!(
            s.choose(Inputs {
                active: Some("awg0"),
                ..direct("permanent")
            }),
            Choice::Check
        );
        assert_eq!(
            s.choose(Inputs {
                active: Some("awg0"),
                outer: None,
                ..direct("permanent")
            }),
            Choice::Pause
        );
        assert_eq!(
            s.choose(Inputs {
                active: Some("awg0"),
                now: 180,
                ..direct("permanent")
            }),
            Choice::Outer
        );
        let reserve = Reserves {
            connection_up: true,
            available: true,
        };
        assert_eq!(
            s.choose(Inputs {
                reserves: reserve,
                ..direct("preferred")
            }),
            Choice::Outer
        );
    }
}
