use super::*;
use serde_json::json;
use std::cell::RefCell;

pub(in crate::client) fn routes() -> Routes {
    Routes {
        iface: "awg1".into(),
        outer: "awg0".into(),
        endpoint: "192.0.2.1".parse().unwrap(),
        source: "10.0.0.8".parse().unwrap(),
    }
}
#[derive(Default)]
pub(in crate::client) struct Fib {
    families: [Objects; 2],
    extra: [String; 2],
    extra_route: [String; 2],
    pub(in crate::client) writes: Vec<String>,
    fail: Option<usize>,
    pub(in crate::client) fail_after: Option<usize>,
    numeric: bool,
}
impl Fib {
    pub(in crate::client) fn run(&mut self, a: &[&str]) -> io::Result<String> {
        let idx = usize::from(a.contains(&"-6"));
        let have = &mut self.families[idx];
        if a.contains(&"show") {
            let mut lines = Vec::new();
            if a.contains(&"rule") {
                lines.extend(
                    [
                        "0: from all lookup local",
                        "40: from all fwmark 0x10100000/0x1ff00000 lookup 901",
                        "32766: from all lookup main",
                    ]
                    .into_iter()
                    .map(str::to_owned),
                );
                if have.lookup {
                    lines.push("60: from all fwmark 0xa0000001 lookup 829".into());
                }
                if have.guard {
                    let action = if self.numeric { "8" } else { "prohibit" };
                    lines.push(format!("61: from all fwmark 0xa0000001 {action}"));
                }
                if !self.extra[idx].is_empty() {
                    lines.push(self.extra[idx].clone());
                }
            } else {
                if have.blackhole {
                    let suffix = if idx == 0 {
                        ""
                    } else {
                        " error -22 pref medium"
                    };
                    let route = if self.numeric { "6" } else { "blackhole" };
                    lines.push(format!(
                        "{route} default dev lo table 829 proto 99 metric 1000{suffix}"
                    ));
                }
                if have.peer {
                    lines.push(
                        "192.0.2.1 dev awg0 table 829 proto 99 scope link src 10.0.0.8".into(),
                    );
                }
                if !self.extra_route[idx].is_empty() {
                    lines.push(self.extra_route[idx].clone());
                }
            }
            return Ok(lines.join("\n"));
        }
        if self.fail == Some(self.writes.len()) {
            self.fail = None;
            return Err(io::Error::other("injected"));
        }
        let obj = if a.contains(&"pref") && a.contains(&"60") {
            &mut have.lookup
        } else if a.contains(&"pref") && a.contains(&"61") {
            &mut have.guard
        } else if a.contains(&"blackhole") {
            &mut have.blackhole
        } else {
            assert!(a.contains(&"192.0.2.1/32") && a.contains(&"10.0.0.8") && a.contains(&"awg0"));
            &mut have.peer
        };
        let desired = if a.contains(&"add") {
            true
        } else {
            assert!(a.contains(&"del"));
            false
        };
        assert_ne!(*obj, desired);
        *obj = desired;
        let index = self.writes.len();
        self.writes.push(a.join(" "));
        if self.fail_after == Some(index) {
            self.fail_after = None;
            return Err(io::Error::other("injected after accepted mutation"));
        }
        Ok(String::new())
    }
}

#[test]
fn retirement_replays_every_accepted_write_and_checks_both_families() {
    let r = routes();
    for interrupted in 0..7 {
        let fib = RefCell::new(Fib {
            numeric: true,
            ..Fib::default()
        });
        let ip = |a: &[&str]| fib.borrow_mut().run(a);
        r.reconcile(true, true, &ip).unwrap();
        let initial = fib.borrow().writes.len();

        fib.borrow_mut().extra[1] = "61: from all fwmark 0xa0000001 8".into();
        assert!(r.verify_retirement(true, &ip).is_err());
        assert!(r.reconcile(true, false, &ip).is_err());
        assert_eq!(fib.borrow().writes.len(), initial);
        fib.borrow_mut().extra[1].clear();

        r.verify_retirement(true, &ip).unwrap();
        fib.borrow_mut().fail_after = Some(initial + interrupted);
        assert!(r.reconcile(true, false, &ip).is_err());
        r.reconcile(true, false, &ip).unwrap();
        r.verify_retirement(false, &ip).unwrap();
        assert_eq!(fib.borrow().writes.len(), initial + 7);
    }
}
#[test]
fn selectors_fail_closed_at_every_interruption_and_repair_without_replacement() {
    for stop in 0..7 {
        let fib = RefCell::new(Fib {
            fail: Some(stop),
            ..Fib::default()
        });
        let ip = |a: &[&str]| fib.borrow_mut().run(a);
        let r = routes();
        r.reconcile(false, false, &ip).unwrap();
        assert!(r.reconcile(true, true, &ip).is_err());
        r.reconcile(true, false, &ip).unwrap();
        assert_eq!(fib.borrow().families, [Objects::default(); 2]);
    }
    let fib = RefCell::new(Fib::default());
    let ip = |a: &[&str]| fib.borrow_mut().run(a);
    let r = routes();
    r.reconcile(true, true, &ip).unwrap();
    assert_eq!(fib.borrow().writes.len(), 7);
    assert!(fib.borrow().writes[0].contains("pref 61"));
    assert!(fib.borrow().writes[3].contains("pref 60"));
    r.reconcile(true, true, &ip).unwrap();
    assert_eq!(fib.borrow().writes.len(), 7);
    r.verify_installed(&ip).unwrap();
    assert_eq!(fib.borrow().writes.len(), 7);
    fib.borrow_mut().families[0].peer = false;
    assert!(r.verify_installed(&ip).is_err());
    assert_eq!(fib.borrow().writes.len(), 7);
    r.reconcile(true, true, &ip).unwrap();
    assert_eq!(fib.borrow().writes.len(), 8);
    r.reconcile(true, false, &ip).unwrap();
    assert_eq!(fib.borrow().families, [Objects::default(); 2]);
}
#[test]
fn refuse_unowned_marks_table_references_foreign_attributes_and_duplicates() {
    let r = routes();
    for (rule, route, own) in [
        (
            "45: from all fwmark 0xa0000000/0xf0000000 lookup 907",
            "",
            true,
        ),
        (
            "45: not from all fwmark 0x10100000/0x1ff00000 lookup 907",
            "",
            true,
        ),
        ("49: from all lookup 900", "", true),
        ("17000: from all lookup 829", "", true),
        ("60: from all fwmark 0xa0000001 lookup 829", "", false),
        (
            "61: from all fwmark 0xa0000001 lookup main prohibit",
            "",
            false,
        ),
        (
            "",
            "blackhole default table 829 proto 99 metric 1000",
            false,
        ),
        ("", "blackhole default table 829 proto 33 metric 1000", true),
        (
            "",
            "192.0.2.1 via 10.0.0.1 dev awg0 table 829 proto 99 scope link src 10.0.0.8",
            true,
        ),
        (
            "",
            "192.0.2.1 dev awg0 table 829 proto 99 scope link src 10.0.0.17",
            true,
        ),
    ] {
        let mut f = Fib::default();
        f.extra[1] = rule.into();
        f.extra_route[0] = route.into();
        let f = RefCell::new(f);
        assert!(
            r.reconcile(own, true, &|a| f.borrow_mut().run(a)).is_err(),
            "{rule} {route}"
        );
        assert!(
            f.borrow().writes.is_empty(),
            "audited both families before first mutation"
        );
    }
    let fib = RefCell::new(Fib::default());
    let ip = |a: &[&str]| fib.borrow_mut().run(a);
    r.reconcile(true, true, &ip).unwrap();
    fib.borrow_mut().extra[1] = "61: from all fwmark 0xa0000001 prohibit".into();
    assert!(r.reconcile(true, false, &ip).is_err());
    assert_eq!(fib.borrow().writes.len(), 7);
}
#[test]
fn outer_peer_source_mtu_and_profile_identity() {
    let r = routes();
    assert_eq!(r.mark().unwrap(), 0xa0000001);
    assert_eq!(r.table().unwrap(), 829);
    assert!(crate::nested_socket_selector("awg01").is_err());
    assert!(crate::nested_socket_selector("awg268435456").is_err());
    let outer = super::super::NestedOuter::from_spec(&super::super::Spec {
        id: "p".into(),
        iface: "awg0".into(),
        conf: format!(
            "[Peer]\nPublicKey = {}\n",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        ),
        endpoint: String::new(),
        outer: None,
        permanent: false,
    })
    .unwrap();
    assert_eq!(outer.iface, r.outer);
    assert_eq!(outer.peer_hex, "01".repeat(32));
    let base=format!("public_key={}\nendpoint=192.0.2.50:123\nlast_handshake_time_sec=99\nallowed_ip=192.0.2.0/24\nerrno=0\n\n",outer.peer_hex);
    check_outer_peer(base.as_bytes(), &outer.peer_hex, r.endpoint, 100).unwrap();
    let direct = format!("fwmark={}\n{base}", crate::DIRECT_SOCKET_MARK);
    check_outer_peer(direct.as_bytes(), &outer.peer_hex, r.endpoint, 100).unwrap();
    for corrupt in [
        base.replace("192.0.2.0/24", "192.0.3.0/24"),
        base.replace("=99", "=0"),
        base.replace("public_key=", "fwmark=2684354561\npublic_key="),
        base.replace(&outer.peer_hex, &"ab".repeat(32)),
    ] {
        assert!(check_outer_peer(corrupt.as_bytes(), &outer.peer_hex, r.endpoint, 100).is_err());
    }
    let addr6 = "2001:db8::123".parse().unwrap();
    assert!(covers("::/0", addr6));
    assert!(!covers("::/129", addr6));
    assert!(covers("2001:db8::/64", addr6));
    let cfg =
        json!({"mtu":1420,"protocol":"awg","obf":{"s4":16,"content_padding_addition":"2-20"}});
    assert_eq!(mtu(&cfg, 1400, r.endpoint).unwrap(), 1304);
    assert_eq!(mtu(&cfg, 1400, addr6).unwrap(), 1284);
    assert!(mtu(&cfg, 610, r.endpoint).is_err());
    let addrs="1: awg0 inet6 fe80::1/64 scope link\n1: awg0 inet6 2001:db8::2/64 tentative\n1: awg0 inet6 2001:db8::123/64 scope global";
    assert_eq!(source(addrs, addr6).unwrap(), addr6);
}

#[test]
fn shared_ip_with_other_outer_port_requires_actual_direct_wan() {
    let key = "01".repeat(32);
    let live = format!("fwmark={}\npublic_key={key}\nendpoint=[::ffff:192.0.2.50]:123\nlast_handshake_time_sec=99\nallowed_ip=192.0.2.0/24\nerrno=0\n\n", crate::DIRECT_SOCKET_MARK);
    let selected: SocketAddr = "192.0.2.50:8443".parse().unwrap();
    let observed = || check_outer_peer(live.as_bytes(), &key, selected.ip(), 100).unwrap();
    let wan = |endpoint: SocketAddr, mark| {
        assert_eq!(endpoint, "192.0.2.50:123".parse().unwrap());
        assert_eq!(mark, crate::DIRECT_SOCKET_MARK);
    };
    assert!(
        verify_shared_outer_wan(selected, observed(), |endpoint, mark| {
            wan(endpoint, mark);
            false
        })
        .is_err()
    );
    verify_shared_outer_wan(selected, observed(), |endpoint, mark| {
        wan(endpoint, mark);
        true
    })
    .unwrap();
    verify_shared_outer_wan(
        "192.0.2.51:8443".parse().unwrap(),
        observed(),
        |_, _| unreachable!(),
    )
    .unwrap();
}
