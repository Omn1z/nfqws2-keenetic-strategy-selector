use nfqws2_blockcheck::{
    firewall::{Firewall, Sandbox},
    Request,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    io,
    net::Ipv4Addr,
    rc::Rc,
};

#[derive(Default)]
struct Table {
    chains: BTreeMap<String, Vec<Vec<String>>>,
    addrs: BTreeSet<Ipv4Addr>,
    history: Vec<Vec<String>>,
    fail_after: Option<usize>,
}
#[derive(Clone)]
struct Fake(Rc<RefCell<Table>>);
impl Fake {
    fn router(vendor: bool) -> Self {
        let mut t = Table::default();
        for name in ["OUTPUT", "PREROUTING", "POSTROUTING"] {
            t.chains.insert(name.into(), Vec::new());
        }
        if vendor {
            for name in ["nfqws_post", "nfqws_pre"] {
                t.chains
                    .insert(name.into(), vec![vec!["-j".into(), "EXISTING".into()]]);
            }
        }
        t.addrs
            .extend([Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 1)]);
        Self(Rc::new(RefCell::new(t)))
    }
}
impl Firewall for Fake {
    fn addresses(&self) -> io::Result<BTreeSet<Ipv4Addr>> {
        Ok(self.0.borrow().addrs.clone())
    }
    fn iptables(&self, cmd: &[String]) -> io::Result<String> {
        let mut t = self.0.borrow_mut();
        t.history.push(cmd.to_vec());
        if cmd[0] == "-S" {
            let mut list = String::new();
            for (chain, rules) in &t.chains {
                if !matches!(chain.as_str(), "OUTPUT" | "PREROUTING" | "POSTROUTING") {
                    list += &format!("-N {chain}\n");
                }
                for r in rules {
                    list += &format!("-A {chain} {}\n", r.join(" "));
                }
            }
            return Ok(list);
        }
        if let Some(remaining) = t.fail_after.as_mut() {
            if *remaining == 0 {
                t.fail_after = None;
                return Err(io::Error::other("test command failure"));
            }
            *remaining -= 1;
        }
        let chain = &cmd[1];
        let missing = || io::Error::other("missing chain/rule");
        match cmd[0].as_str() {
            "-N" => {
                if t.chains.contains_key(chain) {
                    return Err(io::Error::other("exists"));
                }
                t.chains.insert(chain.clone(), Vec::new());
            }
            "-X" => {
                if !t.chains.get(chain).ok_or_else(missing)?.is_empty()
                    || t.chains.values().flatten().any(|r| r.last() == Some(chain))
                {
                    return Err(io::Error::other("chain in use"));
                }
                t.chains.remove(chain);
            }
            op => {
                let rules = t.chains.get_mut(chain).ok_or_else(missing)?;
                match op {
                    "-F" => rules.clear(),
                    "-A" => rules.push(cmd[2..].to_vec()),
                    "-I" => rules.insert(0, cmd[3..].to_vec()),
                    "-C" | "-D" => {
                        let i = rules
                            .iter()
                            .position(|r| *r == cmd[2..])
                            .ok_or_else(missing)?;
                        if op == "-D" {
                            rules.remove(i);
                        }
                    }
                    _ => panic!("unexpected iptables operation"),
                }
            }
        }
        Ok(String::new())
    }
}
#[test]
fn local_origin_and_direction_match_every_worker_marking_is_installed_last() {
    let fake = Fake::router(true);
    let before = fake.0.borrow().chains.clone();
    let mut s = Sandbox::open(fake.clone(), &[(50000, 50009), (50010, 50019)]).unwrap();
    {
        let t = fake.0.borrow();
        assert_eq!(t.chains["OUTPUT"][0], ["-j", "N2S_BC_OUT"]);
        assert!(t.chains["PREROUTING"].is_empty() && t.chains["POSTROUTING"].is_empty());
        assert_eq!(
            t.chains["N2S_BC_OUT"][0],
            [
                "-m",
                "mark",
                "--mark",
                "0x40000000/0x40000000",
                "-j",
                "RETURN"
            ]
        );
        assert_eq!(t.chains["N2S_BC_OUT"].len(), 3);
        for range in ["50000:50009", "50010:50019"] {
            for (chain, sport, dport) in [("nfqws_post", range, "443"), ("nfqws_pre", "443", range)]
            {
                for addr in ["127.0.0.1", "192.0.2.1"] {
                    assert!(t.chains[chain].iter().any(|r| r
                        == &[
                            "-p",
                            "tcp",
                            "--sport",
                            sport,
                            "--dport",
                            dport,
                            "-m",
                            "connmark",
                            "--mark",
                            "0x20000000/0x20000000",
                            "-m",
                            "conntrack",
                            "--ctorigsrc",
                            addr,
                            "-g",
                            "N2S_BC_RETURN"
                        ]));
                }
            }
        }
        assert_eq!(
            t.history.iter().rfind(|c| c[0] == "-I").unwrap()[1],
            "OUTPUT"
        );
    }
    s.close().unwrap();
    s.close().unwrap();
    let t = fake.0.borrow();
    assert_eq!(
        t.history.iter().find(|c| c[0] == "-D").unwrap()[1],
        "OUTPUT"
    );
    assert_eq!(t.chains, before);
}
#[test]
fn partial_setup_at_every_step_restores_existing_state() {
    let mut failures = 0;
    for i in 0..64 {
        let fake = Fake::router(true);
        let before = fake.0.borrow().chains.clone();
        fake.0.borrow_mut().fail_after = Some(i);
        match Sandbox::open(fake.clone(), &[(50000, 50009)]) {
            Err(_) => {
                failures += 1;
                assert_eq!(fake.0.borrow().chains, before, "step {i}");
            }
            Ok(mut s) => {
                fake.0.borrow_mut().fail_after = None;
                s.close().unwrap();
                break;
            }
        }
    }
    assert!(failures >= 14);
}
#[test]
fn verify_detects_chain_replacement_addresses_guard_order_and_rule_loss() {
    for change in 0..6 {
        let fake = Fake::router(true);
        let _s = Sandbox::open(fake.clone(), &[(50000, 50009)]).unwrap();
        let mut t = fake.0.borrow_mut();
        match change {
            0 => {
                t.addrs.remove(&Ipv4Addr::LOCALHOST);
            }
            1 => {
                t.chains.remove("nfqws_pre");
            }
            2 => t
                .chains
                .get_mut("nfqws_post")
                .unwrap()
                .insert(0, vec!["-j".into(), "EXISTING".into()]),
            3 => {
                t.chains.get_mut("N2S_BC_OUT").unwrap().pop();
            }
            4 => t.chains.get_mut("N2S_BC_OUT").unwrap().reverse(),
            _ => t
                .chains
                .get_mut("N2S_BC_RETURN")
                .unwrap()
                .push(vec!["-j".into(), "DROP".into()]),
        }
        drop(t);
        assert!(_s.verify().is_err());
    }
}
#[test]
fn recovers_reserved_chains_after_lost_parent_and_accepts_stopped_vendor() {
    for vendor in [false, true] {
        let fake = Fake::router(vendor);
        let before = fake.0.borrow().chains.clone();
        let old = Sandbox::open(fake.clone(), &[(50000, 50009)]).unwrap();
        std::mem::forget(old);
        let mut s = Sandbox::open(fake.clone(), &[(52000, 52009)]).unwrap();
        if !vendor {
            fake.0
                .borrow_mut()
                .chains
                .insert("nfqws_post".into(), vec![]);
            assert!(s.verify().is_err());
            fake.0.borrow_mut().chains.remove("nfqws_post");
        }
        s.close().unwrap();
        assert_eq!(fake.0.borrow().chains, before);
    }
}
#[test]
fn rollback_failures_are_reported_and_retry_only_the_remaining_changes() {
    let fake = Fake::router(true);
    let before = fake.0.borrow().chains.clone();
    let mut s = Sandbox::open(fake.clone(), &[(50000, 50009)]).unwrap();
    fake.0.borrow_mut().fail_after = Some(0);
    assert!(s.close().is_err());
    s.close().unwrap();
    assert_eq!(fake.0.borrow().chains, before);
}
#[test]
fn rejects_empty_and_overflowing_ranges_before_touching_firewall() {
    let fake = Fake::router(true);
    assert!(Sandbox::open(fake.clone(), &[(300, 320), (315, 325)]).is_err());
    assert!(fake.0.borrow().history.is_empty());
    let mut req = Request {
        targets: vec!["one".into(), "two".into()],
        threads: 2,
        port_base: 65500,
        ports_per_worker: 30,
        wan_ifaces: vec!["wan".into()],
    };
    assert!(req.ports().is_err());
    req.port_base = 50000;
    assert_eq!(req.ports().unwrap(), [(50000, 50029), (50030, 50059)]);
}

#[test]
fn cancellation_during_setup_removes_partial_rules_before_return() {
    let fake = Fake::router(true);
    let before = fake.0.borrow().chains.clone();
    let calls = std::cell::Cell::new(0);
    let res = Sandbox::open_with(fake.clone(), &[(50000, 50009)], || {
        calls.set(calls.get() + 1);
        if calls.get() == 4 {
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        } else {
            Ok(())
        }
    });
    assert!(res.is_err_and(|e| e.kind() == io::ErrorKind::Interrupted));
    assert_eq!(fake.0.borrow().chains, before);
}
