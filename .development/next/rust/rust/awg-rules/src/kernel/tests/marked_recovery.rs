use super::*;
use crate::kernel::{marked, plan::Family};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub(in crate::kernel::tests) struct ProtectedRouter {
    pub(in crate::kernel::tests) router: Router,
    fences: Mutex<BTreeSet<u16>>,
    skip_fence: AtomicBool,
    watching: AtomicBool,
}
impl ProtectedRouter {
    // Walk the actual generated PREROUTING rules and ipsets. Interface
    // deletion removes unicast routes while the independent blackhole stays.
    pub(in crate::kernel::tests) fn forward(&self, src: &str, dst: &str) -> String {
        let Some(mark) = self.router.packet_mark(src, dst) else {
            return "wan".into();
        };
        let tables = self.router.mark_tables.lock().unwrap();
        let Some(table) = tables.get(&mark) else {
            return "wan".into();
        };
        if let Some(iface) = self
            .router
            .ip
            .0
            .lock()
            .unwrap()
            .scoped_routes
            .get(&(*table, Family::V4.any()))
        {
            return iface.clone();
        }
        if self.fences.lock().unwrap().contains(table) {
            "drop".into()
        } else {
            "wan".into()
        }
    }
    fn observe(&self) {
        if self.watching.load(Ordering::Relaxed) {
            assert_ne!(
                self.forward("192.168.1.17", "77.7.0.2"),
                "wan",
                "protected packet fell through to WAN"
            );
            assert_eq!(
                self.forward("192.168.1.18", "77.7.0.2"),
                "wan",
                "unrelated LAN client captured"
            );
            assert_eq!(
                self.forward("192.168.1.17", "77.7.0.3"),
                "wan",
                "unrelated destination captured"
            );
        }
    }
}
impl Runner for ProtectedRouter {
    fn run(&self, program: &str, args: &[&str], end: Instant) -> io::Result<String> {
        let result = match (program, args) {
            (
                "ip",
                ["-4", "route", op, "blackhole", "default", "table", table, "proto", "242", "metric", "1000"],
            ) => {
                let n = table.parse::<u16>().unwrap();
                assert!((18000..=18128).contains(&n));
                if *op == "add" {
                    if !self.skip_fence.swap(false, Ordering::Relaxed) {
                        assert!(self.fences.lock().unwrap().insert(n));
                    }
                } else {
                    assert_eq!(*op, "del");
                    assert!(self.fences.lock().unwrap().remove(&n));
                }
                Ok(String::new())
            }
            ("ip", ["-o", "-N", "-4", "route", "show", "table", "all"]) => {
                let mut routes = self.router.run(program, args, end)?;
                for table in self.fences.lock().unwrap().iter() {
                    routes.push_str(&format!(
                        "\nblackhole default table {table} proto 242 metric 1000"
                    ));
                }
                Ok(routes)
            }
            _ => self.router.run(program, args, end),
        };
        self.observe();
        result
    }
    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        end: Instant,
    ) -> io::Result<String> {
        let result = self.router.run_input(program, args, input, end);
        self.observe();
        result
    }
}

#[test]
fn scoped_killswitch_survives_link_removal_and_lost_classifier_ack() {
    let (_dir, db, _) = setup();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut routing = crate::policy::current(&doc).unwrap();
    routing.killswitch = true;
    routing.zones[0].source_ips = vec!["192.168.1.17".into()];
    routing.zones[0].ips = (0..512_u32)
        .map(|i| Ipv4Addr::from(u32::from(Ipv4Addr::new(77, 7, 0, 2)) + 2 * i).to_string())
        .collect();
    let plan =
        plan::compile_effective(&doc, routing, None, false, &[], Default::default()).unwrap();
    assert!(plan.packed && !plan.marks.is_empty());
    let live = objects(&plan);
    let parked = objects(&plan.guards_only());
    let slot = plan.marks["awg0"];
    assert!(live.contains(&Object::MarkFence(Family::V4, slot)));
    assert!(
        parked.contains(&Object::MarkFence(Family::V4, 0))
            && parked.contains(&Object::MarkLookup(Family::V4, 0))
    );
    let claims = live.union(&parked).cloned().collect::<BTreeSet<_>>();
    let router = ProtectedRouter::default();
    let k = kernel(&router);
    let empty = BTreeSet::new();
    // A different client's policy coexists. A rule able to divert an
    // enrolled LAN source before its guarded table blocks acquisition.
    for (rule, compatible) in [
        ("42: from 192.168.1.18 lookup 71", true),
        ("42: from 192.168.1.17 to 77.7.0.3 lookup 71", true),
        ("42: from 192.168.1.17 to 77.7.0.2 lookup 71", false),
    ] {
        router.router.ip.0.lock().unwrap().foreign_rule = rule.into();
        assert_eq!(
            k.inventory_for(&empty, &live, true).is_ok(),
            compatible,
            "{rule}"
        );
    }
    router.router.ip.0.lock().unwrap().foreign_rule.clear();
    synchronize(&k, &empty, &live).unwrap();
    router.watching.store(true, Ordering::Relaxed);
    assert_eq!(router.forward("192.168.1.17", "77.7.0.2"), "awg0");
    router
        .router
        .ip
        .0
        .lock()
        .unwrap()
        .scoped_routes
        .remove(&(marked::table(slot), Family::V4.any()))
        .unwrap();
    assert_eq!(router.forward("192.168.1.17", "77.7.0.2"), "drop");
    let partial = k.inventory(&live, true).unwrap();
    // Simulate a command that reported success without retaining the sink.
    // Readback must leave the active classifier on its previous safe table.
    router.skip_fence.store(true, Ordering::Relaxed);
    assert!(synchronize(&k, &partial, &parked).is_err());
    assert!(router
        .router
        .classifier
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.contains(&marked::masked(slot))));
    let partial = k.inventory(&claims, false).unwrap();
    router.router.fail_switch.store(true, Ordering::Relaxed);
    assert!(synchronize(&k, &partial, &parked).is_err());
    let partial = k.inventory(&claims, false).unwrap();
    synchronize(&k, &partial, &parked).unwrap();
    assert_eq!(k.inventory(&claims, true).unwrap(), parked);
    assert_eq!(router.forward("192.168.1.17", "77.7.0.2"), "drop");
    // An administrator's higher-priority sink occupies the same table.
    // Strict acquisition blocks, recovery inventories only our exact metric
    // and protocol, and readback rejects switching traffic onto that table.
    let foreign = "blackhole default table 18000 proto 4 metric 333";
    router.router.ip.0.lock().unwrap().foreign_route = foreign.into();
    assert!(k.inventory(&claims, true).is_err());
    assert_eq!(k.inventory(&claims, false).unwrap(), parked);
    assert!(marked::fence::verify(&k, &parked).is_err());
    assert_eq!(router.router.ip.0.lock().unwrap().foreign_route, foreign);
    router.router.ip.0.lock().unwrap().foreign_route.clear();
    synchronize(&k, &parked, &live).unwrap();
    assert_eq!(k.inventory(&claims, true).unwrap(), live);
    assert_eq!(router.forward("192.168.1.17", "77.7.0.2"), "awg0");
    router.watching.store(false, Ordering::Relaxed);
    synchronize(&k, &live, &empty).unwrap();
    assert!(k.inventory(&claims, false).unwrap().is_empty());
}
