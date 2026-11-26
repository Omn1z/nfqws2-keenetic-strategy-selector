use super::{err, implicit_multi, plan, policy, Plan, Value};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io};

/// Attested Go IPv4 blanket without a carrier. The saved Kill Switch
/// determines whether the disconnected path is blocked or uses WAN.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Parked {
    primary: String,
    reserve: String,
    interfaces: [String; 2],
    pub(super) slot: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unguarded: bool,
}

impl Parked {
    pub(super) fn read(doc: &Value, plan: &Plan) -> io::Result<Self> {
        let fail = || err("не подтверждена остановленная политика полного туннеля AWG2_MULTI");
        if !plan.go_ipv4
            || plan.legacy_full.is_some()
            || plan.firewall != plan::Backend::Legacy
            || plan.go_multi_v6_reject.is_some()
            || plan.full_endpoints.is_none()
            || plan.targets.len() != 2
            || plan.has_protection() != plan.killswitch
        {
            return Err(fail());
        }
        let current = policy::current(doc)?;
        let zone = implicit_multi::zone(doc, &current).ok_or_else(fail)?;
        let rows = doc["servers"].as_array().ok_or_else(fail)?;
        let slot = rows
            .iter()
            .position(|row| row["id"] == zone.tunnel_id)
            .ok_or_else(fail)?
            + 1;
        if rows.iter().any(|row| {
            row["config"]["enabled"] != true || row["config"]["client"]["enabled"] != true
        }) || (rows[slot - 1]["config"]["routing"]["killswitch"] == true) != plan.killswitch
        {
            return Err(fail());
        }
        let (selector, primary) = plan.flows().next().ok_or_else(fail)?;
        let [reserve] = plan.reserves_for(selector) else {
            return Err(fail());
        };
        let reserve_id = &plan.targets.get(reserve).ok_or_else(fail)?.id;
        if plan.flows().count() != 1
            || selector.dest != plan::Family::V4.any()
            || selector.source != plan::Family::V4.any()
            || plan
                .targets
                .get(primary)
                .is_none_or(|target| target.id != zone.tunnel_id)
            || zone.fallback_tunnel_ids != [reserve_id.as_str()]
        {
            return Err(fail());
        }
        Ok(Self {
            primary: zone.tunnel_id,
            reserve: reserve_id.clone(),
            interfaces: [primary.to_owned(), reserve.clone()],
            slot,
            unguarded: !plan.killswitch,
        })
    }

    pub(super) fn guarded(&self) -> bool {
        !self.unguarded
    }

    pub(super) fn trial_plan(&self, intent: &Plan) -> Plan {
        if self.guarded() {
            return intent.guards_only();
        }
        let mut offline = intent.clone();
        offline.dns_bridges.clear();
        offline.mss.clear();
        let selectors: Vec<_> = offline.flows().map(|(selector, _)| selector).collect();
        offline.park(&selectors);
        offline
    }

    pub(super) fn verify_empty_tables(&self, k: &crate::kernel::Kernel<'_>) -> io::Result<()> {
        if self.guarded() {
            return Ok(());
        }
        let rows = k.listing(plan::Family::V4, &["route", "show", "table", "all"])?;
        if rows.lines().any(|row| {
            row.split_ascii_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|fields| {
                    fields[0] == "table"
                        && fields[1]
                            .parse::<u16>()
                            .is_ok_and(|table| matches!(table, 900..=964))
                })
        }) {
            return Err(err("в таблице отключённого туннеля Go остался маршрут"));
        }
        Ok(())
    }

    pub(super) fn links_absent(&self, k: &crate::kernel::Kernel<'_>) -> io::Result<bool> {
        let links = crate::kernel::routed_disable::link_names(k)?;
        Ok(self.interfaces.iter().all(|iface| !links.contains(iface)))
    }

    pub(super) fn verify_absent(&self, k: &crate::kernel::Kernel<'_>) -> io::Result<()> {
        if !self.links_absent(k)? {
            return Err(err(
                "интерфейс AWG появился после проверки отсутствующего туннеля",
            ));
        }
        implicit_multi::verify_ipv6(k)?;
        self.verify_empty_tables(k)
    }

    pub(super) fn restored_slots(
        &self,
        k: &crate::kernel::Kernel<'_>,
        selected: &super::GoActionRoute,
        connected: &BTreeSet<String>,
    ) -> io::Result<Vec<(&str, &str)>> {
        let invalid = || err("не подтверждены защищённые маршруты восстановленного туннеля Go");
        if !self.guarded()
            || self.verify_rules(k, true)? != [true, true]
            || connected
                .iter()
                .any(|id| id != &self.primary && id != &self.reserve)
            || (selected.slot != self.slot && selected.slot != 3 - self.slot)
            || (connected.is_empty() && selected.slot != self.slot)
        {
            return Err(invalid());
        }
        implicit_multi::verify_ipv6(k)?;
        let links = crate::kernel::routed_disable::link_names(k)?;
        let mut owners = Vec::new();
        for (slot, id, iface) in [
            (
                self.slot,
                self.primary.as_str(),
                self.interfaces[0].as_str(),
            ),
            (
                3 - self.slot,
                self.reserve.as_str(),
                self.interfaces[1].as_str(),
            ),
        ] {
            let route = super::go_slot_route(k, slot)?;
            let present = links.contains(iface);
            let fresh = connected.contains(id);
            if !route.fence
                || route.dev.as_deref() != present.then_some(iface)
                || fresh && !present
                || (slot == selected.slot
                    && ((!connected.is_empty() && !fresh)
                        || route.dev != selected.dev
                        || !selected.fence))
            {
                return Err(invalid());
            }
            if present {
                owners.push((id, iface));
            }
        }
        Ok(owners)
    }

    pub(super) fn verify_rules(
        &self,
        k: &crate::kernel::Kernel<'_>,
        armed: bool,
    ) -> io::Result<[bool; 2]> {
        let fail = || err("не подтверждён порядок правил остановленного полного туннеля Go");
        // Any other earlier selector may bypass the observed Go blackhole.
        let mut owned = [false; 2];
        let mut local = false;
        for row in k.listing(plan::Family::V4, &["rule", "show"])?.lines() {
            let words: Vec<_> = row.split_ascii_whitespace().collect();
            match words.as_slice() {
                ["0:", "from", "all", "lookup", "local" | "255"] if !local => local = true,
                ["32766:", "from", "all", "lookup", "main" | "254"]
                | ["32767:", "from", "all", "lookup", "default" | "253"] => (),
                ["67:", "from", "all", "lookup", "main" | "254", "suppress_prefixlength", "0"]
                | ["68:", "from", "all", "fwmark", "0/0x20000000" | "0x0/0x20000000", "lookup", "17842"]
                    if armed && self.guarded() => {}
                [pref, "from", "all", "fwmark", mark, "lookup", table] => {
                    let slot = match (*pref, *mark, *table) {
                        ("71:", "0x10100000/0x1ff00000", "901") => 0,
                        ("72:", "0x10200000/0x1ff00000", "902") => 1,
                        _ => return Err(fail()),
                    };
                    if std::mem::replace(&mut owned[slot], true) {
                        return Err(fail());
                    }
                }
                _ => return Err(fail()),
            }
        }
        if !local || !(1..=2).contains(&self.slot) || !owned[self.slot - 1] {
            return Err(fail());
        }
        Ok(owned)
    }
}
