use super::{
    err, hash, implicit_multi, parked_multi::Parked, policy, Capture, PanelEndpoint, Routing,
};
use crate::kernel::{
    acceleration, boot_id, kernel, objects, synchronize, Journal, Kernel, Plan, Runner, Store,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, io};

pub(crate) const FILE: &str = "awg-go-parked-guard.json";

/// Own the native guard across both installations, independently of either
/// panel's normal route ledger. Record this exact claim before the first write.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::kernel) struct Armed {
    boot: String,
    hash: String,
    policy: Parked,
    pub(in crate::kernel) plan: Plan,
}

impl Armed {
    pub(in crate::kernel) fn read(db: &Store) -> io::Result<Option<Self>> {
        match db.read_runtime(FILE, super::MAX_SIZE) {
            Ok(record) => Ok(Some(record)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn validate(&self, db: &Store, k: &Kernel<'_>, doc: &Value) -> io::Result<()> {
        let invalid = || err("не подтверждена запись временной защиты полного туннеля AWG");
        self.plan.validate()?;
        if self.boot != boot_id(k)?
            || doc["routing_revision"].as_u64().unwrap_or_default() != self.plan.revision
            || self.hash != hash(db, doc, &policy::current(doc)?)?
            || Parked::read(doc, &self.plan)? != self.policy
            || !self.policy.guarded()
            || self.plan != self.plan.guards_only()
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn verify_go(
        &self,
        db: &Store,
        k: &Kernel<'_>,
        doc: &Value,
        port: PanelEndpoint,
        releasing: bool,
    ) -> io::Result<()> {
        self.validate(db, k, doc)?;
        let settings = policy::current(doc)?;
        let first = super::live(k.run, port, &settings, false)?;
        if !first.nested.is_empty() || !releasing && !first.connected.is_empty() {
            return Err(err("действующее подключение Go изменило временную защиту"));
        }
        let zone = implicit_multi::zone(doc, &settings)
            .ok_or_else(|| err("изменилась политика полного туннеля Go"))?;
        let mut current = crate::sources::expand(db, settings.clone())?;
        current.zones.push(zone);
        let sample = || -> io::Result<_> {
            if !releasing || (first.connected.is_empty() && self.policy.links_absent(k)?) {
                super::verify_go_parked(k.run, k, &self.plan, &current, &self.policy, true)?;
                return Ok(None);
            }
            self.restored_go_carriers(db, k, &current, &first.connected)
                .map(Some)
        };
        let routing = sample()?;
        acceleration::check_parked_handoff(db, k, true)?;
        let endpoints = self
            .plan
            .full_endpoints
            .as_ref()
            .ok_or_else(|| err("нет исключений временной защиты AWG"))?;
        k.guard(&self.plan, endpoints)?;
        if routing.is_some() && routing != sample()?
            || first != super::live(k.run, port, &settings, false)?
        {
            return Err(err(
                "поколение Go изменилось во время проверки временной защиты",
            ));
        }
        Ok(())
    }

    fn restored_go_carriers(
        &self,
        db: &Store,
        k: &Kernel<'_>,
        policy: &Routing,
        connected: &BTreeSet<String>,
    ) -> io::Result<(usize, Vec<[u8; 32]>)> {
        super::verify_go_default_mode(k.run, &self.plan, policy, |entries, action| {
            let selected = super::go_action_route(k, entries, action, None)?;
            let owners = self.policy.restored_slots(k, &selected, connected)?;
            let receipts = owners
                .into_iter()
                .map(|(id, iface)| {
                    let (owner, fresh) =
                        nfqws2_awg_profile::runtime::Runtime::prove_restored_go_carrier(
                            db, id, iface,
                        )?;
                    if fresh != connected.contains(id) {
                        return Err(err(
                            "рукопожатие восстановленного туннеля не совпало с состоянием Go",
                        ));
                    }
                    Ok(owner)
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok((selected.slot, receipts))
        })
    }

    pub(in crate::kernel) fn verify_native(
        &self,
        db: &Store,
        k: &Kernel<'_>,
        doc: &Value,
    ) -> io::Result<()> {
        self.validate(db, k, doc)?;
        implicit_multi::verify_ipv6(k)?;
        acceleration::check_parked_handoff(db, k, false)?;
        let claims = objects(&self.plan);
        if k.inventory(&claims, true)? != claims {
            return Err(err(
                "ядро не подтвердило временную защиту полного туннеля AWG",
            ));
        }
        Ok(())
    }
}

pub(super) fn finish(db: &Store, run: &dyn Runner) -> io::Result<()> {
    db.transaction(|tx| {
        let Some(armed) = Armed::read(db)? else {
            return Ok(());
        };
        let k = kernel(run);
        let doc = nfqws2_awg_profile::read(db)?;
        let journal = Journal::read(db)?;
        if journal.expires != 0
            || !journal.preparing.is_empty()
            || journal.installed.as_ref() != &armed.plan
            || journal.committed.guards_only() != armed.plan
        {
            return Err(err(
                "временная защита ещё не подтверждена новой панелью AWG",
            ));
        }
        armed.verify_native(db, &k, &doc)?;
        tx.delete_runtime(FILE)
    })
}

pub(super) fn arm(db: &Store, run: &dyn Runner, port: PanelEndpoint) -> io::Result<bool> {
    db.transaction(|tx| {
        let proof: Capture = match db.read_runtime(super::FILE, super::MAX_SIZE) {
            Ok(proof) => proof,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let Some(parked) = proof.implicit_multi_parked.as_ref() else {
            return Ok(false);
        };
        if !parked.guarded() {
            return Ok(false);
        }
        let doc = nfqws2_awg_profile::read(db)?;
        if !Journal::read(db)?.idle()
            || doc["rust_static_routing"].is_object()
            || nfqws2_awg_profile::now()
                .checked_sub(proof.created)
                .is_none_or(|age| age > super::MAX_AGE)
        {
            return Err(err(
                "временная защита требует новой проверки исходной политики Go",
            ));
        }
        let k = kernel(run);
        let intent = super::seeded(db, &doc, None, &proof)?;
        let mut guarded = intent.guards_only();
        k.select_firewall(&mut guarded)?;
        let old = Armed::read(db)?;
        let value = Armed {
            boot: proof.boot,
            hash: proof.policy_hash,
            policy: parked.clone(),
            plan: guarded,
        };
        if let Some(old) = &old {
            old.validate(db, &k, &doc)?;
            if old.plan != value.plan || old.policy != value.policy {
                return Err(err("сохранена временная защита другого поколения AWG"));
            }
        }
        value.verify_go(db, &k, &doc, port, false)?;
        let goal = objects(&value.plan);
        let claims = if old.is_some() {
            goal.clone()
        } else {
            BTreeSet::new()
        };
        let present = k.parked_guard_before_go_stop(&claims, &goal)?;
        tx.save_runtime_bounded(FILE, &value, super::MAX_SIZE)?;
        synchronize(&k, &present, &goal)?;
        if k.parked_guard_before_go_stop(&goal, &goal)? != goal {
            return Err(err("ядро не установило полную временную защиту AWG"));
        }
        value.verify_go(db, &k, &doc, port, false)?;
        Ok(true)
    })
}

/// Go has recreated its own exact data plane. Remove only the separately
/// recorded native guard, while the restored Go blackhole is still present.
pub(super) fn release(db: &Store, run: &dyn Runner, port: PanelEndpoint) -> io::Result<()> {
    db.transaction(|tx| {
        let Some(armed) = Armed::read(db)? else {
            return Ok(());
        };
        let k = kernel(run);
        if armed.boot != boot_id(&k)? {
            // Boot discarded our old kernel objects; there is nothing to delete.
            return tx.delete_runtime(FILE);
        }
        let doc = nfqws2_awg_profile::read(db)?;
        if !Journal::read(db)?.idle() {
            return Err(err("сохранена другая действующая политика AWG"));
        }
        armed.verify_go(db, &k, &doc, port, true)?;
        let claims = objects(&armed.plan);
        let empty = BTreeSet::new();
        let present = k.parked_guard_before_go_stop(&claims, &empty)?;
        let release = || -> io::Result<()> {
            synchronize(&k, &present, &empty)?;
            if !k.parked_guard_before_go_stop(&claims, &empty)?.is_empty() {
                return Err(err("не удалось снять временную защиту полного туннеля AWG"));
            }
            armed.verify_go(db, &k, &doc, port, true)
        };
        if let Err(error) = release() {
            let remaining = k.parked_guard_before_go_stop(&claims, &present)?;
            synchronize(&k, &remaining, &present)?;
            return Err(error);
        }
        tx.delete_runtime(FILE)
    })
}
