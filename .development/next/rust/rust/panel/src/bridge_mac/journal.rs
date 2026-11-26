use super::{
    device::{normalized, valid_name, Interface},
    format_mac, invalid, now, prefix_bytes, random_mac, receipt, saved, vendors, Config, Saved,
    Service, FILE, LIMIT, RECEIPT,
};
use nfqws2_router_command::Runner;
use nfqws2_store::{Store, Transaction};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Lease {
    name: String,
    index: u32,
    original: String,
    assigned: String,
}
type Leases = BTreeMap<String, Lease>;

#[derive(Clone, Serialize, Deserialize)]
struct Mutation {
    name: String,
    index: u32,
    original: String,
    before: String,
    after: String,
}
impl Mutation {
    fn destination(&self, undo: bool) -> &str {
        if undo {
            &self.before
        } else {
            &self.after
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Pending {
    config: Config,
    ops: Vec<Mutation>,
    next: Leases,
    #[serde(default)]
    legacy: bool,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(from = "Stored")]
pub(super) struct Receipt {
    pub leases: Leases,
    pub pending: Option<Pending>,
}

#[derive(Deserialize)]
struct OldPending {
    name: String,
    index: u32,
    before: String,
    after: String,
    config: Config,
    next: Option<Lease>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum PersistedPending {
    Batch(Pending),
    Single(OldPending),
}
#[derive(Default, Deserialize)]
struct Stored {
    #[serde(default)]
    leases: Leases,
    lease: Option<Lease>,
    pending: Option<PersistedPending>,
}
impl From<Stored> for Receipt {
    fn from(stored: Stored) -> Self {
        let mut leases = stored.leases;
        if let Some(l) = stored.lease {
            leases.insert(l.name.clone(), l);
        }
        let pending = stored.pending.map(|p| match p {
            PersistedPending::Batch(batch) => batch,
            PersistedPending::Single(op) => {
                let original = op
                    .next
                    .as_ref()
                    .or_else(|| leases.get(&op.name))
                    .map_or_else(|| op.before.clone(), |l| l.original.clone());
                let next = op.next.into_iter().map(|l| (l.name.clone(), l)).collect();
                Pending {
                    config: op.config,
                    ops: vec![Mutation {
                        name: op.name,
                        index: op.index,
                        before: op.before,
                        after: op.after,
                        original,
                    }],
                    next,
                    legacy: true,
                }
            }
        });
        Self { leases, pending }
    }
}
pub(super) enum Change {
    Config(Config),
    Enable(bool),
}

fn target<'a>(all: &'a [Interface], name: &str, index: u32) -> io::Result<&'a Interface> {
    all.iter()
        .find(|i| i.suggested && i.name == name && i.index == index)
        .ok_or_else(|| invalid("Сохранённый LAN-мост недоступен или изменился"))
}
fn originals(leases: &Leases) -> BTreeMap<String, String> {
    leases
        .iter()
        .map(|(name, l)| (name.clone(), l.original.clone()))
        .collect()
}
fn prepare(mut cfg: Config) -> io::Result<Config> {
    cfg.vendor_id = cfg.vendor_id.trim().to_owned();
    if cfg.vendor_id.is_empty() || cfg.vendor_id == "local" {
        cfg.vendor_id = "custom".into();
    }
    cfg.prefix = if cfg.prefix.trim().is_empty() {
        vendors::first(&cfg.vendor_id).unwrap_or_default().into()
    } else {
        let prefix = format_mac(&prefix_bytes(&cfg.prefix)?);
        if !vendors::matches(&cfg.vendor_id, &prefix) {
            cfg.vendor_id = "custom".into();
        }
        prefix
    };
    for name in &mut cfg.ifaces {
        *name = name.trim().to_owned();
        if !valid_name(name) {
            return Err(invalid("Недопустимое имя LAN-моста"));
        }
    }
    cfg.ifaces.sort();
    cfg.ifaces.dedup();
    cfg.mac = match cfg.mac.trim() {
        "" if cfg.enabled && !cfg.prefix.is_empty() => random_mac(&cfg.prefix)?,
        "" if cfg.enabled => return Err(invalid("Укажите MAC или префикс производителя")),
        "" => String::new(),
        raw => normalized(raw).ok_or_else(|| invalid("Нужен корректный индивидуальный MAC"))?,
    };
    Ok(cfg)
}

impl<R: Runner> Service<R> {
    fn adopt_go(
        &self,
        tx: &Transaction<'_>,
        snapshot: &Saved,
        local: &mut Receipt,
        all: &[Interface],
    ) -> io::Result<()> {
        if !local.leases.is_empty() {
            if !snapshot.config.enabled
                || local
                    .leases
                    .values()
                    .any(|l| !l.assigned.eq_ignore_ascii_case(&snapshot.config.mac))
                || (!snapshot.original_macs.is_empty()
                    && originals(&local.leases) != snapshot.original_macs)
            {
                return Err(invalid(
                    "Сохранённый профиль отличается от журнала LAN-мостов",
                ));
            }
            return Ok(());
        }
        if snapshot.original_macs.is_empty() && !snapshot.config.enabled {
            return Ok(());
        }
        let assigned = normalized(&snapshot.config.mac)
            .ok_or_else(|| invalid("Не подтверждён прежний профиль LAN-мостов"))?;
        if !snapshot.config.enabled || snapshot.original_macs.is_empty() {
            return Err(invalid(
                "Не подтверждены исходные адреса прежнего профиля LAN-мостов",
            ));
        }
        let mut leases = Leases::new();
        for (name, original) in &snapshot.original_macs {
            let bridge = all
                .iter()
                .find(|i| i.suggested && i.name == *name)
                .ok_or_else(|| invalid("Прежний профиль содержит недоступный LAN-мост"))?;
            let original = normalized(original)
                .ok_or_else(|| invalid("Не подтверждён исходный MAC LAN-моста"))?;
            let current = self.device.current(bridge)?;
            if original == assigned || (current != assigned && current != original) {
                return Err(invalid("Действующий MAC отличается от прежнего профиля"));
            }
            leases.insert(
                name.clone(),
                Lease {
                    name: name.clone(),
                    index: bridge.index,
                    original,
                    assigned: assigned.clone(),
                },
            );
        }
        local.leases = leases;
        tx.save_runtime_bounded(RECEIPT, local, LIMIT)
    }

    fn plan(&self, cfg: &Config, all: &[Interface], previous: &Leases) -> io::Result<Pending> {
        let mut selected: BTreeSet<&str> = BTreeSet::new();
        if cfg.enabled {
            if cfg.ifaces.is_empty() {
                selected.extend(all.iter().filter(|i| i.suggested).map(|i| i.name.as_str()));
            } else {
                for name in &cfg.ifaces {
                    selected.insert(self.device.selected(all, name)?.name.as_str());
                }
            }
            if selected.is_empty() {
                return Err(invalid("Не найден активный LAN-мост"));
            }
        }
        let mut names = selected.clone();
        names.extend(previous.keys().map(String::as_str));
        let mut ops = Vec::with_capacity(names.len());
        let mut next = Leases::new();
        for name in names {
            let prior = previous.get(name);
            let bridge = if let Some(l) = prior {
                target(all, name, l.index)?
            } else {
                all.iter()
                    .find(|i| i.suggested && i.name == name)
                    .ok_or_else(|| invalid("Цель должна быть активным LAN-мостом"))?
            };
            let before = self.device.current(bridge)?;
            if prior.is_some_and(|l| before != l.assigned && before != l.original) {
                return Err(invalid("Действующий MAC не совпадает с локальным журналом"));
            }
            let original = prior.map_or_else(|| before.clone(), |l| l.original.clone());
            let after = if selected.contains(name) {
                if original == cfg.mac {
                    return Err(invalid("Выберите MAC, отличный от исходного"));
                }
                next.insert(
                    name.to_owned(),
                    Lease {
                        name: name.to_owned(),
                        index: bridge.index,
                        original: original.clone(),
                        assigned: cfg.mac.clone(),
                    },
                );
                cfg.mac.clone()
            } else {
                original.clone()
            };
            ops.push(Mutation {
                name: name.to_owned(),
                index: bridge.index,
                original,
                before,
                after,
            });
        }
        ops.sort_by_key(|op| next.contains_key(&op.name));
        Ok(Pending {
            config: cfg.clone(),
            ops,
            next,
            legacy: false,
        })
    }

    fn check(
        &self,
        all: &[Interface],
        batch: &Pending,
        op: &Mutation,
        undo: bool,
        apply: bool,
    ) -> io::Result<()> {
        let bridge = target(all, &op.name, op.index)?;
        let (kernel, native) = self.device.observed(bridge)?;
        if std::iter::once(&kernel)
            .chain(native.as_ref())
            .any(|mac| mac != &op.before && mac != &op.after)
        {
            return Err(invalid("MAC моста изменён другим владельцем"));
        }
        let to = op.destination(undo);
        let done = kernel == to && native.as_ref().is_none_or(|m| m == to);
        // An untouched operation requires no compensation, including when a new neighbour
        // claimed the proposed address between validation and execution.
        if undo && done {
            return Ok(());
        }
        let restoring = to == op.original;
        let mut group = BTreeSet::new();
        for member in &batch.ops {
            if member.destination(undo) == to && member.name != op.name {
                if (member.original == to) != restoring {
                    return Err(invalid(
                        "Исходный MAC пересекается с назначением на другом мосту",
                    ));
                }
                let other = target(all, &member.name, member.index)?;
                let (other_kernel, other_native) = self.device.observed(other)?;
                if std::iter::once(&other_kernel)
                    .chain(other_native.as_ref())
                    .any(|m| m != &member.before && m != &member.after)
                {
                    return Err(invalid("MAC другого LAN-моста изменён извне"));
                }
                group.insert(member.name.as_str());
            }
        }
        self.device.unused(to, bridge, all, restoring, &group)?;
        if apply && !done {
            self.device.set(bridge, to)?;
        }
        Ok(())
    }
    fn transition(&self, wan: &[String], batch: &Pending, undo: bool) -> io::Result<()> {
        if undo {
            let mut first = None;
            for op in batch.ops.iter().rev() {
                let result = self
                    .device
                    .interfaces(wan)
                    .and_then(|all| self.check(&all, batch, op, true, true));
                if let Err(e) = result {
                    first.get_or_insert(e);
                }
            }
            if let Some(e) = first {
                return Err(e);
            }
        } else {
            for op in &batch.ops {
                self.check(&self.device.interfaces(wan)?, batch, op, false, true)?;
            }
        }
        Ok(())
    }
    fn recover_pending(
        &self,
        tx: &Transaction<'_>,
        snapshot: &Saved,
        local: &mut Receipt,
        wan: &[String],
    ) -> io::Result<()> {
        let Some(batch) = &local.pending else {
            return Ok(());
        };
        let committed = batch.config == snapshot.config
            && (batch.legacy || snapshot.original_macs == originals(&batch.next));
        self.transition(wan, batch, !committed)?;
        if committed {
            local.leases = batch.next.clone();
        }
        local.pending = None;
        tx.save_runtime_bounded(RECEIPT, local, LIMIT)
    }
    pub(super) fn change(&self, store: &Store, wan: &[String], change: Change) -> io::Result<()> {
        store.transaction(|tx| self.reconcile(store, tx, wan, Some(change)))
    }
    pub(super) fn restore(&self, store: &Store, wan: &[String]) -> io::Result<()> {
        let local = receipt(store)?;
        if local.leases.is_empty() && local.pending.is_none() && !saved(store)?.config.enabled {
            return Ok(());
        }
        store.transaction(|tx| self.reconcile(store, tx, wan, None))
    }
    fn reconcile(
        &self,
        store: &Store,
        tx: &Transaction<'_>,
        wan: &[String],
        change: Option<Change>,
    ) -> io::Result<()> {
        let mut snapshot = saved(store)?;
        let mut local = receipt(store)?;
        self.recover_pending(tx, &snapshot, &mut local, wan)?;
        let explicit = change.is_some();
        let mut cfg = match change {
            Some(Change::Config(cfg)) => prepare(cfg)?,
            Some(Change::Enable(enabled)) => prepare(Config {
                enabled,
                ..snapshot.config.clone()
            })?,
            None => snapshot.config.clone(),
        };
        // A steady-state refresh never advances the config timestamp or rewrites flash.
        if explicit {
            cfg.updated_at = now();
        }
        if !snapshot.config.enabled
            && local.leases.is_empty()
            && snapshot.original_macs.is_empty()
            && !cfg.enabled
        {
            if explicit {
                snapshot.config = cfg;
                snapshot.last_error.clear();
                tx.save(FILE, &snapshot)?;
            }
            return Ok(());
        }
        let mut all = self.device.interfaces(wan)?;
        self.adopt_go(tx, &snapshot, &mut local, &all)?;
        if cfg.enabled {
            cfg.mac =
                normalized(&cfg.mac).ok_or_else(|| invalid("Некорректный сохранённый MAC"))?;
        }
        let batch = self.plan(&cfg, &all, &local.leases)?;
        if !explicit
            && batch.next == local.leases
            && batch.ops.iter().all(|op| op.before == op.after)
        {
            return Ok(());
        }
        for op in &batch.ops {
            self.check(&all, &batch, op, false, false)?;
            // A released bridge stops owning its previous MAC before the next
            // assignment. Simulate that order during preflight only. Actual writes
            // always enumerate the interfaces again.
            let bridge = all.iter_mut().find(|i| i.name == op.name).unwrap();
            bridge.mac.clone_from(&op.after);
        }
        let next = batch.next.clone();
        // Both legs of every transition and its inverse are durable before the first MAC changes.
        local.pending = Some(batch);
        tx.save_runtime_bounded(RECEIPT, &local, LIMIT)?;
        let result = self
            .transition(wan, local.pending.as_ref().unwrap(), false)
            .and_then(|()| {
                snapshot.config = cfg;
                snapshot.original_macs = originals(&next);
                snapshot.applied_at = now();
                snapshot.last_error.clear();
                tx.save(FILE, &snapshot)
            });
        if let Err(e) = result {
            self.recover_pending(tx, &saved(store)?, &mut local, wan)?;
            return Err(e);
        }
        local.leases = next;
        local.pending = None;
        tx.save_runtime_bounded(RECEIPT, &local, LIMIT)
    }
}
