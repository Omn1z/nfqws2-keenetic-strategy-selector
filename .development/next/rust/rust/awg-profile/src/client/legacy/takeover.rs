use super::*;
use std::collections::BTreeSet;

const PENDING: &str = "awg-go-clients-pending.json";
#[cfg(target_os = "linux")]
const CONFIRMED: &str = "awg-go-clients.json";
#[cfg(target_os = "linux")]
const LIMIT: u64 = 128 * 1024;
#[cfg(target_os = "linux")]
const TRIAL_AGE: u64 = 180;

#[cfg(target_os = "linux")]
type Receipts = BTreeMap<String, linux::Receipt>;

#[cfg(target_os = "linux")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    captured: u64,
    clients: Receipts,
}

#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PendingFile {
    Staged(Staged),
    Legacy(Receipts),
}

impl Runtime {
    /// Verify the serving Go process and independently report handshake readiness.
    pub fn prove_restored_go_carrier(
        db: &Store,
        id: &str,
        iface: &str,
    ) -> io::Result<([u8; 32], bool)> {
        #[cfg(target_os = "linux")]
        {
            let root = std::path::Path::new("/");
            let runtime = Self::new(root, root.join("opt/usr/bin/amneziawg-go"));
            let doc = read(db)?;
            let row = find(&doc, id)?;
            if !wanted(row) || !row["applied_config"].is_null() {
                return Err(invalid("не подтверждён восстановленный прямой туннель Go"));
            }
            let spec = saved_specification(&doc, row, false)?;
            if spec.iface != iface {
                return Err(invalid(
                    "не подтверждён интерфейс восстановленного туннеля Go",
                ));
            }
            linux::Inherited::observe_direct_carrier(&runtime, &spec, &row["config"])
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (db, id, iface);
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// Capture the exact live clients the Go panel and routing trial both observed.
    pub fn stage_go_clients(
        db: &Store,
        direct: &BTreeSet<String>,
        nested: &BTreeSet<String>,
    ) -> io::Result<()> {
        Self::stage_go_clients_inner(db, direct, nested, false)
    }

    /// Check exact owners when the upgrade will not run a routing trial.
    pub fn stage_go_clients_only(
        db: &Store,
        direct: &BTreeSet<String>,
        nested: &BTreeSet<String>,
    ) -> io::Result<()> {
        Self::stage_go_clients_inner(db, direct, nested, true)
    }

    fn stage_go_clients_inner(
        db: &Store,
        direct: &BTreeSet<String>,
        nested: &BTreeSet<String>,
        verify_all_direct: bool,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let root = std::path::Path::new("/");
            let runtime = Self::new(root, root.join("opt/usr/bin/amneziawg-go"));
            let doc = read(db)?;
            let graph = (!nested.is_empty())
                .then(|| super::super::failover::Graph::load(&doc))
                .transpose()?;
            let mut receipts = BTreeMap::new();
            for id in direct {
                let row = find(&doc, id)?;
                if !wanted(row) {
                    if verify_all_direct {
                        return Err(invalid("не подтверждён действующий прямой туннель Go"));
                    }
                    continue;
                }
                match saved_specification(&doc, row, false)
                    .and_then(|spec| linux::capture(&runtime, &spec))
                {
                    Ok(receipt) => {
                        receipts.insert(id.clone(), receipt);
                    }
                    Err(error) if verify_all_direct => return Err(error),
                    Err(_) => {}
                }
            }
            for id in nested {
                let unavailable = || invalid("не подтверждён действующий вложенный туннель Go");
                let row = find(&doc, id)?;
                let (outer, _) = graph
                    .as_ref()
                    .and_then(|graph| graph.nested(id))
                    .ok_or_else(unavailable)?;
                if !wanted(row) || !direct.contains(outer) {
                    return Err(unavailable());
                }
                let inner = saved_specification(&doc, row, false)?;
                let outer = saved_specification(&doc, find(&doc, outer)?, false)?;
                let receipt = linux::capture_nested(&runtime, &inner, &outer)?;
                receipts.insert(id.clone(), receipt);
            }
            let staged = Staged {
                captured: crate::now(),
                clients: receipts,
            };
            db.transaction(|tx| tx.save_runtime_bounded(PENDING, &staged, LIMIT))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (direct, nested, verify_all_direct);
            db.transaction(|tx| tx.delete_runtime(PENDING))
        }
    }

    /// Called only after the installer's end-to-end routing trial has been committed.
    pub fn confirm_go_clients(db: &Store) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            db.transaction(|tx| {
                let receipts = match db.read_runtime(PENDING, LIMIT)? {
                    PendingFile::Staged(staged) => staged.clients,
                    PendingFile::Legacy(receipts) => receipts,
                };
                tx.save_runtime_bounded(CONFIRMED, &receipts, LIMIT)?;
                tx.delete_runtime(PENDING)
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            db.transaction(|tx| tx.delete_runtime(PENDING))
        }
    }
}

#[cfg(target_os = "linux")]
fn trial_receipts(db: &Store) -> io::Result<Option<Receipts>> {
    match db.read_runtime(PENDING, LIMIT) {
        Ok(PendingFile::Staged(staged))
            if crate::now()
                .checked_sub(staged.captured)
                .is_some_and(|age| age <= TRIAL_AGE) =>
        {
            Ok(Some(staged.clients))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn trial_in_progress(db: &Store) -> bool {
    trial_receipts(db).is_ok_and(|clients| clients.is_some())
}

impl Runtime {
    /// A prepared Go client may be observed before installation commits.
    pub fn go_nested_trial_peer(
        &self,
        db: &Store,
        config: &Value,
        iface: &str,
    ) -> io::Result<Option<(Vec<String>, super::super::settings::RoutedNestedTransport)>> {
        #[cfg(target_os = "linux")]
        {
            let Some(clients) = trial_receipts(db)? else {
                return Ok(None);
            };
            self.observe_go_nested(db, config, iface, clients, true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (db, config, iface);
            Ok(None)
        }
    }

    /// Keep a confirmed handoff routable while the watchdog acquires ownership.
    pub fn go_nested_confirmed_peer(
        &self,
        db: &Store,
        config: &Value,
        iface: &str,
    ) -> io::Result<Option<(Vec<String>, super::super::settings::RoutedNestedTransport)>> {
        #[cfg(target_os = "linux")]
        {
            let clients = match db.read_runtime(CONFIRMED, LIMIT) {
                Ok(clients) => clients,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            self.observe_go_nested(db, config, iface, clients, false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (db, config, iface);
            Ok(None)
        }
    }

    #[cfg(target_os = "linux")]
    fn observe_go_nested(
        &self,
        db: &Store,
        config: &Value,
        iface: &str,
        clients: Receipts,
        trial: bool,
    ) -> io::Result<Option<(Vec<String>, super::super::settings::RoutedNestedTransport)>> {
        let Some((id, receipt)) = clients
            .into_iter()
            .find(|(_, receipt)| receipt.nested_iface_is(iface))
        else {
            return Ok(None);
        };
        let doc = read(db)?;
        let Ok(row) = find(&doc, &id) else {
            return Ok(None);
        };
        if !wanted(row) || config != wire(row) {
            return Ok(None);
        }
        let spec = saved_specification(&doc, row, false)?;
        let graph = super::super::failover::Graph::load(&doc)?;
        let (outer_id, _) = graph
            .nested(&id)
            .ok_or_else(|| invalid("нет внешнего профиля вложенного туннеля Go"))?;
        let outer = saved_specification(&doc, find(&doc, outer_id)?, false)?;
        let identity = expected_identity(&spec)
            .ok_or_else(|| invalid("нет ключей действующего вложенного туннеля Go"))?;
        let (mut allowed, transport) = linux::Inherited::observe_nested(
            self, &spec, &outer, config, receipt, identity, trial,
        )?;
        if allowed.iter().any(|net| net.contains(':')) && !self.has_usable_ipv6(iface) {
            allowed.retain(|net| !net.contains(':'));
        }
        Ok(Some((allowed, transport)))
    }

    /// Check each original Go transport at the installer commit boundary.
    pub fn verify_go_nested_trial(&self, db: &Store, ids: &BTreeSet<String>) -> io::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let doc = read(db)?;
        for id in ids {
            let row = find(&doc, id)?;
            if self
                .go_nested_trial_peer(db, wire(row), &iface(row, &doc)?)?
                .is_none()
            {
                return Err(invalid(
                    "действующий вложенный туннель Go изменился во время обновления",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_go_clients_only(
        &self,
        db: &Store,
        connected: &BTreeSet<String>,
        nested: &BTreeSet<String>,
    ) -> io::Result<()> {
        self.verify_go_nested_trial(db, nested)?;
        #[cfg(target_os = "linux")]
        {
            let missing = || invalid("действующий прямой туннель Go изменился во время обновления");
            let mut receipts = trial_receipts(db)?.ok_or_else(missing)?;
            let doc = read(db)?;
            for id in connected.difference(nested) {
                let row = find(&doc, id)?;
                if !wanted(row) {
                    return Err(missing());
                }
                let spec = saved_specification(&doc, row, false)?;
                let receipt = receipts.remove(id).ok_or_else(missing)?;
                if receipt.nested_iface_is(&spec.iface) {
                    return Err(missing());
                }
                let identity = expected_identity(&spec).ok_or_else(missing)?;
                let peer = linux::Inherited::bind(self, &spec, receipt, identity)?;
                if peer.snapshot()?["connected"] != true {
                    return Err(missing());
                }
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = connected;
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn retire_disabled(
    runtime: &Runtime,
    db: &Store,
    doc: &Value,
    row: &Value,
) -> io::Result<()> {
    let mut receipts: Receipts = match db.read_runtime(CONFIRMED, LIMIT) {
        Ok(records) => records,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(receipt) = receipts.remove(s(row, "id")) else {
        return Ok(());
    };
    let spec = Runtime::spec_for_release(doc, row)?;
    linux::Inherited::retire_disabled(runtime, &spec, receipt)
}

#[cfg(target_os = "linux")]
pub(super) fn retire_vacant(runtime: &Runtime, db: &Store, spec: &Spec) -> io::Result<()> {
    let mut receipts: BTreeMap<String, linux::Receipt> = match db.read_runtime(CONFIRMED, LIMIT) {
        Ok(records) => records,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if let Some(receipt) = receipts.remove(&spec.id) {
        linux::Inherited::retire_vacant(runtime, spec, receipt)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn confirmed(
    runtime: &Runtime,
    db: &Store,
    spec: &Spec,
    identity: [u8; 32],
) -> Option<Box<dyn Tunnel>> {
    let mut receipts: BTreeMap<String, linux::Receipt> = db.read_runtime(CONFIRMED, LIMIT).ok()?;
    let receipt = receipts.remove(&spec.id)?;
    let engine = linux::Inherited::bind(runtime, spec, receipt, identity).ok()?;
    Some(Box::new(engine))
}

#[cfg(target_os = "linux")]
pub(super) fn replay(
    runtime: &Runtime,
    db: &Store,
    spec: &Spec,
    seal: [u8; 32],
) -> io::Result<Option<Box<dyn Tunnel>>> {
    let mut receipts: BTreeMap<String, linux::Receipt> = db.read_runtime(CONFIRMED, LIMIT)?;
    let receipt = receipts.remove(&spec.id).ok_or(io::ErrorKind::WouldBlock)?;
    let identity = expected_identity(spec).ok_or(io::ErrorKind::WouldBlock)?;
    Ok(
        linux::Inherited::replay(runtime, spec, receipt, identity, seal)?
            .map(|owner| Box::new(owner) as Box<dyn Tunnel>),
    )
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(in crate::client) use linux::{process_start, start_time, SignalTarget};
