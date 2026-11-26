use super::*;
use serde::{de, Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Default)]
pub struct Failover {
    pub fallback_tunnel_ids: Vec<String>,
    pub standby: bool,
    pub double_tunnel_id: Option<String>,
    pub double_tunnel_mode: Option<String>,
}

impl<'de> Deserialize<'de> for Failover {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReadFailover;
        impl<'de> de::Visitor<'de> for ReadFailover {
            type Value = Failover;

            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("an AWG failover configuration")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Failover::default())
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut fields: M) -> Result<Self::Value, M::Error> {
                let mut request = Failover::default();
                while let Some(mut field) = fields.next_key::<String>()? {
                    if !field.is_ascii() {
                        // These two Unicode case folds can match ASCII JSON tags in Go.
                        field = field.replace('ſ', "s").replace('K', "k");
                    }
                    field.make_ascii_lowercase();
                    match field.as_str() {
                        "fallback_tunnel_ids" => {
                            request.fallback_tunnel_ids = fields
                                .next_value::<Option<Vec<Option<String>>>>()?
                                .unwrap_or_default()
                                .into_iter()
                                .map(Option::unwrap_or_default)
                                .collect();
                        }
                        "standby" => {
                            if let Some(standby) = fields.next_value()? {
                                request.standby = standby;
                            }
                        }
                        "double_tunnel_id" => request.double_tunnel_id = fields.next_value()?,
                        "double_tunnel_mode" => request.double_tunnel_mode = fields.next_value()?,
                        _ => {
                            let _: de::IgnoredAny = fields.next_value()?;
                        }
                    }
                }
                Ok(request)
            }
        }
        deserializer.deserialize_any(ReadFailover)
    }
}

impl Failover {
    fn backups(&self, primary: &str) -> io::Result<Vec<&str>> {
        let mut backups = Vec::new();
        let mut seen = BTreeSet::new();
        for id in self.fallback_tunnel_ids.iter().map(|id| id.trim()) {
            if id == primary {
                return Err(invalid("подключение не может быть резервом для самого себя"));
            }
            if !id.is_empty() && seen.insert(id) {
                backups.push(id);
            }
        }
        Ok(backups)
    }

    fn validate_mode(&self) -> io::Result<()> {
        if self.double_tunnel_mode.as_deref().is_some_and(|mode| {
            !matches!(mode, "automatic" | "preferred" | "permanent" | "last_resort")
        }) {
            return Err(invalid("неизвестный режим двойного туннеля"));
        }
        Ok(())
    }
}
struct Node<'a> {
    row: &'a Value,
    backups: Vec<&'a str>,
    outer: Option<&'a str>,
    mode: &'a str,
    standby: bool,
    enabled: bool,
}
pub struct Graph<'a>(BTreeMap<&'a str, Node<'a>>);
fn configured(doc: &Value) -> bool {
    doc["servers"].as_array().into_iter().flatten().any(|row| {
        let c = &row["config"]["client"];
        !s(c, "double_tunnel_id").is_empty()
            || c["double_tunnel_mode"] == "permanent"
            || c["standby"] == true
            || c["fallback_tunnel_ids"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
    })
}
impl<'a> Graph<'a> {
    pub fn load(doc: &'a Value) -> io::Result<Self> {
        Self::load_with_dangling(doc, false)
    }
    pub(super) fn validate_replacement(doc: &'a Value) -> io::Result<()> {
        Self::load_with_dangling(doc, true).map(|_| ())
    }
    fn load_with_dangling(doc: &'a Value, allow_dangling: bool) -> io::Result<Self> {
        let rows = doc["servers"]
            .as_array()
            .ok_or_else(|| invalid("нет списка подключений"))?;
        if rows.len() > 128 {
            return Err(invalid(
                "для резервирования поддерживается до 128 подключений",
            ));
        }
        let known = |id: &str| !allow_dangling || rows.iter().any(|row| row["id"] == id);
        let mut nodes = BTreeMap::new();
        for row in rows {
            let c = &row["config"]["client"];
            let mut backups = Vec::new();
            let mut seen = BTreeSet::new();
            if !c["fallback_tunnel_ids"].is_null() {
                let list = c["fallback_tunnel_ids"]
                    .as_array()
                    .ok_or_else(|| invalid("неверный список резервов"))?;
                for v in list {
                    let id = v
                        .as_str()
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| invalid("неверный идентификатор резерва"))?;
                    if known(id) && seen.insert(id) {
                        backups.push(id);
                    }
                }
            }
            let id = s(row, "id");
            if id.is_empty() || nodes.contains_key(id) {
                return Err(invalid(
                    "пустой или повторяющийся идентификатор подключения",
                ));
            }
            let outer = c["double_tunnel_id"]
                .as_str()
                .filter(|id| !id.is_empty() && known(id));
            let mode = match s(c, "double_tunnel_mode") {
                m @ ("automatic" | "preferred" | "permanent") => m,
                _ => "last_resort",
            };
            nodes.insert(
                id,
                Node {
                    row,
                    backups,
                    outer,
                    mode,
                    standby: c["standby"] == true,
                    enabled: row["config"]["enabled"] == true
                        && c["enabled"] == true
                        && c["rust_managed"] == true,
                },
            );
        }
        let graph = Self(nodes);
        for node in graph.0.values() {
            if node
                .outer
                .and_then(|id| graph.0.get(id))
                .is_some_and(|n| n.mode == "permanent")
            {
                return Err(invalid(
                    "постоянный двойной туннель нельзя использовать как внешний",
                ));
            }
        }
        let mut done = BTreeSet::new();
        for id in graph.0.keys() {
            graph.visit(id, &mut BTreeSet::new(), &mut done)?;
        }
        // Go validates the transport and reserve graphs independently. An
        // outer peer may legitimately list the inner peer as an ordinary backup.
        for id in graph.0.keys() {
            let mut path = BTreeSet::new();
            let mut next = Some(*id);
            while let Some(key) = next {
                if !path.insert(key) {
                    return Err(invalid("цикл двойных туннелей недопустим"));
                }
                next = graph
                    .0
                    .get(key)
                    .ok_or_else(|| invalid("внешнее подключение для двойного туннеля не найдено"))?
                    .outer;
            }
        }
        Ok(graph)
    }
    /// The saved outer tunnel and effective Go mode, independent of whether
    /// the inner VPN currently uses the direct or nested transport.
    pub fn nested(&self, id: &str) -> Option<(&'a str, &'a str)> {
        let n = self.0.get(id)?;
        Some((n.outer?, n.mode))
    }
    fn managed(doc: &'a Value, owned: &HashMap<String, Managed>) -> io::Result<Self> {
        let mut graph = Self::load(doc)?;
        for (id, managed) in owned {
            if managed.tunnel.inherited() {
                if let Some(n) = graph.0.get_mut(id.as_str()) {
                    let cfg = &n.row["config"];
                    n.enabled |= cfg["enabled"] == true
                        && cfg["client"]["enabled"] == true
                        && cfg["client"].get("rust_managed").is_none();
                }
            }
        }
        Ok(graph)
    }
    fn visit(
        &self,
        id: &'a str,
        active: &mut BTreeSet<&'a str>,
        done: &mut BTreeSet<&'a str>,
    ) -> io::Result<()> {
        if done.contains(id) {
            return Ok(());
        }
        if !active.insert(id) {
            return Err(invalid("цикл резервных подключений недопустим"));
        }
        let n = self
            .0
            .get(id)
            .ok_or_else(|| invalid("резервное подключение не найдено"))?;
        for backup in &n.backups {
            self.visit(backup, active, done)?;
        }
        active.remove(id);
        done.insert(id);
        Ok(())
    }
    fn candidates(&self, id: &'a str) -> Vec<&'a str> {
        self.expand(vec![id], BTreeSet::new())
    }
    /// Rule reserves precede the primary's connection reserves. Each
    /// configured reserve inherits its own ordered connection reserves.
    pub fn for_rule(&self, id: &str, reserves: &[String]) -> io::Result<Vec<&'a str>> {
        let (&id, owner) = self
            .0
            .get_key_value(id)
            .ok_or_else(|| invalid("неизвестный основной туннель"))?;
        if owner.mode == "permanent" {
            return Ok(vec![id]);
        }
        let mut stack: Vec<_> = owner.backups.iter().rev().copied().collect();
        for r in reserves.iter().rev() {
            let (&key, _) = self
                .0
                .get_key_value(r.as_str())
                .ok_or_else(|| invalid("неизвестный резервный туннель"))?;
            stack.push(key);
        }
        let mut out = vec![id];
        out.extend(self.expand(stack, BTreeSet::from([id])));
        Ok(out)
    }
    fn expand(&self, mut stack: Vec<&'a str>, mut seen: BTreeSet<&'a str>) -> Vec<&'a str> {
        let mut result = Vec::new();
        while let Some(next) = stack.pop() {
            if seen.insert(next) {
                let n = &self.0[next];
                result.push(next);
                if n.mode != "permanent" {
                    stack.extend(n.backups.iter().rev().copied());
                }
            }
        }
        result
    }
}
#[derive(Default, Clone, Copy)]
struct Health {
    authenticated: bool,
    verified: bool,
    failed: bool,
}
fn health(n: &Node<'_>, managed: &mut Managed, now: u64, timeout: u64) -> Health {
    let alive = managed.tunnel.alive();
    let many = n.row["config"]["client"]["endpoint_backups"]
        .as_array()
        .is_some_and(|a| !a.is_empty());
    let authenticated = alive && managed.recovery.authenticated(now);
    let mut health = Health {
        authenticated,
        verified: authenticated,
        failed: managed.recovery.needs_reserve(now, timeout, many),
    };
    if super::settings::routed_mtu_launch_pending(n.row)
        && super::settings::pending_routed_mtu(n.row)
            .ok()
            .flatten()
            .is_some_and(|change| {
                super::settings::direct_forward_endpoint(n.row, &change).is_some()
            })
    {
        // A still-running predecessor may already have exhausted its old pool.
        // Only the newly launched generation can activate a cold standby.
        health.failed = false;
    }
    if n.outer.is_some() {
        managed.recovery.nested.reserve_health(
            n.mode,
            now,
            timeout,
            &mut health.verified,
            &mut health.failed,
        );
    }
    health
}

fn health_states<'a>(
    graph: &Graph<'a>,
    owned: &mut HashMap<String, Managed>,
    now: u64,
    settings: &Value,
) -> BTreeMap<&'a str, Health> {
    let timeout = settings["handshake_timeout_seconds"].as_u64().unwrap_or(20);
    owned
        .iter_mut()
        .filter_map(|(id, m)| {
            graph
                .0
                .get_key_value(id.as_str())
                .map(|(key, n)| (*key, health(n, m, now, timeout)))
        })
        .collect()
}

fn demand<'a>(
    graph: &Graph<'a>,
    state: &BTreeMap<&str, Health>,
    routing: &Value,
) -> BTreeSet<&'a str> {
    let known = |id: &Value| graph.0.get_key_value(id.as_str()?).map(|(&id, _)| id);
    // Hold an in-use standby through failback until the kernel has verified
    // and journaled the replacement. The routing transaction owns this list.
    let mut wanted: BTreeSet<_> = routing["active_reserves"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(known)
        .collect();
    for (&id, n) in &graph.0 {
        if !n.enabled || n.standby {
            continue;
        }
        let Some(primary) = state.get(id) else {
            continue;
        };
        if primary.verified {
            continue;
        }
        let mut choose = |candidate: &'a str| {
            let node = &graph.0[candidate];
            if !node.enabled || (!node.standby && !state.contains_key(candidate)) {
                return false;
            }
            let h = state.get(candidate).copied().unwrap_or_default();
            if node.standby && (primary.failed || h.verified) {
                wanted.insert(candidate);
            }
            h.verified || (primary.failed && !h.failed)
        };
        if !n.backups.is_empty() {
            graph.candidates(id).into_iter().skip(1).any(&mut choose);
        }
        for chain in routing["reserve_chains"][id]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_array)
        {
            chain.iter().filter_map(known).any(&mut choose);
        }
    }
    wanted
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum UnroutedStandby {
    Direct,
    Cold,
}

fn explicitly_disabled(row: &Value) -> bool {
    let config = &row["config"];
    config["enabled"] == false || config["client"]["enabled"] == false
}

fn dormant_consumer(
    runtime: &Runtime,
    doc: &Value,
    owned: &HashMap<String, Managed>,
    id: &str,
    node: &Node<'_>,
) -> bool {
    if !explicitly_disabled(node.row) || owned.contains_key(id) {
        return false;
    }
    let Ok(name) = iface(node.row, doc) else {
        return false;
    };
    if !matches!(runtime.present(&name), Ok(false)) {
        return false;
    }
    #[cfg(target_os = "linux")]
    if linux::ensure_plain_delete_scope_vacant(runtime, &name).is_err() {
        return false;
    }
    true
}

fn settled_ordinary(node: &Node<'_>) -> bool {
    !node.standby
        && node.outer.is_none()
        && node.mode != "permanent"
        && !settings::has_saved_edit(node.row)
        && matches!(supervisor::pending_endpoint_restart(node.row), Ok(None))
}

fn authenticated_ordinary(
    id: &str,
    node: &Node<'_>,
    states: &BTreeMap<&str, Health>,
    owned: &HashMap<String, Managed>,
) -> bool {
    node.enabled
        && settled_ordinary(node)
        && states.get(id).is_some_and(|h| h.verified)
        && owned.get(id).is_some_and(|m| {
            m.tunnel.nested_iface().is_none()
                && m.tunnel
                    .snapshot()
                    .is_ok_and(|live| live["running"] == true && live["connected"] == true)
        })
}

fn idle_ordinary_consumers(
    runtime: &Runtime,
    doc: &Value,
    graph: &Graph<'_>,
    states: &BTreeMap<&str, Health>,
    owned: &HashMap<String, Managed>,
    standby: &str,
) -> bool {
    let mut has_parent = false;
    let mut through_disabled = false;
    for (&id, node) in &graph.0 {
        let applied = &node.row["applied_config"]["client"];
        if node.outer == Some(standby) || s(applied, "double_tunnel_id").trim() == standby {
            return false;
        }
        let saved_backup = node.backups.contains(&standby);
        let applied_backup = applied["fallback_tunnel_ids"]
            .as_array()
            .is_some_and(|ids| {
                ids.iter()
                    .any(|id| id.as_str().is_some_and(|s| s.trim() == standby))
            });
        if !saved_backup && !applied_backup {
            continue;
        }
        if settled_ordinary(node) && dormant_consumer(runtime, doc, owned, id, node) {
            has_parent = true;
            through_disabled |= saved_backup;
            continue;
        }
        // Every ordinary path to this standby passes through one of its
        // immediate parents. An authenticated parent stops selection.
        if !saved_backup || !authenticated_ordinary(id, node, states, owned) {
            return false;
        }
        has_parent = true;
    }
    // A disabled profile cannot request the standby itself. A surviving
    // primary may still reach its children through the saved fallback list.
    has_parent
        && (!through_disabled
            || graph.0.iter().all(|(&id, node)| {
                node.standby
                    || !graph.candidates(id).contains(&standby)
                    || dormant_consumer(runtime, doc, owned, id, node)
                    || authenticated_ordinary(id, node, states, owned)
            }))
}

pub(super) fn unrouted_standby_plan<'a>(
    runtime: &Runtime,
    doc: &Value,
    owned: &mut HashMap<String, Managed>,
    shared: &[&'a str],
) -> io::Result<BTreeMap<&'a str, UnroutedStandby>> {
    let graph = Graph::managed(doc, owned)?;
    let settings = crate::recovery::recovery_settings(&doc["recovery_settings"]);
    let states = health_states(&graph, owned, crate::now(), &settings);
    let wanted = demand(&graph, &states, &Value::Null);
    Ok(shared
        .iter()
        .filter_map(|&id| {
            if wanted.contains(id) {
                Some((id, UnroutedStandby::Direct))
            } else if idle_ordinary_consumers(runtime, doc, &graph, &states, owned, id) {
                Some((id, UnroutedStandby::Cold))
            } else {
                None
            }
        })
        .collect())
}

fn wanted_standbys<'a>(
    doc: &'a Value,
    graph: &Graph<'a>,
    states: &BTreeMap<&str, Health>,
    owned: &HashMap<String, Managed>,
) -> BTreeSet<&'a str> {
    let mut wanted = demand(graph, states, &doc["rust_static_routing"]);
    // Several inner peers can depend on the same standby. Keep it up until
    // every trial/active transport has released its demand.
    for (id, managed) in owned.iter() {
        if let Some((outer, _)) = graph.nested(id) {
            let pending =
                super::settings::pending_fixed_nested_outer(doc, graph.0[id.as_str()].row);
            if managed.recovery.nested.wants_outer()
                || managed.tunnel.nested_iface().is_some()
                || pending == Some(outer)
            {
                wanted.insert(outer);
            }
        }
    }
    wanted
}

pub(super) fn reconcile(
    doc: &Value,
    owned: &mut HashMap<String, Managed>,
    now: u64,
    settings: &Value,
    events: &mut Vec<String>,
    held_standby: Option<&str>,
    mut start: impl FnMut(Spec) -> io::Result<Box<dyn Tunnel>>,
) -> io::Result<()> {
    if !configured(doc) {
        return Ok(());
    }
    let graph = Graph::managed(doc, owned)?;
    let states = health_states(&graph, owned, now, settings);
    let wanted = wanted_standbys(doc, &graph, &states, owned);
    for (&id, n) in &graph.0 {
        if !n.standby
            || !n.enabled
            || held_standby == Some(id)
            || n.row.get(super::settings::PENDING_ROUTED_MTU).is_some()
        {
            continue;
        }
        if !wanted.contains(id) {
            if let Some(m) = owned.get_mut(id) {
                m.tunnel.stop()?;
                owned.remove(id);
                events.push(format!("резерв {id} переведён в ожидание"));
            }
            continue;
        }
        if owned.contains_key(id) {
            continue;
        }
        let spec = specification(doc, n.row)?;
        let iface = spec.iface.clone();
        let fingerprint = Sha256::digest(spec.conf.as_bytes()).into();
        let (tunnel, recovery) = match start(spec) {
            Ok(t) => {
                events.push(format!("запущен резерв {id}, ожидается handshake"));
                (t, Default::default())
            }
            Err(e) => {
                events.push(format!("резерв {id}: {e}"));
                (
                    Box::new(supervisor::Stopped) as Box<dyn Tunnel>,
                    supervisor::Recovery::failed_start(now, &e),
                )
            }
        };
        owned.insert(
            id.into(),
            Managed {
                tunnel,
                iface,
                fingerprint,
                recovery,
            },
        );
    }
    Ok(())
}
impl Runtime {
    pub fn set_failover(
        &self,
        db: &Store,
        id: &str,
        change: Failover,
        wan: &[String],
    ) -> io::Result<()> {
        self.set_failover_inner(db, id, change, wan, None)
    }

    /// Stage a change to the reserve list of a working routed profile.
    /// The routing caller checks that it leaves every live kernel object intact.
    pub fn stage_active_failover_order(
        &self,
        db: &Store,
        id: &str,
        change: &Failover,
        seal: impl FnOnce(&Value, &mut Value, Option<&super::settings::RoutedNestedTransport>) -> io::Result<()>,
    ) -> io::Result<bool> {
        let mut guard = self
            .clients
            .0
            .lock()
            .map_err(|_| invalid("менеджер подключений недоступен"))?;
        if !routes_use(&read(db)?, id) {
            return Ok(false);
        }
        edit_document(db, |doc| {
            let unavailable =
                || invalid("изменение резервов затрагивает действующую конфигурацию AWG");
            if !routes_use(doc, id) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let row = find(doc, id)?;
            let client = &row["config"]["client"];
            change.validate_mode()?;
            let old_outer = s(client, "double_tunnel_id");
            let old_mode = s(client, "double_tunnel_mode");
            let outer = change.double_tunnel_id.as_deref().map(str::trim).unwrap_or(old_outer);
            let mode = if change.double_tunnel_id.is_some() && outer.is_empty() {
                "last_resort"
            } else {
                change.double_tunnel_mode.as_deref().unwrap_or(old_mode)
            };
            let change_transport = outer != old_outer || mode != old_mode;
            let was_standby = client["standby"] == true;
            let change_standby = was_standby != change.standby;
            if change_transport
                    && (was_standby || change_standby || old_mode == "permanent" || mode == "permanent")
                || super::settings::has_saved_edit(row)
            {
                return Err(unavailable());
            }
            let backups = json!(change.backups(id)?);
            if !change_transport && !change_standby && backups == client["fallback_tunnel_ids"] {
                return Ok(true);
            }
            let retained = if change_transport && outer == old_outer && !outer.is_empty() {
                match guard.get(id) {
                    Some(managed) if !managed.tunnel.inherited() => {
                        super::settings::verify_retained_optional_nested(doc, row, managed)?
                    }
                    _ => self
                        .go_nested_confirmed_peer(db, wire(row), &iface(row, doc)?)?
                        .map(|(_, witness)| witness),
                }
            } else {
                None
            };
            // The authored fields are local policy and do not change UAPI.
            let outer = change_transport.then(|| json!(outer));
            let mode = change_transport.then(|| json!(mode));
            let before = doc.clone();
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == id)
                .unwrap();
            for field in ["config", "applied_config"] {
                if row[field].is_object() {
                    row[field]["client"]["fallback_tunnel_ids"] = backups.clone();
                    if change_standby {
                        row[field]["client"]["standby"] = json!(change.standby);
                    }
                    if let (Some(outer), Some(mode)) = (&outer, &mode) {
                        row[field]["client"]["double_tunnel_id"] = outer.clone();
                        row[field]["client"]["double_tunnel_mode"] = mode.clone();
                    }
                }
            }
            let revision = before["routing_revision"]
                .as_u64()
                .and_then(|revision| revision.checked_add(1))
                .ok_or_else(unavailable)?;
            doc["routing_revision"] = json!(revision);
            if change_standby && change.standby {
                let graph = Graph::managed(doc, &guard)?;
                let settings = crate::recovery::recovery_settings(&doc["recovery_settings"]);
                let states = health_states(&graph, &mut guard, crate::now(), &settings);
                let mut routing = doc["rust_static_routing"].clone();
                if let Some(routing) = routing.as_object_mut() {
                    routing.remove("active_reserves");
                }
                if !states.get(id).is_some_and(|node| node.verified)
                    || !demand(&graph, &states, &routing).contains(id)
                {
                    return Err(unavailable());
                }
            } else {
                Graph::load(doc)?;
            }
            seal(&before, doc, retained.as_ref())?;
            Ok(true)
        })
    }

    pub fn set_failover_with_transport(
        &self,
        db: &Store,
        id: &str,
        change: Failover,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.set_failover_inner(db, id, change, wan, Some(&refresh))
    }

    fn set_failover_inner(
        &self,
        db: &Store,
        id: &str,
        change: Failover,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> io::Result<()> {
        let guard = self
            .clients
            .0
            .lock()
            .map_err(|_| invalid("менеджер подключений недоступен"))?;
        let need_start = edit_document(db, |doc| {
            let row = find(doc, id)?;
            let old = &row["config"]["client"];
            if routes_use(doc, id) {                return Err(invalid(
                    "сначала снимите статические маршруты этих подключений",
                ));
            }
            change.validate_mode()?;
            let outer = change
                .double_tunnel_id
                .as_deref()
                .map(str::trim)
                .unwrap_or(s(old, "double_tunnel_id"))
                .to_owned();
            let mode = if change.double_tunnel_id.is_some() && outer.is_empty() {
                "last_resort"
            } else {
                change
                    .double_tunnel_mode
                    .as_deref()
                    .unwrap_or(s(old, "double_tunnel_mode"))
            }
            .to_owned();
            if mode == "permanent" && outer.is_empty() && old["double_tunnel_mode"] != "permanent" {
                return Err(invalid("выберите внешний туннель для постоянного режима"));
            }
            let backups = change.backups(id)?;
            for candidate in std::iter::once(id)
                .chain(backups.iter().copied())
                .chain((!outer.is_empty()).then_some(outer.as_str()))
            {
                let r = find(doc, candidate)?;
                let c = &r["config"]["client"];
                if c["enabled"] == true && c["rust_managed"] != true {
                    let unavailable = || {
                        invalid("резервирование доступно для клиентов под управлением этой панели")
                    };
                    let current = guard.get(candidate).ok_or_else(unavailable)?;
                    let saved = saved_specification(doc, r, false)?;
                    if c.get("rust_managed").is_some()
                        || super::settings::has_saved_edit(r)
                        || !current.tunnel.inherited()
                        || current.iface != saved.iface
                        || Sha256::digest(saved.conf.as_bytes()).as_slice() != current.fingerprint
                        || !current
                            .tunnel
                            .snapshot()
                            .is_ok_and(|status| status["running"] == true)
                    {
                        return Err(unavailable());
                    }
                }
            }
            standalone(doc, wire(row))?;
            let start = old["standby"] == true
                && !change.standby
                && old["enabled"] == true
                && old["rust_managed"] == true
                && row["config"]["enabled"] == true
                && !guard.contains_key(id);
            let item = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == id)
                .unwrap();
            for field in ["config", "applied_config"] {
                if item[field].is_object() {
                    let c = &mut item[field]["client"];
                    c["standby"] = json!(change.standby);
                    c["fallback_tunnel_ids"] = json!(backups);
                    if change.double_tunnel_mode.is_some() || change.double_tunnel_id.is_some() {
                        c["double_tunnel_id"] = json!(outer);
                        c["double_tunnel_mode"] = json!(mode);
                    }
                }
            }
            Graph::load(doc)?;
            Ok(start)
        })?;
        drop(guard);
        if need_start {
            let started = (|| {
                let inherited = self.collect_transport(db, wan, refresh)?;
                self.clients.up(db, Some(id), |spec| {
                    self.start_local_prepared(spec, wan, refresh.zip(inherited.as_ref()))
                })
            })();
            if let Err(e) = started {
                let doc = read(db)?;
                self.retry_restore(&doc, find(&doc, id)?, &e);
                return Err(invalid(&format!(
                    "настройки сохранены, запуск клиента будет повторён: {e}"
                )));
            }
        }
        self.recover_clients_inner(db, wan, refresh, None, None)?;
        Ok(())
    }
    pub(crate) fn failover_view(&self, doc: &Value) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        let Ok(mut owned) = self.clients.0.try_lock() else {
            return out;
        };
        let Ok(graph) = Graph::managed(doc, &owned) else {
            return out;
        };
        let now = crate::now();
        let settings = crate::recovery::recovery_settings(&doc["recovery_settings"]);
        let states = health_states(&graph, &mut owned, now, &settings);
        let wanted = wanted_standbys(doc, &graph, &states, &owned);
        for (&id, n) in &graph.0 {
            let mut candidates = graph.candidates(id);
            if candidates.len() > 1
                && owned
                    .get(id)
                    .is_some_and(|owner| owner.recovery.nested.prefers_ordinary(n.mode))
            {
                candidates.rotate_left(1);
            }
            let effective = candidates.into_iter()
                .filter(|_| n.enabled)
                .find(|s| graph.0[*s].enabled && states.get(s).is_some_and(|health| health.authenticated));
            let mut status = json!({
                "fallback_tunnel_ids": n.backups,
                "standby": n.standby,
                "activated": n.standby && wanted.contains(id),
                "active_tunnel_id": effective.unwrap_or_default(),
                "double_tunnel_mode": n.mode,
                "double_tunnel_active": false
            });
            if let Some(outer) = n.outer {
                status["double_tunnel_id"] = json!(outer);
            }
            if let Some(m) = owned.get(id) {
                m.recovery.nested.status(
                    m.tunnel.nested_iface(),
                    m.recovery.authenticated(now),
                    &mut status,
                );
            }
            out.insert(id.to_owned(), status);
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standby_status_reports_demand_before_a_worker_owns_the_client() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        let doc = json!({"servers": [
            {"id":"primary","config":{"enabled":true,"client":{"enabled":true,"rust_managed":true,
                "fallback_tunnel_ids":["standby"]}}},
            {"id":"standby","config":{"enabled":true,"client":{"enabled":true,"rust_managed":true,"standby":true}}}
        ]});
        let now = crate::now();
        let recovery = supervisor::Recovery::failed_start(
            now.saturating_sub(60),
            &io::Error::other("unavailable fixture endpoint"),
        );
        {
            let mut owned = runtime.clients.0.lock().unwrap();
            owned.insert("primary".into(), Managed {
                tunnel: Box::new(supervisor::Stopped),
                iface: "awg0".into(),
                fingerprint: [0; 32],
                recovery,
            });
        }
        assert_eq!(runtime.failover_view(&doc)["standby"]["activated"], true);
        {
            let mut owned = runtime.clients.0.lock().unwrap();
            owned.remove("primary");
            owned.insert("standby".into(), Managed {
                tunnel: Box::new(supervisor::Stopped),
                iface: "awg1".into(),
                fingerprint: [0; 32],
                recovery: Default::default(),
            });
        }
        assert_eq!(runtime.failover_view(&doc)["standby"]["activated"], false);
    }

    #[test]
    fn plain_profile_status_keeps_go_shape_and_defaults_legacy_mode() {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(temp.path()).unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        let expected = json!({
            "fallback_tunnel_ids": [],
            "standby": false,
            "activated": false,
            "active_tunnel_id": "",
            "double_tunnel_mode": "last_resort",
            "double_tunnel_active": false
        });
        assert_eq!(crate::status(&db, &runtime).unwrap()["servers"][0]["failover"], expected);
        edit_document(&db, |doc| {
            doc["servers"][0]["config"]["client"]["double_tunnel_mode"] = json!("old-value");
            Ok(())
        }).unwrap();
        let old = read(&db).unwrap();
        assert_eq!(crate::status(&db, &runtime).unwrap()["servers"][0]["failover"], expected);
        assert_eq!(read(&db).unwrap(), old);
    }

    #[test]
    fn failover_request_matches_go_decoding_and_normalization() {
        let raw = r#"{
            "FALLBACK_TUNNEL_IDS":[" first ",null,"","second","first"],
            "ſtandby":true,"STANDBY":null,
            "double_tunnel_id":"previous","DOUBLE_TUNNEL_ID":null,
            "DOUBLE_TUNNEL_MODE":"automatic","unused":{"anything":true}
        }"#;
        let request: Failover = serde_json::from_str(raw).unwrap();
        assert_eq!(request.backups("primary").unwrap(), ["first", "second"]);
        assert!(request.backups("first").is_err());
        assert!(request.standby);
        assert!(request.double_tunnel_id.is_none());
        assert_eq!(request.double_tunnel_mode.as_deref(), Some("automatic"));
        request.validate_mode().unwrap();
        assert!(serde_json::from_str::<Failover>(r#"{"standby":"true"}"#).is_err());
        let request: Failover = serde_json::from_str("null").unwrap();
        assert!(!request.standby && request.fallback_tunnel_ids.is_empty());
        let request: Failover = serde_json::from_str(r#"{"double_tunnel_id":"","double_tunnel_mode":"off"}"#).unwrap();
        assert!(request.validate_mode().is_err());
    }

    #[test]
    fn permanent_peer_stops_ordinary_reserve_expansion_without_hiding_later_options() {
        let doc = json!({"servers":[
            {"id":"primary", "config":{"client":{"fallback_tunnel_ids":["permanent","later"]}}},
            {"id":"permanent", "config":{"client":{
                "double_tunnel_id":"outer", "double_tunnel_mode":"permanent",
                "fallback_tunnel_ids":["behind"],
            }}},
            {"id":"outer", "config":{}},
            {"id":"behind", "config":{}},
            {"id":"later", "config":{"client":{"fallback_tunnel_ids":["tail"]}}},
            {"id":"tail", "config":{}},
        ]});
        let graph = Graph::load(&doc).unwrap();
        let expected = ["primary", "permanent", "later", "tail"];
        assert_eq!(graph.candidates("primary"), expected);
        assert_eq!(graph.for_rule("primary", &["permanent".into()]).unwrap(), expected);
        assert_eq!(graph.candidates("permanent"), ["permanent"]);
        assert_eq!(graph.for_rule("permanent", &["later".into()]).unwrap(), ["permanent"]);
    }

    #[test]
    fn long_failover_order_survives_policy_save_and_reload() {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(temp.path()).unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        let backups: Vec<String> = (1..=24).map(|i| format!("reserve-{i:02}")).collect();
        let expected: Vec<&str> =
            std::iter::once("primary").chain(backups.iter().map(String::as_str)).collect();
        edit_document(&db, |doc| {
            let rows: Vec<_> = expected.iter().enumerate().map(|(index, id)| {
                let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
                cfg["enabled"] = json!(true);
                cfg["client"]["enabled"] = json!(true);
                cfg["client"]["rust_managed"] = json!(true);
                cfg["client_iface"] = json!(format!("awg{index}"));
                json!({"id": id, "config": cfg})
            }).collect();
            doc["servers"] = json!(rows);
            Ok(())
        }).unwrap();
        runtime.set_failover(&db, "primary", Failover {
            fallback_tunnel_ids: backups.clone(), ..Default::default()
        }, &[]).unwrap();
        let doc = read(&db).unwrap();
        let graph = Graph::load(&doc).unwrap();
        assert_eq!(graph.for_rule("primary", &[]).unwrap(), expected);
    }

    struct InheritedPeer;
    impl Tunnel for InheritedPeer {
        fn inherited(&self) -> bool {
            true
        }
        fn alive(&mut self) -> bool {
            true
        }
        fn stop(&mut self) -> io::Result<()> {
            panic!("stable peer stopped")
        }
        fn probe(&mut self) -> io::Result<()> {
            panic!("stable peer probed")
        }
        fn snapshot(&self) -> io::Result<Value> {
            Ok(
                json!({"running":true,"connected":true,"last_handshake":crate::now(),"endpoint":"192.0.2.51:51820","rx_bytes":5}),
            )
        }
    }

    #[test]
    fn failover_edit_admits_only_exact_adopted_go_participants() {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(temp.path()).unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        edit_document(&db, |doc| {
            let rows: Vec<_> = ["primary", "backup"]
                .into_iter()
                .enumerate()
                .map(|(index, id)| {
                    let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
                    cfg["enabled"] = true.into();
                    cfg["client"]["enabled"] = true.into();
                    cfg["client_iface"] = format!("awg{index}").into();
                    json!({"id":id,"config":cfg})
                })
                .collect();
            doc["servers"] = json!(rows);
            doc["active_id"] = "primary".into();
            Ok(())
        })
        .unwrap();
        let edit = || {
            runtime.set_failover(
                &db,
                "primary",
                Failover {
                    fallback_tunnel_ids: vec!["backup".into()],
                    ..Default::default()
                },
                &[],
            )
        };
        let doc = read(&db).unwrap();
        assert!(edit().is_err());
        for id in ["primary", "backup"] {
            let spec = saved_specification(&doc, find(&doc, id).unwrap(), false).unwrap();
            runtime.clients.0.lock().unwrap().insert(
                id.into(),
                Managed {
                    fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                    iface: spec.iface,
                    tunnel: Box::new(InheritedPeer),
                    recovery: Default::default(),
                },
            );
            if id == "primary" {
                assert!(edit().is_err());
            }
        }
        {
            let mut owned = runtime.clients.0.lock().unwrap();
            owned.get_mut("backup").unwrap().fingerprint[0] ^= 1;
        }
        assert!(edit().is_err());
        assert_eq!(read(&db).unwrap(), doc);
        {
            let mut owned = runtime.clients.0.lock().unwrap();
            owned.get_mut("backup").unwrap().fingerprint[0] ^= 1;
        }
        edit().unwrap();
        let updated = read(&db).unwrap();
        assert_eq!(
            updated["servers"][0]["config"]["client"]["fallback_tunnel_ids"],
            json!(["backup"])
        );
        assert_eq!(updated["servers"][1], doc["servers"][1]);
        assert!(updated["servers"][0]["config"]["client"]
            .get("rust_managed")
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standby_change_needs_live_demand_even_when_routing_holds_the_reserve() {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(temp.path()).unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        edit_document(&db, |doc| {
            let rows = ["primary", "backup"].into_iter().enumerate().map(|(i, id)| {
                let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
                cfg["enabled"] = json!(true);
                cfg["client"]["enabled"] = json!(true);
                cfg["client_iface"] = json!(format!("awg{i}"));
                if id == "primary" {
                    cfg["client"]["fallback_tunnel_ids"] = json!(["backup"]);
                }
                json!({"id": id, "config": cfg})
            }).collect::<Vec<_>>();
            doc["servers"] = json!(rows);
            doc["routing_revision"] = json!(1);
            doc["rust_static_routing"] = json!({"targets":["primary","backup"],"active_reserves":["backup"]});
            Ok(())
        }).unwrap();
        let original = read(&db).unwrap();
        for id in ["primary", "backup"] {
            let row = find(&original, id).unwrap();
            let spec = saved_specification(&original, row, false).unwrap();
            runtime.clients.0.lock().unwrap().insert(id.into(), Managed {
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                iface: spec.iface,
                recovery: supervisor::Recovery::from_inherited(&InheritedPeer, row, &original),
                tunnel: Box::new(InheritedPeer),
            });
        }
        let change = Failover { standby: true, ..Default::default() };
        assert!(runtime.stage_active_failover_order(&db, "backup", &change, |_, _, _| {
            panic!("healthy primary leaves no standby demand")
        }).is_err());
        assert_eq!(read(&db).unwrap(), original);
        runtime.clients.0.lock().unwrap().get_mut("primary").unwrap().recovery = Default::default();
        assert!(runtime.stage_active_failover_order(&db, "backup", &change, |_, doc, _| {
            assert_eq!(find(doc, "backup")?["config"]["client"]["standby"], true);
            Ok(())
        }).unwrap());
    }

    #[test]
    fn an_inactive_profile_can_reference_an_independent_routed_reserve() {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(temp.path()).unwrap();
        let runtime = Runtime::new(temp.path(), temp.path().join("no-engine"));
        edit_document(&db, |doc| {
            let rows: Vec<_> = ["offline", "live"].into_iter().enumerate().map(|(i, id)| {
                let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
                cfg["enabled"] = json!(id == "live");
                cfg["client"]["enabled"] = json!(true);
                cfg["client"]["rust_managed"] = json!(true);
                cfg["client_iface"] = json!(format!("awg{i}"));
                cfg["routing"]["active"] = json!(id == "live");
                json!({"id": id, "config": cfg})
            }).collect();
            doc["servers"] = json!(rows);
            doc["routing_revision"] = json!(11);
            doc["rust_static_routing"] = json!({"targets":["live"],"committed_targets":["live"]});
            Ok(())
        }).unwrap();
        let before = read(&db).unwrap();
        runtime.set_failover(&db, "offline", Failover {
            fallback_tunnel_ids: vec!["live".into()], ..Default::default()
        }, &[]).unwrap();
        let after = read(&db).unwrap();
        assert_eq!(find(&after, "offline").unwrap()["config"]["client"]["fallback_tunnel_ids"], json!(["live"]));
        assert_eq!(find(&after, "live").unwrap(), find(&before, "live").unwrap());
        assert_eq!(after["rust_static_routing"], before["rust_static_routing"]);
        assert_eq!(after["routing_revision"], before["routing_revision"]);
    }

    #[test]
    fn rule_only_standby_waits_for_outage_and_stays_up_until_kernel_failback() {
        let mut doc = json!({"servers":[]});
        for id in ["P", "R", "last"] {
            doc["servers"].as_array_mut().unwrap().push(json!({"id":id,"config":{"enabled":true,"client":{"enabled":true,"rust_managed":true,"standby":id!="P"}}}));
        }
        let graph = Graph::load(&doc).unwrap();
        let down = Health {
            authenticated: false,
            verified: false,
            failed: true,
        };
        let up = Health {
            authenticated: true,
            verified: true,
            failed: false,
        };
        let state = BTreeMap::from([("P", down)]);
        assert!(demand(&graph, &state, &Value::Null).is_empty());
        let mut receipt = json!({"reserve_chains":{"P":[["R","last"]]}});
        assert_eq!(demand(&graph, &state, &receipt), BTreeSet::from(["R"]));
        assert!(demand(
            &graph,
            &BTreeMap::from([("P", Health::default())]),
            &receipt
        )
        .is_empty());
        receipt["active_reserves"] = json!(["R"]);
        let healthy = BTreeMap::from([("P", up), ("R", up)]);
        assert_eq!(demand(&graph, &healthy, &receipt), BTreeSet::from(["R"]));
        receipt["active_reserves"] = json!([]);
        assert!(demand(&graph, &healthy, &receipt).is_empty());
    }
    #[test]
    fn stable_nested_priority_deduplicates_and_bad_updates_leave_profile_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(tmp.path()).unwrap();
        let runtime = Runtime::new(tmp.path(), tmp.path().join("no-engine"));
        edit_document(&db, |doc| {
            let row = doc["servers"][0].clone();
            doc["servers"] = json!(["P", "A", "B", "C"].map(|id| {
                let mut row = row.clone();
                row["id"] = json!(id);
                row
            }));
            doc["active_id"] = json!("P");
            Ok(())
        })
        .unwrap();
        let set = |id, ids: &[&str], standby| {
            runtime.set_failover(
                &db,
                id,
                Failover {
                    fallback_tunnel_ids: ids.iter().map(|v| (*v).to_owned()).collect(),
                    standby,
                    ..Default::default()
                },
                &[],
            )
        };
        set("A", &["B"], true).unwrap();
        set("P", &["A", "C", "A"], false).unwrap();
        let doc = read(&db).unwrap();
        assert_eq!(
            Graph::load(&doc).unwrap().candidates("P"),
            ["P", "A", "B", "C"]
        );
        for (id, backups) in [("B", vec!["P"]), ("A", vec!["missing"]), ("C", vec!["C"])] {
            assert!(set(id, &backups, false).is_err());
        }
        assert!(runtime
            .set_failover(
                &db,
                "P",
                Failover {
                    double_tunnel_id: Some("P".into()),
                    ..Default::default()
                },
                &[]
            )
            .is_err());
        assert_eq!(read(&db).unwrap(), doc);
        let view = runtime.failover_view(&doc);
        assert_eq!(view["A"]["standby"], true);
        assert_eq!(view["A"]["activated"], false);
        assert_eq!(view["P"]["active_tunnel_id"], "");
        let outer = |id, outer: &str, mode: Option<&str>, standby| {
            runtime.set_failover(
                &db,
                id,
                Failover {
                    double_tunnel_id: Some(outer.into()),
                    double_tunnel_mode: mode.map(String::from),
                    standby,
                    ..Default::default()
                },
                &[],
            )
        };
        outer("P", "B", Some("automatic"), false).unwrap();
        outer("A", "B", None, true).unwrap();
        let saved = read(&db).unwrap();
        let graph = Graph::load(&saved).unwrap();
        assert_eq!(graph.nested("P"), Some(("B", "automatic")));
        assert_eq!(graph.nested("A"), Some(("B", "last_resort")));
        assert!(graph.0["A"].standby);
        assert_eq!(graph.for_rule("P", &["A".into()]).unwrap(), ["P", "A"]);
        assert!(outer("B", "A", None, false).is_err());
        assert!(outer("B", "missing", None, false).is_err());
        assert!(outer("B", "P", Some("permanent"), false).is_err());
        assert_eq!(read(&db).unwrap(), saved);
    }
}
