use super::*;
use crate::client::settings::{
    confirmed_routing_revision, direct_endpoint_profile, has_saved_edit, hostname_port,
    selected_named_address, RoutedRetryHooks,
};
use std::sync::Arc;

const HINT_TTL: Duration = Duration::from_secs(20 * 60);

#[derive(Default)]
pub struct ClientRecoveryPass {
    pub events: Vec<String>,
    pub named_reconnects: Vec<NamedReconnectRequest>,
}

pub enum NamedReconnectInput {
    Collect,
    Apply(Vec<ResolvedNamedReconnect>),
}

pub struct NamedReconnectTarget<'a> {
    pub id: &'a str,
    pub iface: &'a str,
    pub raw: &'a str,
    pub revision: u64,
    pub selected: SocketAddr,
    pub addresses: &'a [SocketAddr],
}

impl NamedReconnectTarget<'_> {
    pub fn validate(&self) -> io::Result<()> {
        if self.addresses.iter().any(SocketAddr::is_ipv6)
            || selected_named_address(self.raw, self.addresses)? != self.selected
        {
            return Err(invalid("неверный IPv4-адрес endpoint AWG"));
        }
        Ok(())
    }
}

/// One native watchdog attempt awaiting a fresh lookup outside operation locks.
pub struct NamedReconnectRequest {
    ticket: Arc<()>,
    id: String,
    iface: String,
    raw: String,
    revision: u64,
    fingerprint: [u8; 32],
    row: Value,
    cursor: Cursor,
    next: (u16, bool),
    alive: bool,
}

pub struct ResolvedNamedReconnect {
    request: NamedReconnectRequest,
    addresses: io::Result<Vec<SocketAddr>>,
}

pub(super) struct NamedLookupHint {
    raw: String,
    fingerprint: [u8; 32],
    addresses: Vec<SocketAddr>,
    expires: Instant,
}

impl NamedLookupHint {
    fn matches(&self, request: &NamedReconnectRequest) -> bool {
        self.raw == request.raw
            && self.fingerprint == request.fingerprint
            && self.expires > Instant::now()
    }
}

impl NamedReconnectRequest {
    pub fn resolve(self) -> ResolvedNamedReconnect {
        let addresses = crate::endpoint::resolve_fresh_client_ipv4_addresses(
            &self.raw,
            Instant::now() + Duration::from_secs(15),
        );
        ResolvedNamedReconnect {
            request: self,
            addresses,
        }
    }
}

pub fn named_reconnect_profile(row: &Value, raw: &str) -> bool {
    direct_endpoint_profile(row)
        && !has_saved_edit(row)
        && row.get(PENDING_ENDPOINT_RESTART).is_none()
        && s(wire(row), "endpoint") == raw
        && hostname_port(raw).is_some()
}

type Scope<'a> = dyn Fn(&str, &str, &str) -> io::Result<Option<u64>> + 'a;
type Validate<'a> = dyn Fn(NamedReconnectTarget<'_>) -> io::Result<()> + 'a;
type DnsFailure<'a> = dyn Fn() -> Option<u64> + 'a;

pub(super) struct Collector<'a> {
    scope: &'a Scope<'a>,
    requests: Vec<NamedReconnectRequest>,
}

struct Cursor {
    candidate: String,
    since: u64,
    attempt: u64,
    attempts: u32,
    tried: u16,
    exhausted: bool,
}

fn same_policy_revision(doc: &Value, id: &str, revision: u64) -> bool {
    doc["routing_revision"].as_u64().unwrap_or_default() == revision
        && confirmed_routing_revision(doc, id) == Some(revision)
}

impl Cursor {
    fn matches(&self, recovery: &Recovery) -> bool {
        self.candidate == recovery.candidate
            && self.since == recovery.since
            && self.attempt == recovery.attempt
            && self.attempts == recovery.attempts
            && self.tried == recovery.tried
            && self.exhausted == recovery.exhausted
    }
}

impl Collector<'_> {
    pub(super) fn collect(
        &mut self,
        doc: &Value,
        row: &Value,
        spec: &Spec,
        recovery: &mut Recovery,
        previous: (u16, bool),
        alive: bool,
    ) -> io::Result<bool> {
        let Some(revision) = (self.scope)(&spec.id, &spec.iface, &spec.endpoint)? else {
            return Ok(false);
        };
        if !same_policy_revision(doc, &spec.id, revision) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let ticket = Arc::new(());
        recovery.named_ticket = Some(ticket.clone());
        self.requests.push(NamedReconnectRequest {
            ticket,
            id: spec.id.clone(),
            iface: spec.iface.clone(),
            raw: spec.endpoint.clone(),
            revision,
            fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
            row: row.clone(),
            cursor: Cursor {
                candidate: recovery.candidate.clone(),
                since: recovery.since,
                attempt: recovery.attempt,
                attempts: recovery.attempts,
                tried: previous.0,
                exhausted: previous.1,
            },
            next: (recovery.tried, recovery.exhausted),
            alive,
        });
        Ok(true)
    }
}

impl Runtime {
    pub fn recover_clients_with_named_reconnect(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        (park, read_retry, prepare_retry): (
            impl Fn(&RoutedMtuChange) -> io::Result<()>,
            impl Fn(&RoutedMtuChange) -> io::Result<RoutedEndpointLaunch>,
            impl Fn(&RoutedMtuChange, SocketAddr) -> io::Result<()>,
        ),
        (input, scope, validate): (
            NamedReconnectInput,
            impl Fn(&str, &str, &str) -> io::Result<Option<u64>>,
            impl Fn(NamedReconnectTarget<'_>) -> io::Result<()>,
        ),
    ) -> io::Result<ClientRecoveryPass> {
        self.recover_clients_with_named_reconnect_policy(
            db,
            wan,
            refresh,
            (park, read_retry, prepare_retry),
            (input, scope, validate, || None),
        )
    }

    /// An already accepted lookup may be reused only while the failed policy is current.
    pub fn recover_clients_with_named_reconnect_policy(
        &self,
        db: &Store,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
        (park, read_retry, prepare_retry): (
            impl Fn(&RoutedMtuChange) -> io::Result<()>,
            impl Fn(&RoutedMtuChange) -> io::Result<RoutedEndpointLaunch>,
            impl Fn(&RoutedMtuChange, SocketAddr) -> io::Result<()>,
        ),
        (input, scope, validate, dns_failure): (
            NamedReconnectInput,
            impl Fn(&str, &str, &str) -> io::Result<Option<u64>>,
            impl Fn(NamedReconnectTarget<'_>) -> io::Result<()>,
            impl Fn() -> Option<u64>,
        ),
    ) -> io::Result<ClientRecoveryPass> {
        let _deployment = self.deployment_guard()?;
        match input {
            NamedReconnectInput::Collect => {
                let mut collector = Collector {
                    scope: &scope,
                    requests: Vec::new(),
                };
                let events = self.recover_clients_pass(
                    db,
                    wan,
                    Some(&refresh),
                    Some(&park),
                    Some(RoutedRetryHooks {
                        read: &read_retry,
                        prepare: &prepare_retry,
                    }),
                    Some(&mut collector),
                )?;
                Ok(ClientRecoveryPass {
                    events,
                    named_reconnects: collector.requests,
                })
            }
            NamedReconnectInput::Apply(resolved) => {
                let events = self.apply_named_reconnects(
                    db,
                    wan,
                    &refresh,
                    resolved,
                    (&scope, &validate, &dns_failure),
                )?;
                Ok(ClientRecoveryPass {
                    events,
                    named_reconnects: Vec::new(),
                })
            }
        }
    }

    fn apply_named_reconnects(
        &self,
        db: &Store,
        wan: &[String],
        refresh: &RefreshTransport<'_>,
        resolved: Vec<ResolvedNamedReconnect>,
        (scope, validate, dns_failure): (&Scope<'_>, &Validate<'_>, &DnsFailure<'_>),
    ) -> io::Result<Vec<String>> {
        if resolved.is_empty() {
            return Ok(Vec::new());
        }
        let mut owned = self
            .clients
            .0
            .lock()
            .map_err(|_| invalid("менеджер AWG недоступен"))?;
        let doc = read(db)?;
        let inherited = self.capture_inherited_transport(&doc, &owned, wan);
        let audit = AttemptContext {
            db,
            doc: &doc,
            scope,
            validate,
            dns_failure,
        };
        let mut events = Vec::new();
        for resolved in resolved {
            let id = resolved.request.id.clone();
            if let Some(managed) = owned.get_mut(&id) {
                if let Err(error) = apply_attempt(
                    &audit,
                    managed,
                    resolved,
                    |endpoint| inherited.prepare(refresh, endpoint),
                    |spec| {
                        self.record_nested(&spec.iface, false);
                        self.start_local(spec, wan)
                    },
                ) {
                    managed.recovery.error = error.to_string();
                    events.push(format!("{id}: переподключение AWG: {error}"));
                }
            }
        }
        Ok(events)
    }
}

struct AttemptContext<'a> {
    db: &'a Store,
    doc: &'a Value,
    scope: &'a Scope<'a>,
    validate: &'a Validate<'a>,
    dns_failure: &'a DnsFailure<'a>,
}

fn remains_failed(
    tunnel: &mut dyn Tunnel,
    recovery: &mut Recovery,
    expected_alive: bool,
    settings: &Value,
) -> bool {
    let alive = tunnel.alive();
    if alive != expected_alive {
        return false;
    }
    let snapshot = if alive { tunnel.snapshot().ok() } else { None };
    let now = crate::now();
    recovery.adjust_clock(now, Instant::now());
    recovery.observe(now, alive, snapshot.as_ref(), settings) == Action::Reconnect
}

fn apply_attempt(
    ctx: &AttemptContext<'_>,
    managed: &mut Managed,
    resolved: ResolvedNamedReconnect,
    refresh: impl FnOnce(SocketAddr) -> io::Result<()>,
    start: impl FnOnce(Spec) -> io::Result<Box<dyn Tunnel>>,
) -> io::Result<()> {
    let ResolvedNamedReconnect { request, addresses } = resolved;
    let recovery = &mut managed.recovery;
    if !recovery
        .named_ticket
        .as_ref()
        .is_some_and(|ticket| Arc::ptr_eq(ticket, &request.ticket))
    {
        return Ok(());
    }
    recovery.named_ticket = None;
    let Ok(row) = find(ctx.doc, &request.id) else {
        return Ok(());
    };
    if row != &request.row
        || !named_reconnect_profile(row, &request.raw)
        || !same_policy_revision(ctx.doc, &request.id, request.revision)
        || managed.iface != request.iface
        || managed.fingerprint != request.fingerprint
        || managed.tunnel.inherited()
        || managed.tunnel.nested_iface().is_some()
        || !request.cursor.matches(recovery)
    {
        return Ok(());
    }
    let mut spec = specification(ctx.doc, row)?;
    if spec.iface != request.iface
        || Sha256::digest(spec.conf.as_bytes()).as_slice() != request.fingerprint
        || spec.endpoint != request.raw
    {
        return Ok(());
    }
    let settings = crate::recovery_settings(&ctx.doc["recovery_settings"]);
    if !remains_failed(managed.tunnel.as_mut(), recovery, request.alive, &settings)
        || (ctx.scope)(&request.id, &request.iface, &request.raw)? != Some(request.revision)
    {
        return Ok(());
    }
    let mut fallback = None;
    let addresses = addresses.or_else(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::TimedOut | io::ErrorKind::ConnectionAborted
        ) {
            if let Some(hint) = recovery
                .named_hint
                .as_ref()
                .filter(|hint| hint.matches(&request))
            {
                if let Some(generation) = (ctx.dns_failure)() {
                    fallback = Some((generation, hint.expires));
                    return Ok(hint.addresses.clone());
                }
            }
        }
        Err(error)
    });
    let selected = addresses.and_then(|addresses| {
        let selected = selected_named_address(&request.raw, &addresses)?;
        let target = NamedReconnectTarget {
            id: &request.id,
            iface: &request.iface,
            raw: &request.raw,
            revision: request.revision,
            selected,
            addresses: &addresses,
        };
        target.validate()?;
        Ok((selected, addresses))
    });
    let result = match selected {
        Ok((endpoint, addresses)) => {
            check_recovery_row(ctx.db, row)?;
            (ctx.validate)(NamedReconnectTarget {
                id: &request.id,
                iface: &request.iface,
                raw: &request.raw,
                revision: request.revision,
                selected: endpoint,
                addresses: &addresses,
            })?;
            refresh(endpoint)?;
            if !remains_failed(managed.tunnel.as_mut(), recovery, request.alive, &settings) {
                return Ok(());
            }
            let current = read(ctx.db)?;
            if find(&current, &request.id)? != row
                || !same_policy_revision(&current, &request.id, request.revision)
                || fallback.is_some_and(|(generation, expires)| {
                    expires <= Instant::now() || (ctx.dns_failure)() != Some(generation)
                })
            {
                return Ok(());
            }
            if fallback.is_none() {
                recovery.named_hint = Some(NamedLookupHint {
                    raw: request.raw.clone(),
                    fingerprint: request.fingerprint,
                    addresses,
                    expires: Instant::now() + HINT_TTL,
                });
            }
            spec.endpoint = endpoint.to_string();
            (|| {
                managed.tunnel.stop()?;
                recovery.nested.launched(crate::now(), false);
                managed.tunnel = Box::new(Stopped);
                managed.tunnel = start(spec)?;
                Ok(())
            })()
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
        Err(error) => Err(error),
    };
    (recovery.tried, recovery.exhausted) = request.next;
    recovery.candidate = request.raw;
    recovery.attempted(crate::now(), &result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };

    const HOST: &str = "Named.Example.:2408";
    const REVISION: u64 = 17;

    struct Owner {
        running: Arc<AtomicBool>,
        handshake: Arc<AtomicU64>,
    }

    impl Tunnel for Owner {
        fn alive(&mut self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
        fn stop(&mut self) -> io::Result<()> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn probe(&mut self) -> io::Result<()> {
            unreachable!()
        }
        fn snapshot(&self) -> io::Result<Value> {
            Ok(json!({
                "running": self.running.load(Ordering::SeqCst),
                "last_handshake": self.handshake.load(Ordering::SeqCst),
                "endpoint": "192.0.2.8:2408",
                "socket_mark": 0
            }))
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        db: Store,
        runtime: Runtime,
        id: String,
        running: Arc<AtomicBool>,
        handshake: Arc<AtomicU64>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db = Store::open(dir.path()).unwrap();
            let runtime = Runtime::new(dir.path(), dir.path().join("no-engine"));
            crate::import(&db, &crate::tests::input(), "imported").unwrap();
            let id = s(active(&read(&db).unwrap()).unwrap(), "id").to_owned();
            crate::edit_document(&db, |doc| {
                doc["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["id"] == id)
                    .unwrap()["config"]["endpoint"] = json!(HOST);
                Ok(())
            })
            .unwrap();
            let running = Arc::new(AtomicBool::new(true));
            let handshake = Arc::new(AtomicU64::new(0));
            runtime
                .clients
                .up(&db, Some(&id), |_| {
                    Ok(Box::new(Owner {
                        running: running.clone(),
                        handshake: handshake.clone(),
                    }))
                })
                .unwrap();
            crate::edit_document(&db, |doc| {
                doc["routing_revision"] = json!(REVISION);
                doc["rust_static_routing"] = json!({
                    "revision":REVISION,"pending_commit":false,"targets":[id],"committed_targets":[id]
                });
                Ok(())
            }).unwrap();
            {
                let mut owned = runtime.clients.0.lock().unwrap();
                let recovery = &mut owned.get_mut(&id).unwrap().recovery;
                recovery.since = crate::now().saturating_sub(120);
                recovery.attempt = recovery.since;
                recovery.attempts = 1;
            }
            Self {
                _dir: dir,
                db,
                runtime,
                id,
                running,
                handshake,
            }
        }

        fn collect(&self) -> NamedReconnectRequest {
            let pass = self
                .runtime
                .recover_clients_with_named_reconnect(
                    &self.db,
                    &[],
                    |_| unreachable!(),
                    (
                        |_: &RoutedMtuChange| unreachable!(),
                        |_: &RoutedMtuChange| unreachable!(),
                        |_: &RoutedMtuChange, _| unreachable!(),
                    ),
                    (
                        NamedReconnectInput::Collect,
                        |id: &str, _: &str, raw: &str| {
                            assert_eq!(id, self.id);
                            assert_eq!(raw, HOST);
                            Ok(Some(REVISION))
                        },
                        |_: NamedReconnectTarget<'_>| unreachable!(),
                    ),
                )
                .unwrap();
            assert_eq!(pass.named_reconnects.len(), 1);
            assert!(self.running.load(Ordering::SeqCst));
            pass.named_reconnects.into_iter().next().unwrap()
        }
    }

    #[test]
    fn named_watchdog_reconnect_validates_and_refreshes_before_retiring() {
        let fixture = Fixture::new();
        let request = fixture.collect();
        let first = "192.0.2.18:2408".parse().unwrap();
        let second = "192.0.2.19:2408".parse().unwrap();
        let order = RefCell::new(Vec::new());
        let doc = read(&fixture.db).unwrap();
        let ctx = AttemptContext {
            db: &fixture.db,
            doc: &doc,
            scope: &|_, _, _| Ok(Some(REVISION)),
            dns_failure: &|| unreachable!("a fresh answer always wins"),
            validate: &|target| {
                target.validate()?;
                assert_eq!(target.id, fixture.id);
                assert_eq!(target.raw, HOST);
                assert_eq!(target.selected, first);
                assert_eq!(target.addresses, [first, second]);
                assert!(fixture.running.load(Ordering::SeqCst));
                order.borrow_mut().push("validate");
                Ok(())
            },
        };
        let mut owned = fixture.runtime.clients.0.lock().unwrap();
        let managed = owned.get_mut(&fixture.id).unwrap();
        managed.recovery.named_hint = Some(NamedLookupHint {
            raw: HOST.into(),
            fingerprint: managed.fingerprint,
            addresses: vec!["192.0.2.99:2408".parse().unwrap()],
            expires: Instant::now() + HINT_TTL,
        });
        apply_attempt(
            &ctx,
            managed,
            ResolvedNamedReconnect {
                request,
                addresses: Ok(vec![first, second]),
            },
            |endpoint| {
                assert_eq!(endpoint, first);
                assert!(fixture.running.load(Ordering::SeqCst));
                order.borrow_mut().push("refresh");
                Ok(())
            },
            |spec| {
                assert!(!fixture.running.load(Ordering::SeqCst));
                assert_eq!(spec.endpoint, first.to_string());
                assert!(spec
                    .conf
                    .lines()
                    .any(|line| line == format!("Endpoint = {HOST}")));
                order.borrow_mut().push("start");
                Ok(Box::new(Stopped))
            },
        )
        .unwrap();
        assert_eq!(*order.borrow(), ["validate", "refresh", "start"]);
        assert_eq!(managed.recovery.attempts, 2);
        assert_eq!(managed.recovery.selected(), Some(HOST));
        let hint = managed.recovery.named_hint.as_ref().unwrap();
        assert_eq!(hint.addresses, [first, second]);
        assert_eq!(hint.fingerprint, managed.fingerprint);
    }

    #[test]
    fn named_watchdog_reconnect_drops_stale_or_healthy_requests_without_spending_attempt() {
        for stale in [true, false] {
            let fixture = Fixture::new();
            let request = fixture.collect();
            let tried = (request.cursor.tried, request.cursor.exhausted);
            if stale {
                crate::edit_document(&fixture.db, |doc| {
                    doc["rust_static_routing"]["revision"] = json!(REVISION + 1);
                    Ok(())
                })
                .unwrap();
            } else {
                fixture.handshake.store(crate::now(), Ordering::SeqCst);
            }
            let doc = read(&fixture.db).unwrap();
            let ctx = AttemptContext {
                db: &fixture.db,
                doc: &doc,
                scope: &|_, _, _| unreachable!(),
                validate: &|_| unreachable!(),
                dns_failure: &|| unreachable!(),
            };
            let mut owned = fixture.runtime.clients.0.lock().unwrap();
            let managed = owned.get_mut(&fixture.id).unwrap();
            apply_attempt(
                &ctx,
                managed,
                ResolvedNamedReconnect {
                    request,
                    addresses: Err(io::ErrorKind::NotFound.into()),
                },
                |_| unreachable!(),
                |_| unreachable!(),
            )
            .unwrap();
            assert!(fixture.running.load(Ordering::SeqCst));
            assert_eq!((managed.recovery.tried, managed.recovery.exhausted), tried);
            assert_eq!(managed.recovery.attempts, u32::from(stale));
            assert!(managed.recovery.named_ticket.is_none());
        }
    }

    #[test]
    fn named_watchdog_reconnect_skips_retirement_if_peer_recovers_during_refresh() {
        let fixture = Fixture::new();
        let request = fixture.collect();
        let doc = read(&fixture.db).unwrap();
        let ctx = AttemptContext {
            db: &fixture.db,
            doc: &doc,
            scope: &|_, _, _| Ok(Some(REVISION)),
            validate: &|_| Ok(()),
            dns_failure: &|| None,
        };
        let mut owned = fixture.runtime.clients.0.lock().unwrap();
        let managed = owned.get_mut(&fixture.id).unwrap();
        apply_attempt(
            &ctx,
            managed,
            ResolvedNamedReconnect {
                request,
                addresses: Ok(vec!["192.0.2.18:2408".parse().unwrap()]),
            },
            |_| {
                fixture.handshake.store(crate::now(), Ordering::SeqCst);
                Ok(())
            },
            |_| unreachable!(),
        )
        .unwrap();
        assert!(fixture.running.load(Ordering::SeqCst));
        assert_eq!(managed.recovery.attempts, 0);
    }

    #[test]
    fn named_watchdog_reconnect_skips_retirement_if_draft_changes_during_refresh() {
        let fixture = Fixture::new();
        let request = fixture.collect();
        let doc = read(&fixture.db).unwrap();
        let ctx = AttemptContext {
            db: &fixture.db,
            doc: &doc,
            scope: &|_, _, _| Ok(Some(REVISION)),
            validate: &|_| Ok(()),
            dns_failure: &|| None,
        };
        let mut owned = fixture.runtime.clients.0.lock().unwrap();
        let managed = owned.get_mut(&fixture.id).unwrap();
        apply_attempt(
            &ctx,
            managed,
            ResolvedNamedReconnect {
                request,
                addresses: Ok(vec!["192.0.2.18:2408".parse().unwrap()]),
            },
            |_| {
                crate::edit_document(&fixture.db, |doc| {
                    doc["routing_revision"] = json!(REVISION + 1);
                    Ok(())
                })
            },
            |_| unreachable!(),
        )
        .unwrap();
        let current = read(&fixture.db).unwrap();
        assert_eq!(
            confirmed_routing_revision(&current, &fixture.id),
            Some(REVISION)
        );
        assert!(fixture.running.load(Ordering::SeqCst));
        assert_eq!(managed.recovery.attempts, 1);
    }

    #[test]
    fn named_watchdog_reconnect_spends_only_current_dns_failure() {
        for (kind, attempts) in [(io::ErrorKind::NotFound, 2), (io::ErrorKind::WouldBlock, 1)] {
            let fixture = Fixture::new();
            let request = fixture.collect();
            let doc = read(&fixture.db).unwrap();
            let ctx = AttemptContext {
                db: &fixture.db,
                doc: &doc,
                scope: &|_, _, _| Ok(Some(REVISION)),
                validate: &|_| unreachable!(),
                dns_failure: &|| None,
            };
            let mut owned = fixture.runtime.clients.0.lock().unwrap();
            let managed = owned.get_mut(&fixture.id).unwrap();
            let error = apply_attempt(
                &ctx,
                managed,
                ResolvedNamedReconnect {
                    request,
                    addresses: Err(kind.into()),
                },
                |_| unreachable!(),
                |_| unreachable!(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(managed.recovery.attempts, attempts);
            assert!(fixture.running.load(Ordering::SeqCst));
        }
    }

    fn remember_hint(managed: &mut Managed, expires: Instant) -> SocketAddr {
        let address = "192.0.2.43:2408".parse().unwrap();
        managed.recovery.named_hint = Some(NamedLookupHint {
            raw: HOST.into(),
            fingerprint: managed.fingerprint,
            addresses: vec![address],
            expires,
        });
        address
    }

    #[test]
    fn named_watchdog_dns_hint_requires_current_failure_and_does_not_extend_expiry() {
        for recover_during_refresh in [false, true] {
            let fixture = Fixture::new();
            let request = fixture.collect();
            let doc = read(&fixture.db).unwrap();
            let gate = Cell::new(Some(7));
            let lifetime = Instant::now() + Duration::from_secs(10);
            let mut owned = fixture.runtime.clients.0.lock().unwrap();
            let managed = owned.get_mut(&fixture.id).unwrap();
            let old = remember_hint(managed, lifetime);
            let ctx = AttemptContext {
                db: &fixture.db,
                doc: &doc,
                scope: &|_, _, _| Ok(Some(REVISION)),
                validate: &|target| {
                    assert_eq!(target.selected, old);
                    assert_eq!(target.addresses, [old]);
                    assert!(fixture.running.load(Ordering::SeqCst));
                    target.validate()
                },
                dns_failure: &|| gate.get(),
            };
            apply_attempt(
                &ctx,
                managed,
                ResolvedNamedReconnect {
                    request,
                    addresses: Err(io::ErrorKind::ConnectionAborted.into()),
                },
                |address| {
                    assert_eq!(address, old);
                    assert!(fixture.running.load(Ordering::SeqCst));
                    if recover_during_refresh {
                        gate.set(None);
                    }
                    Ok(())
                },
                |spec| {
                    assert!(!recover_during_refresh);
                    assert_eq!(spec.endpoint, old.to_string());
                    assert!(!fixture.running.load(Ordering::SeqCst));
                    Ok(Box::new(Stopped))
                },
            )
            .unwrap();
            assert_eq!(
                fixture.running.load(Ordering::SeqCst),
                recover_during_refresh
            );
            assert_eq!(
                managed.recovery.attempts,
                if recover_during_refresh { 1 } else { 2 }
            );
            assert_eq!(
                managed.recovery.named_hint.as_ref().unwrap().expires,
                lifetime
            );
        }
    }

    #[test]
    fn named_watchdog_dns_hint_refuses_healthy_gate_expiry_and_local_error() {
        for (failure, expired, kind) in [
            (None, false, io::ErrorKind::NotFound),
            (Some(7), true, io::ErrorKind::TimedOut),
            (Some(7), false, io::ErrorKind::InvalidInput),
            (Some(7), false, io::ErrorKind::WouldBlock),
        ] {
            let fixture = Fixture::new();
            let request = fixture.collect();
            let doc = read(&fixture.db).unwrap();
            let ctx = AttemptContext {
                db: &fixture.db,
                doc: &doc,
                scope: &|_, _, _| Ok(Some(REVISION)),
                validate: &|_| unreachable!(),
                dns_failure: &|| {
                    assert_eq!(kind, io::ErrorKind::NotFound);
                    failure
                },
            };
            let mut owned = fixture.runtime.clients.0.lock().unwrap();
            let managed = owned.get_mut(&fixture.id).unwrap();
            remember_hint(
                managed,
                Instant::now() + if expired { Duration::ZERO } else { HINT_TTL },
            );
            let error = apply_attempt(
                &ctx,
                managed,
                ResolvedNamedReconnect {
                    request,
                    addresses: Err(kind.into()),
                },
                |_| unreachable!(),
                |_| unreachable!(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert!(fixture.running.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn named_watchdog_dns_hint_cannot_run_after_a_profile_edit_is_staged() {
        let fixture = Fixture::new();
        let request = fixture.collect();
        crate::edit_document(&fixture.db, |doc| {
            let row = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["id"] == fixture.id)
                .unwrap();
            row[crate::client::settings::PENDING_PROFILE] = json!(request.fingerprint);
            Ok(())
        })
        .unwrap();
        let doc = read(&fixture.db).unwrap();
        let ctx = AttemptContext {
            db: &fixture.db,
            doc: &doc,
            scope: &|_, _, _| unreachable!(),
            validate: &|_| unreachable!(),
            dns_failure: &|| unreachable!(),
        };
        let mut owned = fixture.runtime.clients.0.lock().unwrap();
        let managed = owned.get_mut(&fixture.id).unwrap();
        remember_hint(managed, Instant::now() + HINT_TTL);
        apply_attempt(
            &ctx,
            managed,
            ResolvedNamedReconnect {
                request,
                addresses: Err(io::ErrorKind::TimedOut.into()),
            },
            |_| unreachable!(),
            |_| unreachable!(),
        )
        .unwrap();
        assert!(fixture.running.load(Ordering::SeqCst));
        assert_eq!(managed.recovery.attempts, 1);
    }
}
