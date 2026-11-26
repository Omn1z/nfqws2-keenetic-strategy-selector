//! A verified alternate UDP tuple for the owned staged direct profile.
use super::*;

fn unsupported() -> io::Error {
    io::ErrorKind::Unsupported.into()
}

pub(super) fn valid(change: &RoutedMtuChange, selected: SocketAddr) -> bool {
    change.nested_outer.is_none()
        && change.legacy_predecessor.is_none()
        && !change.combines_endpoint_mtu()
        && !named(change)
        && canonical_socket(selected) == Some(selected)
        && edit_endpoints(change).is_some_and(|(_, after)| selected != after)
}

fn row<'a>(doc: &'a Value, change: &RoutedMtuChange) -> io::Result<&'a Value> {
    doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| row["id"] == change.id)
        .ok_or_else(invalid)
}

fn checked_pool(
    candidates: Vec<SocketAddr>,
    change: &RoutedMtuChange,
) -> io::Result<Vec<SocketAddr>> {
    if candidates
        .first()
        .is_some_and(|primary| edit_endpoints(change).is_none_or(|(_, after)| *primary != after))
    {
        return Err(invalid());
    }
    Ok(candidates)
}

fn pool(doc: &Value, change: &RoutedMtuChange) -> io::Result<Vec<SocketAddr>> {
    checked_pool(
        nfqws2_awg_profile::routed_endpoint_retry_pool(row(doc, change)?, change)?,
        change,
    )
}

fn projected_row(doc: &Value, change: &RoutedMtuChange) -> io::Result<Value> {
    let edit = change.endpoint_edit.as_ref().ok_or_else(invalid)?;
    let mut projected = row(doc, change)?.clone();
    if projected["config"]["endpoint"] != edit.before {
        return Err(invalid());
    }
    projected["config"]["endpoint"] = json!(edit.after);
    Ok(projected)
}

pub(super) fn projected_pool(doc: &Value, change: &RoutedMtuChange) -> io::Result<Vec<SocketAddr>> {
    saved_pool(&projected_row(doc, change)?, change)
}

pub(super) fn projected_literal_pool(
    doc: &Value,
    change: &RoutedMtuChange,
) -> io::Result<Option<Vec<SocketAddr>>> {
    nfqws2_awg_profile::routing_direct_literal_pool(&projected_row(doc, change)?)
}

pub(super) fn backup_or_wait(
    k: &Kernel<'_>,
    journal: &Journal,
    candidates: &[SocketAddr],
    literal_pool: Option<&[SocketAddr]>,
    wan: &[String],
) -> io::Result<RoutedEndpointLaunch> {
    for &candidate in candidates.iter().skip(1) {
        address::check_plans(journal, candidate.ip())?;
        if address::has_wan(k, candidate.ip(), wan)? {
            return Ok(RoutedEndpointLaunch::Alternate(candidate));
        }
    }
    if literal_pool == Some(candidates) {
        Ok(RoutedEndpointLaunch::Waiting)
    } else {
        Err(no_wan())
    }
}

fn no_wan() -> io::Error {
    err("ни один резервный endpoint AWG не подтвердил маршрут через WAN")
}

pub(super) fn legacy_choice(choice: RoutedEndpointLaunch) -> io::Result<Option<SocketAddr>> {
    match choice {
        RoutedEndpointLaunch::Primary => Ok(None),
        RoutedEndpointLaunch::Alternate(endpoint) => Ok(Some(endpoint)),
        RoutedEndpointLaunch::Waiting => Err(no_wan()),
    }
}

pub(super) fn check_candidate(
    doc: &Value,
    journal: &Journal,
    change: &RoutedMtuChange,
    selected: SocketAddr,
) -> io::Result<()> {
    if !valid(change, selected)
        || !pool(doc, change)?
            .get(1..)
            .is_some_and(|backups| backups.contains(&selected))
    {
        return Err(invalid());
    }
    address::check_plans(journal, selected.ip())
}

fn forward_profile(doc: &Value, journal: &Journal, authority: &Authority) -> io::Result<Profile> {
    let change = &authority.change;
    if change.nested_outer.is_some()
        || change.legacy_predecessor.is_some()
        || change.combines_endpoint_mtu()
        || named(change)
        || !address::explicit(journal)
    {
        return Err(unsupported());
    }
    let profile = authority.profile(doc)?;
    if !profile.forward || profile.marker.as_ref() != Some(change) {
        return Err(unsupported());
    }
    authority.committed(journal)?;
    address::checked_ip(journal, change, profile.endpoint, true)?;
    Ok(profile)
}

fn pending_forward(
    doc: &Value,
    journal: &Journal,
    authority: &Authority,
) -> io::Result<Vec<SocketAddr>> {
    if forward_profile(doc, journal, authority)?.launch_pending {
        return Err(unsupported());
    }
    let change = &authority.change;
    let candidates = pool(doc, change)?;
    if candidates.is_empty() {
        return Err(unsupported());
    }
    Ok(candidates)
}

fn initial_pool(
    doc: &Value,
    journal: &Journal,
    authority: &Authority,
) -> io::Result<Option<Vec<SocketAddr>>> {
    let change = &authority.change;
    let row = row(doc, change)?;
    if !nfqws2_awg_profile::routed_endpoint_initial_pending(row)? {
        return Ok(None);
    }
    let primary = forward_profile(doc, journal, authority)?
        .endpoint
        .ok_or_else(invalid)?;
    address::check_plans(journal, primary.ip())?;
    let candidates = saved_pool(row, change)?;
    if candidates.is_empty() {
        return Err(unsupported());
    }
    Ok(Some(candidates))
}

fn saved_pool(row: &Value, change: &RoutedMtuChange) -> io::Result<Vec<SocketAddr>> {
    checked_pool(nfqws2_awg_profile::routing_direct_backup_pool(row)?, change)
}

/// Read the selected tuple without acquiring another Store transaction.
/// Recovery can re-arm the saved primary if the recorded reserve was removed.
pub fn pending_endpoint_retry(
    db: &Store,
    change: &RoutedMtuChange,
) -> io::Result<Option<SocketAddr>> {
    let authority = read(db)?.ok_or_else(unsupported)?;
    if authority.change != *change {
        return Err(invalid());
    }
    let journal = Journal::read(db)?;
    let doc = nfqws2_awg_profile::read(db)?;
    pending_forward(&doc, &journal, &authority)?;
    Ok(authority.retry_endpoint)
}

/// Recover an initial selection before launching the new configuration.
/// The existing authorization also survives the transport cleanup phase.
pub fn pending_endpoint_retry_with_wan(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
) -> io::Result<Option<SocketAddr>> {
    legacy_choice(pending_endpoint_launch(db, run, change, wan)?)
}

pub fn pending_endpoint_launch(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    wan: &[String],
) -> io::Result<RoutedEndpointLaunch> {
    let journal = Journal::read(db)?;
    let doc = nfqws2_awg_profile::read(db)?;
    let saved = read(db)?;
    let authority = Authority::bind(&doc, &journal, change, saved.as_ref())?;
    if saved
        .as_ref()
        .is_some_and(|previous| previous != &authority)
        || !journal.preparing.is_empty()
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let profile = forward_profile(&doc, &journal, &authority)?;
    if !profile.launch_pending {
        return pending_endpoint_retry(db, change).map(|selected| {
            selected.map_or(
                RoutedEndpointLaunch::Primary,
                RoutedEndpointLaunch::Alternate,
            )
        });
    }
    let Some(candidates) = initial_pool(&doc, &journal, &authority)? else {
        return authority
            .retry_endpoint
            .map(RoutedEndpointLaunch::Alternate)
            .ok_or_else(unsupported);
    };
    let k = kernel_for_transition(run, db, &journal, &journal.installed)?;
    if let Some(selected) = authority
        .retry_endpoint
        .filter(|selected| candidates[1..].contains(selected))
    {
        address::check_plans(&journal, selected.ip())?;
        if address::has_wan(&k, selected.ip(), wan)? {
            return Ok(RoutedEndpointLaunch::Alternate(selected));
        }
    }
    let primary = candidates[0];
    if address::has_wan(&k, primary.ip(), wan)? {
        return Ok(authority
            .retry_endpoint
            .map_or(RoutedEndpointLaunch::Primary, |_| {
                RoutedEndpointLaunch::Alternate(primary)
            }));
    }
    let literal = nfqws2_awg_profile::routing_direct_literal_pool(row(&doc, change)?)?;
    backup_or_wait(&k, &journal, &candidates, literal.as_deref(), wan)
}

/// Confirm the saved forward edit and exact selected reserve before the
/// client manager can retire its current owned direct daemon.
pub fn prepare_endpoint_retry(
    db: &Store,
    run: &dyn Runner,
    change: &RoutedMtuChange,
    selected: SocketAddr,
    wan: &[String],
) -> io::Result<()> {
    let endpoint = canonical_socket(selected).ok_or_else(invalid)?;
    db.transaction(|tx| {
        let journal = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        let saved = read(db)?;
        let mut authority = Authority::bind(&doc, &journal, change, saved.as_ref())?;
        if saved
            .as_ref()
            .is_some_and(|previous| previous != &authority)
            || !journal.preparing.is_empty()
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let initial = initial_pool(&doc, &journal, &authority)?;
        let before_launch = initial.is_some();
        let cleanup = !before_launch && forward_profile(&doc, &journal, &authority)?.launch_pending;
        let candidates = match initial {
            Some(candidates) => candidates,
            None if cleanup && authority.retry_endpoint == Some(endpoint) => {
                saved_pool(row(&doc, change)?, change)?
            }
            None if saved.is_some() => pending_forward(&doc, &journal, &authority)?,
            None => return Err(unsupported()),
        };
        let primary = edit_endpoints(change).ok_or_else(invalid)?.1;
        let reserve = endpoint != primary;
        if reserve
            && !candidates
                .get(1..)
                .is_some_and(|backups| backups.contains(&endpoint))
            || !reserve && authority.retry_endpoint.is_none()
        {
            return Err(invalid());
        }
        address::check_plans(&journal, endpoint.ip())?;
        let k = kernel_for_transition(run, db, &journal, &journal.installed)?;
        if !journal.installed.empty()
            && journal.boot == boot_id(&k)?
            && k.inventory(&journal.claims(), true)? != objects(&journal.installed)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if before_launch
            && reserve
            && authority.retry_endpoint != Some(endpoint)
            && address::has_wan(&k, primary.ip(), wan)?
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        address::verify_wan(&k, endpoint.ip(), wan)?;
        if !cleanup {
            authority.endpoint_committed = false;
            authority.retry_endpoint = reserve.then_some(endpoint);
        }
        if saved.as_ref() != Some(&authority) {
            authority.save(tx)?;
        }
        park_target(db, tx, &k, &journal, &change.iface, None)
    })
}
