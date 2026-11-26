use super::{ineligible, mtu_edit::canonical_socket, row, ActiveReplacementPeer, Journal, Store};
use nfqws2_awg_profile::{
    active_named_replacement_fingerprint, active_replacement_endpoint,
    active_replacement_fingerprint, exact_route_hostname, resolve_initial_named_active_replacement,
    validate_active_named_replacement, validate_warm_named_ipv6, verify_warm_named_ipv4_failure,
    ActiveReplacementLaunchPin,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    id: String,
    raw: String,
    fingerprint: [u8; 32],
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    answers: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unresolved: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    warm_ipv6: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::kernel) struct TransportClaims([Endpoint; 2]);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedTransportPair {
    pub claims: TransportClaims,
    selected: [Option<SocketAddr>; 2],
}

impl SealedTransportPair {
    pub fn binds(&self, owners: [(&str, &[u8; 32]); 2]) -> bool {
        if self.claims.0[0].warm_ipv6 || self.is_warm_ipv6() && !self.claims.0[0].answers.is_empty()
        {
            return false;
        }
        self.target_unresolved().map_or_else(
            || {
                self.claims
                    .0
                    .iter()
                    .any(|transport| !transport.answers.is_empty())
            },
            |_| self.claims.0[0].answers.is_empty(),
        ) && self
            .claims
            .0
            .iter()
            .zip(self.selected)
            .zip(owners)
            .enumerate()
            .all(|(index, ((transport, selected), (id, fingerprint)))| {
                transport.id == id
                    && &transport.fingerprint == fingerprint
                    && match selected {
                        Some(selected) => transport.valid_selection(selected),
                        None => index == 1 && transport.valid_unresolved(),
                    }
            })
    }

    pub fn selected(&self, published: bool) -> Option<SocketAddr> {
        self.selected[usize::from(published)]
    }

    pub fn is_warm_ipv6(&self) -> bool {
        self.claims.0[1].warm_ipv6
    }

    pub(super) fn warm_target_addresses(&self) -> &[SocketAddr] {
        if self.is_warm_ipv6() {
            &self.claims.0[1].answers
        } else {
            &[]
        }
    }

    pub fn target_name(&self) -> Option<&str> {
        let target = &self.claims.0[1];
        (!target.answers.is_empty() || target.valid_unresolved()).then_some(target.raw.as_str())
    }

    pub fn target_unresolved(&self) -> Option<&str> {
        let target = &self.claims.0[1];
        (self.selected[1].is_none() && target.valid_unresolved()).then_some(target.raw.as_str())
    }

    pub fn rotated_target(&self, answers: &[SocketAddr]) -> io::Result<Self> {
        if self.is_warm_ipv6() {
            return Err(ineligible());
        }
        self.target_name().ok_or_else(ineligible)?;
        let mut pair = self.clone();
        let selected = answers
            .iter()
            .copied()
            .find(SocketAddr::is_ipv4)
            .ok_or_else(ineligible)?;
        let target = &mut pair.claims.0[1];
        target.answers = answers.to_vec();
        target.unresolved = false;
        if !target.valid_selection(selected) {
            return Err(ineligible());
        }
        pair.selected[1] = Some(selected);
        Ok(pair)
    }
}

impl Endpoint {
    fn valid_selection(&self, selected: SocketAddr) -> bool {
        if self.unresolved
            || self.raw.trim() != self.raw
            || selected.is_ipv6() != self.warm_ipv6
            || canonical_socket(selected) != Some(selected)
        {
            return false;
        }
        if self.warm_ipv6 {
            return self.answers.first() == Some(&selected)
                && self.answers.iter().all(SocketAddr::is_ipv6)
                && self.valid_named_answers();
        }
        if self.answers.is_empty() {
            return self
                .raw
                .parse::<SocketAddr>()
                .ok()
                .and_then(canonical_socket)
                == Some(selected);
        }
        self.answers.contains(&selected) && self.valid_named_answers()
    }

    fn valid_unresolved(&self) -> bool {
        self.unresolved
            && !self.warm_ipv6
            && self.answers.iter().all(SocketAddr::is_ipv6)
            && self.valid_named_answers()
    }

    fn valid_named_answers(&self) -> bool {
        let Some((host, port)) = self.raw.rsplit_once(':') else {
            return false;
        };
        let Ok(port) = port.parse::<u16>() else {
            return false;
        };
        port != 0
            && !host.contains(':')
            && exact_route_hostname(host).is_some()
            && self.answers.len() <= 16
            && self.answers.iter().enumerate().all(|(index, &answer)| {
                port == answer.port()
                    && canonical_socket(answer) == Some(answer)
                    && !self.answers[..index].contains(&answer)
            })
    }
}

/// Complete freshly resolved transport claims for one pair of running profiles.
pub struct NamedActiveReplacement {
    prior: Journal,
    pub(super) claims: TransportClaims,
    until: Instant,
}

/// The exact current native IPv4 transfer layout and its single cold target.
/// A resolver may observe a candidate only for this immutable raw profile.
#[derive(Clone, Eq, PartialEq)]
pub struct WarmNamedReplacementRequest {
    prior: Journal,
    source: Endpoint,
    target: Endpoint,
    host: String,
    port: u16,
}

impl WarmNamedReplacementRequest {
    pub fn verify_current_ipv4_failure(&self, db: &Store, deadline: Instant) -> io::Result<()> {
        verify_warm_named_ipv4_failure(&nfqws2_awg_profile::read(db)?, self.target(), deadline)
    }

    pub fn source(&self) -> &str {
        &self.source.id
    }
    pub fn target(&self) -> &str {
        &self.target.id
    }
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn authorize(
        &self,
        db: &Store,
        addresses: &[IpAddr],
        expires: Instant,
    ) -> io::Result<NamedActiveReplacement> {
        if expires <= Instant::now() || warm_named_replacement_request(db)?.as_ref() != Some(self) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut target = self.target.clone();
        target.answers = addresses
            .iter()
            .map(|&ip| SocketAddr::new(ip, self.port))
            .collect();
        let packet = target.answers.first().copied().ok_or_else(ineligible)?;
        if !target.valid_selection(packet) {
            return Err(ineligible());
        }
        Ok(NamedActiveReplacement {
            prior: self.prior.clone(),
            claims: TransportClaims([self.source.clone(), target]),
            until: expires.min(Instant::now() + Duration::from_secs(12)),
        })
    }
}

pub fn warm_named_replacement_request(
    db: &Store,
) -> io::Result<Option<WarmNamedReplacementRequest>> {
    let prior = Journal::read(db)?;
    let Ok((_, owner)) = super::profile_rebind::native_ipv4_prefixes(&prior) else {
        return Ok(None);
    };
    let doc = nfqws2_awg_profile::read(db)?;
    let revision = prior.committed.revision;
    if doc["routing_revision"].as_u64() != Some(revision)
        || !super::profile_rebind::owner_matches(&doc, &prior, &owner.id, revision)
        || super::active_replacement_in_progress(db)?
        || super::mtu_edit::pending_mtu_edit(db)?
        || super::profile_rebind::pending(&doc)
    {
        return Ok(None);
    }
    let rows = doc["servers"].as_array().ok_or_else(ineligible)?;
    if rows.len() != 2 {
        return Ok(None);
    }
    let candidate = rows
        .iter()
        .find(|row| row["id"] != owner.id)
        .ok_or_else(ineligible)?;
    let id = candidate["id"].as_str().ok_or_else(ineligible)?;
    let Some((host, port)) = candidate["config"]["endpoint"]
        .as_str()
        .and_then(|raw| raw.rsplit_once(':'))
        .and_then(|(host, port)| Some((exact_route_hostname(host)?, port.parse::<u16>().ok()?)))
    else {
        return Ok(None);
    };
    let (Ok(source_fingerprint), Ok(target_fingerprint)) = (
        active_replacement_fingerprint(&doc, &owner.id),
        active_named_replacement_fingerprint(&doc, id),
    ) else {
        return Ok(None);
    };
    if candidate["config"]["client"]["standby"] != true
        || candidate["config"]["routing"]["active"] == true
    {
        return Ok(None);
    }
    let source = Endpoint {
        id: owner.id.clone(),
        raw: row(&doc, &owner.id)
            .and_then(|row| row["config"]["endpoint"].as_str())
            .ok_or_else(ineligible)?
            .to_owned(),
        fingerprint: source_fingerprint,
        answers: Vec::new(),
        unresolved: false,
        warm_ipv6: false,
    };
    let target = Endpoint {
        id: id.to_owned(),
        raw: candidate["config"]["endpoint"]
            .as_str()
            .ok_or_else(ineligible)?
            .to_owned(),
        fingerprint: target_fingerprint,
        answers: Vec::new(),
        unresolved: false,
        warm_ipv6: true,
    };
    Ok(Some(WarmNamedReplacementRequest {
        prior,
        source,
        target,
        host: host.to_ascii_lowercase(),
        port,
    }))
}

/// Resolve outside route, profile and Store locks. Kernel admission must still
/// check the exact journal, profiles, live sockets and every returned address.
pub fn prepare_named_active_replacement(
    db: &Store,
    source: &str,
    target: &str,
) -> io::Result<Option<NamedActiveReplacement>> {
    let doc = nfqws2_awg_profile::read(db)?;
    NamedActiveReplacement::prepare_intent(
        db,
        &doc,
        source,
        target,
        resolve_initial_named_active_replacement,
    )
}

impl NamedActiveReplacement {
    #[cfg(test)]
    pub(in crate::kernel) fn prepare(
        db: &Store,
        doc: &Value,
        source: &str,
        target: &str,
        resolve: impl Fn(&Value, &str, Instant) -> io::Result<Vec<SocketAddr>>,
    ) -> io::Result<Option<Self>> {
        Self::prepare_intent(db, doc, source, target, |doc, id, until| {
            resolve(doc, id, until).map(Some)
        })
    }

    pub(in crate::kernel) fn prepare_intent(
        db: &Store,
        doc: &Value,
        source: &str,
        target: &str,
        resolve: impl Fn(&Value, &str, Instant) -> io::Result<Option<Vec<SocketAddr>>>,
    ) -> io::Result<Option<Self>> {
        let has_named = [source, target]
            .iter()
            .any(|id| active_named_replacement_fingerprint(doc, id).is_ok());
        if !has_named {
            return Ok(None);
        }
        let prior = Journal::read(db)?;
        let (_, owner) = match super::profile_rebind::native_ipv4_prefixes(&prior) {
            Ok(result) => result,
            _ => return Ok(None),
        };
        if owner.id != source
            || doc["routing_revision"].as_u64() != Some(prior.committed.revision)
            || source == target
        {
            return Ok(None);
        }
        let until = Instant::now() + Duration::from_secs(12);
        let endpoint = |id: &str| -> io::Result<Endpoint> {
            let raw = row(doc, id)
                .and_then(|row| row["config"]["endpoint"].as_str())
                .ok_or_else(ineligible)?;
            let (fingerprint, answers, unresolved) = if active_replacement_endpoint(doc, id).is_ok()
            {
                (active_replacement_fingerprint(doc, id)?, Vec::new(), false)
            } else {
                let fingerprint = active_named_replacement_fingerprint(doc, id)?;
                let can_defer = id == target && active_replacement_endpoint(doc, source).is_ok();
                match resolve(doc, id, until)? {
                    Some(addresses) if addresses.iter().any(SocketAddr::is_ipv4) => {
                        validate_active_named_replacement(doc, id, &addresses)?;
                        (fingerprint, addresses, false)
                    }
                    Some(addresses) if can_defer && !addresses.is_empty() => {
                        (fingerprint, addresses, true)
                    }
                    None if can_defer => (fingerprint, Vec::new(), true),
                    _ => return Err(io::ErrorKind::NotFound.into()),
                }
            };
            let endpoint = Endpoint {
                id: id.into(),
                raw: raw.into(),
                fingerprint,
                answers,
                unresolved,
                warm_ipv6: false,
            };
            if endpoint.unresolved && !endpoint.valid_unresolved() {
                return Err(ineligible());
            }
            Ok(endpoint)
        };
        let proof = Self {
            prior,
            claims: TransportClaims([endpoint(source)?, endpoint(target)?]),
            until,
        };
        proof.check_expiry()?;
        Ok(Some(proof))
    }

    pub(super) fn check_expiry(&self) -> io::Result<()> {
        if Instant::now() >= self.until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    pub(super) fn verify_scope(
        &self,
        prior: &Journal,
        peers: &[ActiveReplacementPeer; 2],
    ) -> io::Result<()> {
        self.check_expiry()?;
        if self.target_unresolved()
            || &self.prior != prior
            || super::profile_rebind::native_ipv4_prefixes(prior).is_err()
            || peers.iter().zip(&self.claims.0).any(|(peer, endpoint)| {
                peer.owner.id != endpoint.id
                    || peer.owner.nested.is_some()
                    || peer.underlay.is_some()
                    || peer.nested_only
            })
        {
            return Err(ineligible());
        }
        Ok(())
    }

    pub(super) fn seal(&self, peers: &[ActiveReplacementPeer; 2]) -> SealedTransportPair {
        SealedTransportPair {
            claims: self.claims.clone(),
            selected: peers.each_ref().map(|peer| Some(peer.endpoint)),
        }
    }

    /// The second tuple is only the previously authorized launch address.
    /// A running native peer must prove it before forwarding resumes.
    pub(super) fn seal_deferred(
        &self,
        source: &ActiveReplacementPeer,
        pin: Option<ActiveReplacementLaunchPin>,
    ) -> SealedTransportPair {
        SealedTransportPair {
            claims: self.claims.clone(),
            selected: [Some(source.endpoint), pin.map(|pin| pin.endpoint)],
        }
    }

    pub fn target_unresolved(&self) -> bool {
        self.claims.0[1].valid_unresolved()
    }

    pub(super) fn warm_ipv6_addresses(&self) -> &[SocketAddr] {
        let target = &self.claims.0[1];
        if target.warm_ipv6 {
            &target.answers
        } else {
            &[]
        }
    }

    pub(super) fn unselected_ipv6(&self) -> &[SocketAddr] {
        if self.target_unresolved() {
            &self.claims.0[1].answers
        } else {
            &[]
        }
    }

    pub(super) fn verify_unresolved(
        &self,
        prior: &Journal,
        doc: &Value,
        source: &ActiveReplacementPeer,
        target: &str,
    ) -> io::Result<[u8; 32]> {
        self.check_expiry()?;
        let [from, to] = &self.claims.0;
        if &self.prior != prior
            || from.id != source.owner.id
            || from.fingerprint != source.fingerprint
            || !from.valid_selection(source.endpoint)
            || to.id != target
            || !to.valid_unresolved()
            || row(doc, target).and_then(|row| row["config"]["endpoint"].as_str())
                != Some(to.raw.as_str())
            || active_named_replacement_fingerprint(doc, target)? != to.fingerprint
        {
            return Err(ineligible());
        }
        Ok(to.fingerprint)
    }

    pub(super) fn cold_pin(
        &self,
        prior: &Journal,
        source: &str,
        target: &str,
    ) -> io::Result<ActiveReplacementLaunchPin> {
        self.check_expiry()?;
        let [from, to] = &self.claims.0;
        if &self.prior != prior
            || from.id != source
            || to.id != target
            || super::profile_rebind::native_ipv4_prefixes(prior).is_err()
        {
            return Err(ineligible());
        }
        let endpoint = to
            .answers
            .iter()
            .copied()
            .find(|endpoint| endpoint.is_ipv6() == to.warm_ipv6)
            .ok_or_else(ineligible)?;
        Ok(ActiveReplacementLaunchPin {
            endpoint,
            deadline: self.until,
            warm_ipv6: to.warm_ipv6,
        })
    }
}

impl TransportClaims {
    pub(super) fn verify_peer(&self, doc: &Value, peer: &ActiveReplacementPeer) -> io::Result<()> {
        if self.verify_configured(doc, &peer.owner.id, peer.endpoint)? != peer.fingerprint {
            return Err(ineligible());
        }
        Ok(())
    }

    pub(super) fn verify_configured(
        &self,
        doc: &Value,
        id: &str,
        endpoint: SocketAddr,
    ) -> io::Result<[u8; 32]> {
        let row = row(doc, id).ok_or_else(ineligible)?;
        let raw = row["config"]["endpoint"].as_str().ok_or_else(ineligible)?;
        let bound = self
            .0
            .iter()
            .find(|endpoint| endpoint.id == id)
            .ok_or_else(ineligible)?;
        let fingerprint = if bound.answers.is_empty() {
            active_replacement_fingerprint(doc, id)?
        } else if bound.warm_ipv6 {
            validate_warm_named_ipv6(doc, id, &bound.answers)?;
            active_named_replacement_fingerprint(doc, id)?
        } else {
            validate_active_named_replacement(doc, id, &bound.answers)?;
            active_named_replacement_fingerprint(doc, id)?
        };
        if bound.raw != raw || !bound.valid_selection(endpoint) || fingerprint != bound.fingerprint
        {
            return Err(ineligible());
        }
        Ok(fingerprint)
    }

    pub(in crate::kernel) fn addresses(
        &self,
        row: &Value,
        primary: bool,
        raw: &str,
    ) -> io::Result<&[SocketAddr]> {
        self.0
            .iter()
            .find(|endpoint| {
                primary
                    && row["id"] == endpoint.id
                    && raw == endpoint.raw
                    && (!endpoint.answers.is_empty() || endpoint.valid_unresolved())
            })
            .map(|endpoint| endpoint.answers.as_slice())
            .ok_or_else(ineligible)
    }
}
