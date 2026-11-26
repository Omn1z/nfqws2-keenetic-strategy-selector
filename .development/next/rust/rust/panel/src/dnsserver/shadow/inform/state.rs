//! Shared DHCPINFORM policy for one Shadow discovery worker.
//!
//! The caller attests WAN ownership before planning and again before committing.
//! Firmware DNS, native lease and PPP decisions remain separate from options.

use super::{probe, unicast, validate, Ack, ReplyTimeout, Target};
use std::{collections::BTreeMap, io, net::Ipv4Addr, time::Duration};
use tokio::time::Instant;

const LIMIT: usize = 8;
const VALIDITY: Duration = Duration::from_secs(5 * 60);
const REFRESH_MARGIN: Duration = Duration::from_secs(60);
const BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Wan {
    pub key: String,
    pub iface: String,
    pub device: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub client: Ipv4Addr,
}

impl Wan {
    fn target(&self, server: Option<Ipv4Addr>) -> Target<'_> {
        Target {
            device: &self.device,
            index: self.index,
            mac: self.mac,
            client: self.client,
            server,
        }
    }

    fn usable(&self, key: &str) -> bool {
        !key.is_empty() && self.key == key && validate(self.target(None)).is_ok()
    }

    fn same_link(&self, other: &Self) -> bool {
        self.key == other.key
            && self.device == other.device
            && self.index == other.index
            && self.mac == other.mac
            && self.client == other.client
    }
}

/// Persisted as proof of the server identifier, without options or backoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KnownTarget {
    pub iface: String,
    pub wan_key: String,
    pub client: Ipv4Addr,
    pub server: Ipv4Addr,
    pub stamp: String,
    /// Unix time from the same trusted firmware clock, when available.
    pub observed_at_epoch: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Options {
    pub wan: Wan,
    pub dns: Vec<Ipv4Addr>,
    pub expires: Instant,
}

impl Options {
    fn current(&self, seen: Instant, owners: &[Wan], local: &[Ipv4Addr]) -> Option<Self> {
        if self.expires <= seen || !owners.contains(&self.wan) {
            return None;
        }
        let mut options = self.clone();
        options.dns.retain(|ip| !local.contains(ip));
        (!options.dns.is_empty()).then_some(options)
    }
}

struct Entry {
    wan: Wan,
    known: KnownTarget,
    options: Option<Options>,
    retry: Option<Instant>,
    refresh: bool,
    prefer_broadcast: bool,
}

impl Entry {
    fn new(wan: Wan, known: KnownTarget) -> Self {
        Self {
            wan,
            known,
            options: None,
            retry: None,
            refresh: false,
            prefer_broadcast: false,
        }
    }

    fn refresh_due(&self, now: Instant) -> bool {
        self.refresh
            || self
                .options
                .as_ref()
                .is_none_or(|options| now + REFRESH_MARGIN >= options.expires)
    }

    fn cooled(&self, now: Instant) -> bool {
        self.retry.is_some_and(|retry| now < retry)
    }

    fn defer_probe(&self, now: Instant) -> bool {
        !self.refresh_due(now) || self.cooled(now) || self.prefer_broadcast
    }

    fn verified_owner<'a>(&self, input: Input<'a>) -> Option<&'a Wan> {
        input.owners.iter().find(|wan| {
            wan.usable(input.key)
                && self.known.iface == wan.iface
                && self.wan.same_link(wan)
                && eligible(self.known.server, wan.client, input.local)
        })
    }
}

#[derive(Default)]
pub(crate) struct State {
    entries: BTreeMap<Ipv4Addr, Entry>,
    broadcast_retry: Option<(Wan, Instant)>,
}

#[derive(Clone, Copy)]
pub(crate) enum Source {
    Authoritative,
    NativeLease,
    Fallback { has_verified_peer: bool },
}

#[derive(Clone, Copy)]
pub(crate) struct Input<'a> {
    pub key: &'a str,
    /// Current physical candidates in firmware order. An alias here must be
    /// verified to own this exact local client, including after an exchange.
    pub owners: &'a [Wan],
    pub local: &'a [Ipv4Addr],
    pub source: Source,
}

#[derive(Debug)]
pub(crate) enum Selection {
    Authoritative,
    NativeLease,
    /// Supersedes ordinary DHCP lease DNS. Keep independently verified PPP.
    Inform(Options),
    /// Keep any current verified lease/PPP evidence and report the error only
    /// when no eligible baseline peer remains.
    Fallback(Option<io::Error>),
}

pub(crate) enum Plan {
    Ready(Selection),
    Probe(Attempt),
}

pub(crate) enum DiscoveryEvent<'a> {
    Target {
        wan: &'a Wan,
        server: Ipv4Addr,
        prefer_broadcast: bool,
    },
    TargetRejected(&'a str),
    Cached(&'a Options),
    Cooldown {
        iface: &'a str,
        next: Instant,
    },
    Broadcast {
        fallback: bool,
    },
    NextBroadcast(&'a str),
}

pub(crate) struct Attempt {
    wan: Wan,
    server: Option<Ipv4Addr>,
    cached: Option<Options>,
}

impl Attempt {
    pub(crate) fn wan(&self) -> &Wan {
        &self.wan
    }

    pub(crate) fn target(&self) -> Target<'_> {
        self.wan.target(self.server)
    }

    pub(in crate::dnsserver::shadow) async fn exchange(
        &self,
        deadline: Instant,
        trace: &super::Trace,
    ) -> io::Result<Ack> {
        probe(self.target(), deadline, trace).await
    }

    fn fallback(self, input: Input<'_>, now: Instant, error: io::Error) -> Selection {
        self.cached(input, now)
            .map_or(Selection::Fallback(Some(error)), Selection::Inform)
    }

    fn cached(&self, input: Input<'_>, now: Instant) -> Option<Options> {
        self.cached
            .as_ref()
            .and_then(|options| options.current(now, input.owners, input.local))
    }
}

impl Source {
    fn authoritative(self) -> Option<Selection> {
        match self {
            Self::Authoritative => Some(Selection::Authoritative),
            Self::NativeLease => Some(Selection::NativeLease),
            Self::Fallback { .. } => None,
        }
    }
}

impl State {
    pub(crate) fn known(&self) -> impl Iterator<Item = &KnownTarget> {
        self.entries.values().map(|entry| &entry.known)
    }

    pub(crate) fn remember(&mut self, wan: &Wan, mut known: KnownTarget, local: &[Ipv4Addr]) {
        if !wan.usable(&known.wan_key)
            || wan.iface != known.iface
            || wan.client != known.client
            || !eligible(known.server, wan.client, local)
        {
            return;
        }
        self.entries.retain(|_, entry| entry.wan.key == wan.key);
        if let Some(entry) = self
            .entries
            .get_mut(&wan.client)
            .filter(|entry| entry.wan.same_link(wan))
        {
            let previous = &entry.known;
            if matches!((previous.observed_at_epoch, known.observed_at_epoch), (Some(old), Some(new)) if new < old)
                || previous.stamp == known.stamp
                    && (!known.stamp.is_empty() || previous.server == known.server)
            {
                return;
            }
            // The two aliases were each attested for this physical WAN. Keep
            // the original watermark identity rather than duplicate targets.
            known.iface.clone_from(&previous.iface);
            if previous.server == known.server {
                entry.refresh = true;
                entry.known = known;
            } else {
                *entry = Entry::new(entry.wan.clone(), known);
            }
        } else if self.entries.len() < LIMIT || self.entries.contains_key(&wan.client) {
            self.entries
                .insert(wan.client, Entry::new(wan.clone(), known));
        }
    }

    /// Call only for newly applied, correlated native ACK/NAK on this exact
    /// WAN. The verified server identity outlives a DNS option withdrawal.
    pub(crate) fn native_reply(&mut self, wan: &Wan) {
        if let Some(entry) = self
            .entries
            .get_mut(&wan.client)
            .filter(|entry| entry.wan.same_link(wan))
        {
            entry.options = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn plan(&mut self, input: Input<'_>, now: Instant) -> Plan {
        self.plan_report(input, now, |_| {})
    }

    pub(crate) fn plan_report(
        &mut self,
        input: Input<'_>,
        now: Instant,
        mut report: impl FnMut(DiscoveryEvent<'_>),
    ) -> Plan {
        if let Some(selection) = input.source.authoritative() {
            return Plan::Ready(selection);
        }
        if input.key.is_empty() {
            return Plan::Ready(Selection::Fallback(None));
        }
        self.entries.retain(|_, entry| {
            let keep = entry.wan.key == input.key
                && !input.owners.iter().any(|wan| {
                    wan.usable(input.key)
                        && wan.client == entry.wan.client
                        && !entry.wan.same_link(wan)
                });
            if !keep {
                report(DiscoveryEvent::TargetRejected(&entry.known.iface));
            }
            keep
        });
        let mut known: Vec<_> = self
            .entries
            .values()
            .filter_map(|entry| {
                let wan = entry.verified_owner(input);
                if wan.is_none() {
                    report(DiscoveryEvent::TargetRejected(&entry.known.iface));
                }
                wan.map(|wan| (entry, wan))
            })
            .collect();
        known.sort_unstable_by(|(a, _), (b, _)| a.known.iface.cmp(&b.known.iface));

        let mut cached = None;
        let mut deferred = None;
        for &(entry, wan) in &known {
            report(DiscoveryEvent::Target {
                wan,
                server: entry.known.server,
                prefer_broadcast: entry.prefer_broadcast,
            });
            let valid = entry
                .options
                .as_ref()
                .and_then(|options| options.current(now, input.owners, input.local));
            if entry.defer_probe(now) {
                if valid.is_some() {
                    cached = valid;
                    break;
                }
                if let Some(next) = entry.retry.filter(|next| *next > now) {
                    report(DiscoveryEvent::Cooldown {
                        iface: &entry.known.iface,
                        next,
                    });
                }
                deferred = Some(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "DHCPINFORM retry is deferred",
                ));
                continue;
            }
            return Plan::Probe(Attempt {
                wan: wan.clone(),
                server: Some(entry.known.server),
                cached: valid,
            });
        }
        let has_base = matches!(
            input.source,
            Source::Fallback {
                has_verified_peer: true
            }
        );
        let broadcast = known
            .iter()
            .find(|(entry, _)| {
                entry.prefer_broadcast && entry.refresh_due(now) && !entry.cooled(now)
            })
            .map(|(_, wan)| *wan)
            .or_else(|| {
                (known.is_empty() && !has_base)
                    .then(|| input.owners.iter().find(|wan| wan.usable(input.key)))
                    .flatten()
            });
        if let Some(wan) = broadcast {
            report(DiscoveryEvent::Broadcast {
                fallback: !known.is_empty(),
            });
            let cooling = self
                .broadcast_retry
                .as_ref()
                .filter(|(previous, next)| previous == wan && now < *next);
            if let Some((_, next)) = cooling {
                report(DiscoveryEvent::Cooldown {
                    iface: &wan.iface,
                    next: *next,
                });
            } else {
                return Plan::Probe(Attempt {
                    wan: wan.clone(),
                    server: None,
                    cached,
                });
            }
            deferred = Some(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DHCPINFORM broadcast retry is deferred",
            ));
        }
        if let Some(options) = cached.as_ref() {
            report(DiscoveryEvent::Cached(options));
        }
        Plan::Ready(cached.map_or(Selection::Fallback(deferred), Selection::Inform))
    }

    fn cached_after(&self, attempt: &Attempt, input: Input<'_>, now: Instant) -> Option<Options> {
        attempt.server?;
        // The one unicast exchange is spent. Later WANs can still supply a
        // verified answer that ordinarily would not require another probe.
        self.entries
            .values()
            .filter(|entry| {
                entry.known.iface > attempt.wan.iface
                    && entry.defer_probe(now)
                    && entry.verified_owner(input).is_some()
            })
            .filter_map(|entry| {
                let options = entry
                    .options
                    .as_ref()
                    .filter(|options| now < options.expires)?;
                Some((&entry.known.iface, options))
            })
            .min_by_key(|(iface, _)| *iface)
            .and_then(|(_, options)| options.current(now, input.owners, input.local))
    }

    /// Complete one actual attempt while the caller still owns the discovery
    /// gate. The caller drops an attempt if the session or observed native
    /// receipt is superseded during the exchange.
    #[cfg(test)]
    pub(crate) fn finish(
        &mut self,
        attempt: Attempt,
        result: io::Result<Ack>,
        input: Input<'_>,
        now: Instant,
        deadline: Instant,
    ) -> Selection {
        self.finish_report(attempt, result, input, now, deadline, |_| {})
    }

    pub(crate) fn finish_report(
        &mut self,
        attempt: Attempt,
        result: io::Result<Ack>,
        input: Input<'_>,
        now: Instant,
        deadline: Instant,
        mut report: impl FnMut(DiscoveryEvent<'_>),
    ) -> Selection {
        if let Some(selection) = input.source.authoritative() {
            return selection;
        }
        let wan = &attempt.wan;
        if !wan.usable(input.key) || !input.owners.contains(wan) {
            return Selection::Fallback(None);
        }
        if self
            .entries
            .get(&wan.client)
            .is_some_and(|entry| !entry.wan.same_link(wan))
        {
            return Selection::Fallback(None);
        }
        if now >= deadline {
            return attempt.fallback(input, now, io::ErrorKind::TimedOut.into());
        }
        if let Err(error) = &result {
            if error.kind() == io::ErrorKind::Interrupted {
                return attempt.fallback(input, now, io::ErrorKind::Interrupted.into());
            }
        }
        if let Some(server) = attempt.server {
            if !self.entries.get(&wan.client).is_some_and(|entry| {
                entry.verified_owner(input) == Some(wan) && entry.known.server == server
            }) {
                return Selection::Fallback(None);
            }
        } else {
            self.broadcast_retry = Some((wan.clone(), now + BACKOFF));
        }
        let checked = result.and_then(|ack| check_ack(ack, &attempt, input.local, now));
        if let Some(entry) = self
            .entries
            .get_mut(&wan.client)
            .filter(|entry| entry.known.iface == wan.iface)
        {
            entry.retry = Some(now + BACKOFF);
            if attempt.server.is_some()
                && checked.as_ref().is_err_and(|error| {
                    error
                        .get_ref()
                        .is_some_and(|cause| cause.is::<ReplyTimeout>())
                })
            {
                entry.prefer_broadcast = true;
                report(DiscoveryEvent::NextBroadcast(&entry.known.iface));
            }
        }
        let (server, options) = match checked {
            Ok(value) => value,
            Err(error) => {
                let cached = attempt
                    .cached(input, now)
                    .or_else(|| self.cached_after(&attempt, input, now));
                if let Some(options) = cached.as_ref() {
                    report(DiscoveryEvent::Cached(options));
                }
                return cached.map_or(Selection::Fallback(Some(error)), Selection::Inform);
            }
        };
        if !self.entries.contains_key(&wan.client) && self.entries.len() >= LIMIT {
            return attempt.fallback(
                input,
                now,
                io::Error::other("DHCPINFORM verified target limit reached"),
            );
        }
        let entry = self.entries.entry(wan.client).or_insert_with(|| {
            Entry::new(
                wan.clone(),
                KnownTarget {
                    iface: wan.iface.clone(),
                    wan_key: wan.key.clone(),
                    client: wan.client,
                    server,
                    stamp: String::new(),
                    observed_at_epoch: None,
                },
            )
        });
        if entry.known.iface != wan.iface {
            // An unknown broadcast can re-attest the same link under a new
            // native alias after the old alias ceases to prove ownership.
            entry.wan = wan.clone();
            entry.known.iface.clone_from(&wan.iface);
            entry.prefer_broadcast = false;
        }
        entry.known.server = server;
        entry.retry = Some(now + BACKOFF);
        entry.refresh = false;
        entry.options = Some(options.clone());
        Selection::Inform(options)
    }
}

fn eligible(ip: Ipv4Addr, client: Ipv4Addr, local: &[Ipv4Addr]) -> bool {
    unicast(ip) && ip != client && !local.contains(&ip)
}

fn check_ack(
    ack: Ack,
    attempt: &Attempt,
    local: &[Ipv4Addr],
    now: Instant,
) -> io::Result<(Ipv4Addr, Options)> {
    if !eligible(ack.server, attempt.wan.client, local)
        || attempt
            .server
            .is_some_and(|expected| ack.server != expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DHCPINFORM server identifier is no longer eligible",
        ));
    }
    let mut dns = Vec::new();
    for ip in ack.dns {
        if eligible(ip, attempt.wan.client, local) && !dns.contains(&ip) {
            dns.push(ip);
            if dns.len() == LIMIT {
                break;
            }
        }
    }
    if dns.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DHCPINFORM returned no eligible DNS address",
        ));
    }
    Ok((
        ack.server,
        Options {
            wan: attempt.wan.clone(),
            dns,
            expires: now + VALIDITY,
        },
    ))
}

#[cfg(test)]
mod tests;
