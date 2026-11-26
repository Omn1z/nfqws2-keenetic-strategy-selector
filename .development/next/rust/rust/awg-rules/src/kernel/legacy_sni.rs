//! Name decisions from the selected Go full-tunnel profile. These decisions
//! are telemetry. The installed blanket still sends all traffic to the tunnel.
use crate::{observed::Scope, policy, sources};
use nfqws2_store::Store;
use std::{io, net::IpAddr, sync::Arc};

use super::Journal;

struct Rule {
    index: usize,
    tunnel: bool,
    // Go models a raw global catch-all as an always-true matcher.
    domains: Option<Scope>,
}

#[derive(Clone)]
pub struct LegacySni {
    rules: Arc<[Rule]>,
    trial_expires: u64,
}

impl LegacySni {
    pub fn trial_expires(&self) -> u64 {
        self.trial_expires
    }

    pub fn decision(&self, name: &str, dst: IpAddr) -> (&'static str, Option<usize>) {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let matched = self.rules.iter().find(|rule| {
            rule.domains
                .as_ref()
                .is_none_or(|domains| domains.match_domain(&name).is_some())
        });
        match matched {
            Some(rule) if rule.tunnel => ("tunnel", Some(rule.index)),
            Some(_) if super::shared_cdn_address(dst) => ("cdn-skip", None),
            Some(rule) => ("direct", Some(rule.index)),
            None => ("direct", None),
        }
    }
}

fn global_rule(zone: &crate::Zone) -> bool {
    zone.enabled && !zone.waiting_for_connection && zone.source_ips.is_empty()
}

pub(super) fn read(db: &Store, journal: &Journal) -> io::Result<Option<LegacySni>> {
    if journal.installed.legacy_full.is_none()
        || !journal.installed.fully_live()
        || !journal.preparing.is_empty()
        || journal.expires != 0 && nfqws2_awg_profile::now() >= journal.expires
    {
        return Ok(None);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    let Some(owner) = journal
        .installed
        .prefixes
        .get(&super::plan::Family::V4.any())
        .and_then(|iface| journal.installed.targets.get(iface))
    else {
        return Ok(None);
    };
    let profiles = doc["servers"].as_array().unwrap();
    let Some(row) = profiles.iter().find(|row| row["id"] == owner.id) else {
        return Ok(None);
    };
    let config = &row["config"];
    let shared = super::legacy_watchdog::is_transient(&journal.committed, &journal.installed)
        .then(|| &doc["routing"]);
    let mode = shared
        .and_then(|r| r["mode"].as_str())
        .or_else(|| config["routing"]["mode"].as_str());
    let sni = shared
        .and_then(|r| r["sni_routing"].as_bool())
        .or_else(|| config["routing"]["sni_routing"].as_bool());
    if config["enabled"] != true
        || config["client"]["enabled"] != true
        || mode != Some("full")
        || sni != Some(true)
    {
        return Ok(None);
    }
    let mut raw = policy::decode(&config["routing"])?;
    raw.normalize();
    for zone in &mut raw.zones {
        // Go detaches dangling primary references when loading the receipt.
        if !zone.tunnel_id.is_empty() && !profiles.iter().any(|r| r["id"] == zone.tunnel_id) {
            zone.waiting_for_connection = true;
        }
    }
    let catch = raw.zones.iter().position(|z| {
        global_rule(z)
            && (z.domains.iter().any(|s| s.trim() == "*")
                || z.ips
                    .iter()
                    .any(|s| matches!(s.trim(), "0.0.0.0/0" | "::/0")))
    });
    let effective = sources::expand(db, raw)?;
    let mut rules = Vec::new();
    for (index, zone) in effective.zones.iter().enumerate() {
        if !global_rule(zone) {
            continue;
        }
        let tunnel = zone.direction() == "tunnel";
        if catch == Some(index) {
            rules.push(Rule {
                index: index + 1,
                tunnel,
                domains: None,
            });
            break;
        }
        let mut domains = Scope::default();
        for entry in zone.domains.iter().filter(|s| !crate::model::catch_all(s)) {
            domains.add(entry, zone.include_subdomains)?;
        }
        if !domains.is_empty() {
            rules.push(Rule {
                index: index + 1,
                tunnel,
                domains: Some(domains),
            });
        }
    }
    Ok((!rules.is_empty()).then(|| LegacySni {
        rules: rules.into(),
        trial_expires: journal.expires,
    }))
}
