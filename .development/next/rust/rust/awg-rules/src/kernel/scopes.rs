//! Partition addresses at configured CIDR boundaries. Source ranges with the
//! same ordered set of applicable zones share all destination lookup work.
use super::{
    err, packed,
    plan::{Family, Prefix},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};
#[derive(Default)]
pub(super) struct Scopes {
    pub members: BTreeMap<Prefix, Vec<Prefix>>,
    pub by_zone: BTreeMap<usize, BTreeSet<Prefix>>,
}
impl Scopes {
    pub fn from_policy(policy: &crate::Routing, go_ipv4: bool) -> io::Result<Self> {
        let mut events = BTreeMap::<Family, Vec<(u128, bool, usize)>>::new();
        for (i, z) in policy
            .zones
            .iter()
            .enumerate()
            .filter(|(_, z)| z.enabled && !z.waiting_for_connection)
        {
            let mut nets = z
                .source_ips
                .iter()
                .filter(|s| !go_ipv4 || !s.contains(':'))
                .map(|s| s.parse::<Prefix>())
                .collect::<io::Result<BTreeSet<_>>>()?;
            if nets.is_empty() {
                nets.insert(Family::V4.any());
                if !go_ipv4 {
                    nets.insert(Family::V6.any());
                }
            }
            for src in Prefix::compact(nets) {
                let (lo, hi) = src.interval();
                let family = src.family();
                let events = events.entry(family).or_default();
                events.push((lo, true, i));
                if hi < family.any().interval().1 {
                    events.push((hi + 1, false, i));
                }
            }
        }
        let mut result = Self::default();
        for (f, mut seq) in events {
            seq.sort_unstable();
            let mut active = BTreeSet::new();
            let mut groups = BTreeMap::<Vec<usize>, Vec<Prefix>>::new();
            let mut last = 0;
            let mut total = 0;
            // Bound both the address partition and its zone index on an
            // overlapping pathological configuration before building the FIB.
            let mut edges = 0usize;
            let mut add = |active: &BTreeSet<usize>, lo, hi| -> io::Result<()> {
                if active.is_empty() {
                    return Ok(());
                }
                let key = active.iter().copied().collect::<Vec<_>>();
                if !groups.contains_key(&key) {
                    edges += key.len();
                }
                if edges > packed::LIMIT {
                    return Err(err("слишком много пересечений зон источника"));
                }
                let parts = groups.entry(key).or_default();
                let before = parts.len();
                Prefix::append_interval(f, lo, hi, parts);
                total += parts.len() - before;
                if total > packed::LIMIT {
                    return Err(err("слишком много отдельных сетей источника"));
                }
                Ok(())
            };
            for changes in seq.chunk_by(|a, b| a.0 == b.0) {
                let at = changes[0].0;
                if at > last {
                    add(&active, last, at - 1)?;
                }
                for &(_, on, i) in changes {
                    if on {
                        active.insert(i);
                    } else {
                        active.remove(&i);
                    }
                }
                last = at;
            }
            add(&active, last, f.any().interval().1)?;
            for (zones, parts) in groups {
                let anchor = parts[0];
                for i in zones {
                    result.by_zone.entry(i).or_default().insert(anchor);
                }
                result.members.insert(anchor, parts);
            }
        }
        Ok(result)
    }
}
