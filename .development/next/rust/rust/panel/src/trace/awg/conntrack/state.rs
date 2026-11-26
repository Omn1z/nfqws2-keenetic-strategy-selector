use nfqws2_monitor::Conn;
use std::{
    collections::{hash_map::Entry, HashMap},
    net::IpAddr,
    time::{Duration, Instant},
};

const UNREPLIED: Duration = Duration::from_secs(2);
const GONE: Duration = Duration::from_secs(3);
const TARGET: usize = 4096;
const LIMIT: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    New,
    Replied,
    Unreplied,
    Gone,
}

impl Event {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Replied => "replied",
            Self::Unreplied => "unreplied",
            Self::Gone => "gone",
        }
    }

    pub(super) fn reason(self, conn: &Conn) -> &'static str {
        match self {
            Self::New if failing(conn) => "new flow, no reply yet",
            Self::New => "new flow",
            Self::Replied => "reply appeared",
            Self::Unreplied => "no reply for more than 2s",
            Self::Gone => "flow disappeared while still failing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct Key {
    protocol: Protocol,
    src: IpAddr,
    dst: IpAddr,
    sport: u64,
    dport: u64,
}

impl Key {
    pub(super) fn of(conn: &Conn) -> Option<Self> {
        let (src, dst) = conn.src.zip(conn.dst)?;
        if conn.zone == "swan" || !lan(src, conn.zone) || !meaningful(dst) {
            return None;
        }
        let protocol = if conn.proto.eq_ignore_ascii_case("tcp") {
            Protocol::Tcp
        } else if conn.proto.eq_ignore_ascii_case("udp") {
            Protocol::Udp
        } else if conn.proto.eq_ignore_ascii_case("icmp") {
            Protocol::Icmp
        } else {
            return None;
        };
        Some(Self {
            protocol,
            src,
            dst,
            sport: conn.sport,
            dport: conn.dport,
        })
    }
}

fn lan(src: IpAddr, zone: &str) -> bool {
    let src = src.to_canonical();
    unicast(src) && (zone == "slan" || private(src))
}

fn meaningful(dst: IpAddr) -> bool {
    let dst = dst.to_canonical();
    unicast(dst) && !private(dst) && !matches!(dst, IpAddr::V4(ip) if ip.is_broadcast())
}

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

fn unicast(ip: IpAddr) -> bool {
    !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

fn failing(conn: &Conn) -> bool {
    conn.unreplied || (conn.proto == "tcp" && conn.state == "SYN_SENT")
}

struct Seen<D> {
    conn: Conn,
    decision: D,
    policy_generation: u64,
    first_seen: Instant,
    last_seen: Instant,
    reported_unreplied: bool,
}

pub(super) struct Tracker<D> {
    seen: HashMap<Key, Seen<D>>,
}

impl<D> Default for Tracker<D> {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }
}

impl<D> Tracker<D> {
    /// Update one conntrack snapshot. A bounded prefix still supports flow
    /// transitions, but only a complete snapshot can prove disappearance.
    pub(super) fn update(
        &mut self,
        now: Instant,
        complete: bool,
        policy_generation: u64,
        rows: impl IntoIterator<Item = Conn>,
        mut decide: impl FnMut(&Conn) -> Option<D>,
        mut emit: impl FnMut(Event, &Conn, &D),
    ) {
        let mut saturated = false;
        for conn in rows {
            let Some(key) = Key::of(&conn) else { continue };
            match self.seen.entry(key) {
                Entry::Vacant(slot) => {
                    let Some(decision) = decide(&conn) else {
                        continue;
                    };
                    emit(Event::New, &conn, &decision);
                    slot.insert(Seen {
                        conn,
                        decision,
                        policy_generation,
                        first_seen: now,
                        last_seen: now,
                        reported_unreplied: false,
                    });
                }
                Entry::Occupied(mut slot) => {
                    if slot.get().policy_generation != policy_generation {
                        let Some(decision) = decide(&conn) else {
                            // A changed policy can make a visible flow
                            // indeterminate. Do not report the old decision.
                            slot.remove();
                            continue;
                        };
                        let seen = slot.get_mut();
                        seen.decision = decision;
                        seen.policy_generation = policy_generation;
                    }
                    let seen = slot.get_mut();
                    if seen.conn.unreplied && !conn.unreplied {
                        emit(Event::Replied, &conn, &seen.decision);
                    }
                    if conn.unreplied
                        && !seen.reported_unreplied
                        && now.saturating_duration_since(seen.first_seen) >= UNREPLIED
                    {
                        emit(Event::Unreplied, &conn, &seen.decision);
                        seen.reported_unreplied = true;
                    }
                    seen.conn = conn;
                    seen.last_seen = now;
                }
            }
            if self.seen.len() > LIMIT {
                saturated = true;
                self.trim();
            }
        }
        if complete {
            self.seen.retain(|_, seen| {
                if now.saturating_duration_since(seen.last_seen) < GONE {
                    return true;
                }
                if failing(&seen.conn) {
                    emit(Event::Gone, &seen.conn, &seen.decision);
                }
                false
            });
        }
        if saturated && self.seen.len() > TARGET {
            self.trim();
        }
    }

    fn trim(&mut self) {
        let mut oldest: Vec<_> = self
            .seen
            .iter()
            .map(|(&key, seen)| (seen.last_seen, key))
            .collect();
        let remove = oldest.len() - TARGET;
        oldest.select_nth_unstable(remove);
        for (_, key) in oldest.into_iter().take(remove) {
            self.seen.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(port: u64, unreplied: bool) -> Conn {
        Conn {
            l3: "ipv4".into(),
            proto: "tcp".into(),
            state: if unreplied { "SYN_SENT" } else { "ESTABLISHED" }.into(),
            ttl: 1,
            src: Some("192.168.1.2".parse().unwrap()),
            dst: Some("203.0.113.1".parse().unwrap()),
            sport: port,
            dport: 443,
            packets: 0,
            bytes: 0,
            reply_bytes: 0,
            assured: !unreplied,
            unreplied,
            fastnat: false,
            mac: String::new(),
            zone: "slan",
        }
    }

    #[test]
    fn tracks_go_events_and_uses_the_last_decision_for_gone() {
        let mut tracker = Tracker::default();
        let now = Instant::now();
        let mut events = Vec::new();
        for (elapsed, complete, rows) in [
            (0, true, vec![conn(10, true), conn(30, true)]),
            (1, true, vec![conn(10, false), conn(30, true)]),
            (2, true, vec![conn(10, false), conn(30, true)]),
            (3, true, vec![conn(10, false), conn(30, true)]),
            (6, false, Vec::new()),
            (7, true, Vec::new()),
        ] {
            tracker.update(
                now + Duration::from_secs(elapsed),
                complete,
                elapsed,
                rows,
                |_| Some(elapsed),
                |event, row, &decision| events.push((event.as_str(), row.sport, decision)),
            );
        }
        assert_eq!(
            events,
            [
                ("new", 10, 0),
                ("new", 30, 0),
                ("replied", 10, 1),
                ("unreplied", 30, 2),
                ("gone", 30, 3)
            ]
        );
        assert_eq!(Event::New.reason(&conn(20, true)), "new flow, no reply yet");
        assert!(tracker.seen.is_empty());
    }

    #[test]
    fn classifies_each_tuple_once_per_policy_generation() {
        let mut tracker = Tracker::default();
        let now = Instant::now();
        let mut calls = Vec::new();
        let mut events = Vec::new();
        for (elapsed, generation, rows) in [
            (0, 1, vec![conn(10, true), conn(20, true)]),
            (1, 1, vec![conn(10, false), conn(20, true)]),
            (2, 2, vec![conn(10, false), conn(20, true)]),
            (3, 2, vec![conn(20, true)]),
            (4, 3, vec![conn(10, false), conn(20, false)]),
        ] {
            tracker.update(
                now + Duration::from_secs(elapsed),
                true,
                generation,
                rows,
                |row| {
                    calls.push((row.sport, generation));
                    (row.sport != 10 || generation != 2).then_some(generation)
                },
                |event, row, &decision| events.push((event, row.sport, decision)),
            );
        }
        assert_eq!(
            calls,
            [(10, 1), (20, 1), (10, 2), (20, 2), (10, 3), (20, 3)]
        );
        assert_eq!(
            events,
            [
                (Event::New, 10, 1),
                (Event::New, 20, 1),
                (Event::Replied, 10, 1),
                (Event::Unreplied, 20, 2),
                (Event::New, 10, 3),
                (Event::Replied, 20, 3),
            ]
        );
    }

    #[test]
    fn filters_wan_and_local_endpoints_and_bounds_a_large_snapshot() {
        let mut row = conn(10, true);
        row.zone = "swan";
        assert!(Key::of(&row).is_none());
        row.zone = "slan";
        row.dst = Some("fd00::1".parse().unwrap());
        assert!(Key::of(&row).is_none());
        row.dst = Some("2001:db8::1".parse().unwrap());
        row.src = Some("2001:db8::2".parse().unwrap());
        assert!(Key::of(&row).is_some());
        row.zone = "";
        assert!(Key::of(&row).is_none());
        row.zone = "slan";
        row.proto = "icmpv6".into();
        assert!(Key::of(&row).is_none());

        let mut tracker = Tracker::default();
        let mut added = 0;
        tracker.update(
            Instant::now(),
            false,
            0,
            (0..(LIMIT + 500) as u64).map(|port| conn(port, true)),
            |_| Some(()),
            |event, _, _| {
                assert_eq!(event, Event::New);
                added += 1;
            },
        );
        assert_eq!(added, LIMIT + 500);
        assert_eq!(tracker.seen.len(), TARGET);
    }
}
