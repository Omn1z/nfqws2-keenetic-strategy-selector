use super::discovery::native;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime, Time};

pub struct Lease {
    pub iface: String,
    pub client: Ipv4Addr,
    pub servers: Vec<IpAddr>,
    pub remaining: Duration,
    pub at: OffsetDateTime,
    pub stamp: String,
    pub lease_seconds: u32,
}

pub(super) fn observed_at(stamp: &str, now: OffsetDateTime) -> Option<OffsetDateTime> {
    let mut fields = stamp.split_ascii_whitespace();
    let mon = fields.next()?;
    let month = Month::try_from(
        ("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec"
            .split(' ')
            .position(|m| m == mon)?
            + 1) as u8,
    )
    .ok()?;
    let day = fields.next()?.parse().ok()?;
    let mut clock = fields.next()?.split(':');
    let time = Time::from_hms(
        clock.next()?.parse().ok()?,
        clock.next()?.parse().ok()?,
        clock.next()?.parse().ok()?,
    )
    .ok()?;
    if clock.next().is_some() || fields.next().is_some() {
        return None;
    }
    let at = |year| {
        Some(
            Date::from_calendar_date(year, month, day)
                .ok()?
                .with_time(time)
                .assume_offset(now.offset()),
        )
    };
    let t = at(now.year())?;
    if t > now {
        at(now.year() - 1)
    } else {
        Some(t)
    }
}
pub fn parse_clock(raw: &str) -> Option<OffsetDateTime> {
    let raw = raw.trim();
    if raw.len() != 24 || !raw.is_ascii() {
        return None;
    }
    let mut v = raw.to_owned();
    v.insert(22, ':');
    OffsetDateTime::parse(&v, &Rfc3339).ok()
}
pub(super) struct Ack {
    pub(super) iface: String,
    pub(super) client: Ipv4Addr,
    pub(super) server: Option<Ipv4Addr>,
    pub(super) stamp: String,
    seconds: u32,
    dns: Vec<IpAddr>,
}

impl Ack {
    pub(super) fn lease(&self, now: OffsetDateTime) -> Option<Lease> {
        if self.dns.is_empty() || matches!(self.seconds, 0 | u32::MAX) {
            return None;
        }
        let at = observed_at(&self.stamp, now)?;
        let expires = at.checked_add(time::Duration::seconds(self.seconds.into()))?;
        let left = Duration::try_from(expires - now).ok()?;
        (!left.is_zero()).then(|| Lease {
            iface: self.iface.clone(),
            client: self.client,
            servers: self.dns.clone(),
            remaining: left.min(Duration::from_secs(7 * 86400)),
            at,
            stamp: self.stamp.clone(),
            lease_seconds: self.seconds,
        })
    }

    pub(super) fn valid_stamp(&self) -> bool {
        let reference = Date::from_calendar_date(2000, Month::December, 31)
            .unwrap()
            .with_hms(23, 59, 59)
            .unwrap()
            .assume_utc();
        observed_at(&self.stamp, reference).is_some()
    }
}

#[cfg(test)]
pub(super) fn parse(log: &str, now: OffsetDateTime) -> Vec<Lease> {
    ack_records(log)
        .iter()
        .filter_map(|ack| ack.lease(now))
        .collect()
}

pub(super) fn ack_records(log: &str) -> Vec<Ack> {
    let mut acks = BTreeMap::<String, Ack>::new();
    let mut context = String::new();
    let mut stamp = String::new();
    let mut obtained = false;
    let mut remaining = 0u8;
    records(log, |line: &str| {
        if line.is_empty() {
            acks.clear();
        }
        let Some((header, msg)) = line.get(3..).and_then(|s| s.split_once("] ")) else {
            context.clear();
            return;
        };
        if let Some(body) = msg.strip_prefix("ndhcpc: ") {
            context.clear();
            let mut words = body.split_ascii_whitespace();
            let Some(iface) = words
                .next()
                .and_then(|v| v.strip_suffix(':'))
                .filter(|v| native(v))
            else {
                return;
            };
            if words.next() != Some("received") {
                return;
            }
            if words.clone().next() == Some("NAK") {
                // A refusal invalidates DNS in this ring entry. Its previous
                // proved server identifier is independent of the address lease.
                if let Some(previous) = acks.get_mut(iface) {
                    previous.dns.clear();
                }
            }
            if words.next() != Some("ACK") || words.next() != Some("for") {
                return;
            }
            let Some(client) = words.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
                return;
            };
            if words.next() != Some("from") {
                return;
            }
            let (Some(server), Some(lease), Some(seconds)) =
                (words.next(), words.next(), words.next())
            else {
                return;
            };
            if !acks.contains_key(iface) && acks.len() >= 32 {
                return;
            }
            acks.insert(
                iface.to_owned(),
                Ack {
                    iface: iface.into(),
                    client,
                    server: server.parse().ok(),
                    stamp: header.into(),
                    seconds: if lease == "lease" {
                        seconds.parse().unwrap_or(0)
                    } else {
                        0
                    },
                    dns: Vec::new(),
                },
            );
            context = iface.into();
            stamp = header.into();
            remaining = 16;
            obtained = false;
            return;
        }
        if header != stamp || remaining == 0 {
            context.clear();
            return;
        }
        remaining -= 1;
        let Some(ack) = acks.get_mut(&context) else {
            return;
        };
        if let Some(cidr) = msg.strip_prefix("ndm: Dhcp::Client: obtained IP address ") {
            obtained = cidr
                .trim_end_matches('.')
                .split_once('/')
                .is_some_and(|(ip, n)| {
                    ip.parse() == Ok(ack.client) && n.parse::<u8>().is_ok_and(|n| n <= 32)
                });
            return;
        }
        if obtained && ack.dns.len() < 8 {
            let address = msg
                .strip_prefix("ndm: Dns::InterfaceSpecific: name server ")
                .or_else(|| msg.strip_prefix("ndm: Dhcp::Client: name server "))
                .and_then(|v| v.strip_suffix(" is ignored."));
            if let Some(ip) = address.and_then(|v| v.parse().ok()) {
                ack.dns.push(ip);
            }
        }
    });
    acks.into_values().collect()
}
// Both ndhcpc and pppd use wrapped records. Drop partial history and never
// associate records across an oversized message or a truncated prefix.
pub(super) fn records(log: &str, mut record: impl FnMut(&str)) {
    const MAX_LOG: usize = 1 << 20;
    let start = log.len().saturating_sub(MAX_LOG);
    let log = if start == 0 {
        log
    } else {
        let Some(eol) = log.as_bytes()[start..].iter().position(|b| *b == b'\n') else {
            return;
        };
        &log[start + eol + 1..]
    };
    let mut buf = String::new();
    for line in log.lines() {
        let line = line.trim_end().trim_start_matches("\x1b[K");
        if line.as_bytes().get(1..3) == Some(b" [") {
            record(&buf);
            buf.clear();
            if line.len() <= 2048 {
                buf.push_str(line);
            }
        } else if line.starts_with(' ') && !buf.is_empty() {
            if buf.len() + line.len() + 1 > 2048 {
                buf.clear();
                continue;
            }
            buf.push(' ');
            buf.push_str(line.trim());
        }
    }
    record(&buf);
}
