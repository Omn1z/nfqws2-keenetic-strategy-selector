use super::{
    discovery, ppp,
    renew::capture::{Capture, Receipt},
};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};
use time::OffsetDateTime;
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{timeout_at, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Candidate {
    pub(super) iface: String,
    pub(super) device: String,
    pub(super) client: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) wan_key: String,
    pub(super) candidate: Candidate,
    pub(super) index: u32,
    pub(super) mac: [u8; 6],
}

impl Target {
    fn same_link(&self, other: &Self) -> bool {
        self.wan_key == other.wan_key
            && self.candidate.device == other.candidate.device
            && self.candidate.client == other.candidate.client
            && self.index == other.index
            && self.mac == other.mac
    }
}

pub(super) struct Wan {
    pub(super) key: String,
    pub(super) devices: HashSet<String>,
}

impl Wan {
    pub(super) fn read(
        routes: &str,
        configured: &[String],
        hosts: &[(String, IpAddr)],
    ) -> Option<Self> {
        let mut parts = Vec::new();
        let mut devices = HashSet::new();
        for row in routes.lines() {
            let mut fields = row.split_ascii_whitespace();
            if fields.next() != Some("default") {
                continue;
            }
            let mut device = None;
            let mut gateway = None;
            while let Some(field) = fields.next() {
                match field {
                    "dev" if device.is_none() => device = fields.next(),
                    "via" if gateway.is_none() => gateway = fields.next(),
                    "dev" | "via" => {
                        device = None;
                        break;
                    }
                    _ => (),
                }
            }
            if let Some(device) = device.filter(|device| {
                discovery::wan(device) && configured.iter().any(|name| name == device)
            }) {
                if gateway.is_some_and(|ip| ip.parse::<IpAddr>().is_err()) {
                    continue;
                }
                parts.push(format!("route={device}/{}", gateway.unwrap_or_default()));
                devices.insert(device.to_owned());
            }
        }
        let routes = parts.len();
        for (device, ip) in hosts {
            if ip.is_ipv4() && configured.contains(device) {
                parts.push(format!("ip={ip}"));
            }
        }
        if routes == 0 || routes == parts.len() {
            return None;
        }
        parts.sort_unstable();
        let key = parts.join("|");
        (key.len() <= 2048).then_some(Self { key, devices })
    }

    pub(super) fn candidates(
        &self,
        interfaces: &str,
        hosts: &[(String, IpAddr)],
    ) -> Vec<Candidate> {
        let mut seen = HashSet::new();
        ppp::interface_records(interfaces, |name, fields| {
            let iface = fields.get("id").copied().unwrap_or(name);
            if !discovery::native(name)
                || !discovery::native(iface)
                || !matches!(
                    fields.get("type").copied(),
                    Some("Ethernet" | "GigabitEthernet" | "FastEthernet" | "Vlan" | "VLAN")
                )
                || !["connected", "global", "defaultgw"]
                    .iter()
                    .all(|field| fields.get(field).copied() == Some("yes"))
                || fields.get("security-level").copied() != Some("public")
            {
                return None;
            }
            let client = fields.get("address")?.parse::<Ipv4Addr>().ok()?;
            if !discovery::usable(client.into()) {
                return None;
            }
            let mut owned = hosts.iter().filter(|(device, ip)| {
                self.devices.contains(device) && *ip == IpAddr::from(client)
            });
            let (device, _) = owned.next()?;
            if owned.any(|(other, _)| other != device) || !seen.insert(device.clone()) {
                return None;
            }
            Some(Candidate {
                iface: iface.into(),
                device: device.clone(),
                client,
            })
        })
    }
}

pub(super) fn link_identity(device: &str) -> io::Result<(u32, [u8; 6])> {
    fn mac(text: &str) -> Option<[u8; 6]> {
        let bytes: Vec<_> = text
            .trim()
            .split(':')
            .map(|part| {
                (part.len() == 2)
                    .then(|| u8::from_str_radix(part, 16).ok())
                    .flatten()
            })
            .collect::<Option<_>>()?;
        let mac: [u8; 6] = bytes.try_into().ok()?;
        (mac[0] & 1 == 0 && mac != [0; 6]).then_some(mac)
    }
    if !discovery::wan(device) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let path = Path::new("/sys/class/net").join(device);
    let flags = std::fs::read_to_string(path.join("flags"))?;
    if !flags
        .trim()
        .strip_prefix("0x")
        .and_then(|raw| u32::from_str_radix(raw, 16).ok())
        .is_some_and(|f| f & 1 != 0)
    {
        return Err(io::ErrorKind::NotConnected.into());
    }
    let index = std::fs::read_to_string(path.join("ifindex"))?
        .trim()
        .parse()
        .ok()
        .filter(|index| *index != 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    let mac =
        mac(&std::fs::read_to_string(path.join("address"))?).ok_or(io::ErrorKind::InvalidData)?;
    Ok((index, mac))
}

#[derive(Clone)]
pub(super) struct Snapshot {
    pub(super) started: OffsetDateTime,
    pub(super) requests: u64,
    pub(super) sequence: u64,
    pub(super) receipt: Option<Receipt>,
    pub(super) failed: bool,
}

#[derive(Clone)]
pub(super) struct Reader {
    pub(super) target: Target,
    state: watch::Receiver<Snapshot>,
    generation: u64,
}

impl Reader {
    #[cfg(test)]
    pub(super) fn fixture(target: Target) -> (Self, watch::Sender<Snapshot>) {
        let (tx, state) = watch::channel(Snapshot {
            started: OffsetDateTime::now_utc(),
            requests: 0,
            sequence: 0,
            receipt: None,
            failed: false,
        });
        (
            Self {
                target,
                state,
                generation: 1,
            },
            tx,
        )
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        self.state.borrow().clone()
    }

    pub(super) fn revision(&self, snapshot: &Snapshot) -> (u64, u64) {
        (self.generation, snapshot.sequence)
    }

    pub(super) fn current(&self, other: &Self) -> bool {
        self.generation == other.generation && !self.closed()
    }

    pub(super) fn closed(&self) -> bool {
        self.state.has_changed().is_err()
    }

    pub(super) async fn wait(mut self, baseline: u64, deadline: Instant) -> Option<Receipt> {
        let _ = timeout_at(deadline, self.state.wait_for(|s| s.sequence > baseline)).await;
        let state = self.state.borrow();
        state.receipt.clone().filter(|_| state.sequence > baseline)
    }
}

#[derive(Default)]
pub(super) struct Slot {
    active: Option<Active>,
    generation: u64,
}

struct Active {
    reader: Reader,
    lifecycle: watch::Receiver<bool>,
    task: JoinHandle<()>,
}

impl Drop for Active {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Slot {
    #[cfg(test)]
    pub(super) fn attach_fixture(&mut self, lifecycle: &watch::Receiver<bool>, reader: Reader) {
        assert!(self.active.is_none());
        self.generation = reader.generation;
        self.active = Some(Active {
            reader,
            lifecycle: lifecycle.clone(),
            task: tokio::spawn(std::future::pending()),
        });
    }

    pub(super) fn reader(&self, lifecycle: &watch::Receiver<bool>) -> Option<&Reader> {
        self.active
            .as_ref()
            .filter(|active| active.lifecycle.same_channel(lifecycle) && !active.reader.closed())
            .map(|active| &active.reader)
    }

    pub(super) async fn reconcile(
        &mut self,
        lifecycle: &watch::Receiver<bool>,
        target: Option<Target>,
    ) -> io::Result<Option<Reader>> {
        if *lifecycle.borrow() || lifecycle.has_changed().is_err() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some(reader) = self.reader(lifecycle).filter(|r| {
            target
                .as_ref()
                .is_some_and(|target| r.target.same_link(target))
        }) {
            return Ok(Some(reader.clone()));
        }
        if let Some(active) = self.active.as_mut() {
            if !active.lifecycle.same_channel(lifecycle) && !active.reader.closed() {
                // A replacement listener can begin serving just before the
                // old engine is notified. Never evict the other live owner.
                let mut retiring = active.lifecycle.clone();
                let mut current = lifecycle.clone();
                tokio::select! {
                    biased;
                    _ = current.wait_for(|stopped| *stopped) => return Err(io::ErrorKind::Interrupted.into()),
                    _ = retiring.wait_for(|stopped| *stopped) => (),
                }
            }
            active.task.abort();
            // Keep the retiring handle in the slot until join succeeds, even if
            // discovery is cancelled here. Another engine cannot overlap it.
            let _ = (&mut active.task).await;
            self.active = None;
        }
        if *lifecycle.borrow() || lifecycle.has_changed().is_err() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let Some(target) = target else {
            return Ok(None);
        };
        let c = &target.candidate;
        let mut capture = Capture::open(&c.device, target.index, c.client, target.mac)?;
        let (tx, state) = watch::channel(Snapshot {
            started: OffsetDateTime::now_utc(),
            requests: 0,
            sequence: 0,
            receipt: None,
            failed: false,
        });
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("DHCP capture generation overflow"))?;
        let mut stop = lifecycle.clone();
        let task = tokio::spawn(async move {
            loop {
                let receipt = tokio::select! {
                    biased;
                    _ = stop.wait_for(|stopped| *stopped) => return,
                    result = capture.next(|requests| tx.send_modify(|s| s.requests = requests)) => result,
                };
                match receipt {
                    Ok(receipt) => tx.send_modify(|s| {
                        s.sequence = s.sequence.saturating_add(1);
                        s.receipt = Some(receipt);
                    }),
                    Err(_) => {
                        tx.send_modify(|s| s.failed = true);
                        return;
                    }
                }
            }
        });
        let reader = Reader {
            target,
            state,
            generation: self.generation,
        };
        self.active = Some(Active {
            reader: reader.clone(),
            lifecycle: lifecycle.clone(),
            task,
        });
        Ok(Some(reader))
    }
}

#[cfg(test)]
mod tests {
    use super::super::renew::capture::Observation;
    use super::*;
    use std::time::Duration;

    fn target() -> Target {
        Target {
            wan_key: "ip=192.0.2.10|route=eth9/".into(),
            candidate: Candidate {
                iface: "ISP".into(),
                device: "eth9".into(),
                client: "192.0.2.10".parse().unwrap(),
            },
            index: 9,
            mac: [2, 0, 0, 0, 0, 1],
        }
    }

    #[tokio::test]
    async fn native_dhcp_manual_baseline_excludes_old_receipt_and_outlives_waiter() {
        let (reader, producer) = Reader::fixture(target());
        let reply = |sequence| {
            producer.send_modify(|s| {
                s.sequence = sequence;
                s.receipt = Some(Receipt {
                    observation: Observation::AckNoDns,
                    observed_at: OffsetDateTime::now_utc(),
                });
            })
        };
        reply(1);
        assert!(reader.clone().wait(1, Instant::now()).await.is_none());
        let deadline = Instant::now() + Duration::from_secs(1);
        let cancelled = tokio::spawn(reader.clone().wait(1, deadline));
        cancelled.abort();
        let _ = cancelled.await;
        assert!(!reader.closed());
        reply(2);
        let receipt = reader.wait(1, deadline).await.unwrap();
        assert_eq!(receipt.observation, Observation::AckNoDns);
    }

    #[tokio::test]
    async fn native_dhcp_observer_handoff_waits_for_retiring_dns_engine() {
        let (running, prior) = watch::channel(false);
        let (_next, replacement) = watch::channel(false);
        let (reader, _tx) = Reader::fixture(target());
        let mut slot = Slot::default();
        slot.attach_fixture(&prior, reader.clone());
        let result = timeout_at(Instant::now(), slot.reconcile(&replacement, None)).await;
        assert!(result.is_err());
        assert!(slot
            .reader(&prior)
            .is_some_and(|active| active.current(&reader)));
        running.send_replace(true);
        assert!(slot.reconcile(&replacement, None).await.unwrap().is_none());
        assert!(slot.reader(&prior).is_none());
    }

    #[test]
    fn native_dhcp_wan_key_stays_stable_across_metrics_and_firmware_aliases() {
        let configured = ["eth9".into(), "eth8".into()];
        let hosts = [
            ("eth9".into(), "192.0.2.10".parse().unwrap()),
            ("eth8".into(), "198.51.100.10".parse().unwrap()),
        ];
        let first = Wan::read(
            "default via 192.0.2.1 dev eth9 metric 9\ndefault dev eth8 metric 10",
            &configured,
            &hosts,
        )
        .unwrap();
        let reordered = Wan::read(
            "default dev eth8 metric 1\ndefault via 192.0.2.1 dev eth9 metric 20",
            &configured,
            &hosts,
        )
        .unwrap();
        assert_eq!(first.key, reordered.key);
        let changed = Wan::read(
            "default via 192.0.2.8 dev eth9\ndefault dev eth8",
            &configured,
            &hosts,
        )
        .unwrap();
        assert_ne!(first.key, changed.key);
        let record = |iface, kind, ip| {
            format!("Interface, name = \"{iface}\":\nid: {iface}\ntype: {kind}\nconnected: yes\nglobal: yes\ndefaultgw: yes\nsecurity-level: public\naddress: {ip}\n")
        };
        let native = record("ISP", "GigabitEthernet", "192.0.2.10")
            + &record("Eth9Alias", "Vlan", "192.0.2.10")
            + &record("PPPoE0", "PPPoE", "198.51.100.10")
            + &record("WAN2", "Vlan", "198.51.100.10");
        let candidates = first.candidates(&native, &hosts);
        assert_eq!(
            candidates
                .iter()
                .map(|c| c.iface.as_str())
                .collect::<Vec<_>>(),
            ["ISP", "WAN2"]
        );
    }
}
