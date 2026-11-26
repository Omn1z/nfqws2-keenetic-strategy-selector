use crate::neighbors::{read_ndp, Neighbors};
use serde::{Serialize, Serializer};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;

#[derive(Debug, Serialize)]
pub struct Conn {
    pub l3: Cow<'static, str>,
    pub proto: Cow<'static, str>,
    pub state: Cow<'static, str>,
    pub ttl: u64,
    #[serde(serialize_with = "address")]
    pub src: Option<IpAddr>,
    #[serde(serialize_with = "address")]
    pub dst: Option<IpAddr>,
    pub sport: u64,
    pub dport: u64,
    pub packets: u64,
    pub bytes: u64,
    pub reply_bytes: u64,
    pub assured: bool,
    pub unreplied: bool,
    pub fastnat: bool,
    pub mac: String,
    pub zone: &'static str,
}

fn address<S: Serializer>(addr: &Option<IpAddr>, s: S) -> Result<S::Ok, S::Error> {
    match addr {
        Some(ip) => s.collect_str(ip),
        None => s.serialize_str(""),
    }
}

fn atom(s: &str) -> Cow<'static, str> {
    // The same few values occur in tens of thousands of rows per snapshot.
    for name in [
        "ipv4",
        "ipv6",
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "ESTABLISHED",
        "SYN_SENT",
        "TIME_WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "SYN_RECV",
        "FIN_WAIT",
        "LAST_ACK",
        "",
    ] {
        if s == name {
            return Cow::Borrowed(name);
        }
    }
    Cow::Owned(s.to_owned())
}

impl Conn {
    fn failing(&self) -> bool {
        self.unreplied || (self.proto == "tcp" && self.state == "SYN_SENT")
    }
}

fn conn(line: &str) -> Option<Conn> {
    let mut words = line.split_ascii_whitespace().peekable();
    let l3 = atom(words.next()?);
    let proto = atom(words.nth(1)?);
    let ttl = counter(words.nth(1)?)?;
    let state = if proto == "tcp"
        && words
            .peek()
            .is_some_and(|w| !w.starts_with('[') && !w.contains('='))
    {
        atom(words.next()?)
    } else {
        Cow::Borrowed("")
    };
    let mut row = Conn {
        l3,
        proto,
        state,
        ttl,
        src: None,
        dst: None,
        sport: 0,
        dport: 0,
        packets: 0,
        bytes: 0,
        reply_bytes: 0,
        assured: false,
        unreplied: false,
        fastnat: false,
        mac: String::new(),
        zone: "",
    };
    let (mut src, mut dst, mut sport, mut dport, mut packets, mut bytes) =
        (None, None, None, None, None, None);
    for word in words {
        match word {
            "[ASSURED]" => row.assured = true,
            "[UNREPLIED]" => row.unreplied = true,
            "[FASTNAT]" => row.fastnat = true,
            "slan" => row.zone = "slan",
            "swan" => row.zone = "swan",
            _ => {
                if let Some((key, value)) = word.split_once('=') {
                    match key {
                        "src" => {
                            src.get_or_insert(value);
                        }
                        "dst" => {
                            dst.get_or_insert(value);
                        }
                        "sport" => {
                            sport.get_or_insert(value);
                        }
                        "dport" => {
                            dport.get_or_insert(value);
                        }
                        "packets" => {
                            packets.get_or_insert(value);
                        }
                        "bytes" if bytes.is_none() => bytes = Some(value),
                        "bytes" => {
                            if let Some(n) = counter(value) {
                                row.reply_bytes = n;
                            }
                        }
                        "mac" => row.mac = value.to_ascii_lowercase(),
                        _ => (),
                    }
                }
            }
        }
    }
    row.src = src.and_then(|v| v.parse().ok());
    row.dst = dst.and_then(|v| v.parse().ok());
    row.sport = sport.and_then(counter).unwrap_or(0);
    row.dport = dport.and_then(counter).unwrap_or(0);
    row.packets = packets.and_then(counter).unwrap_or(0);
    row.bytes = bytes.and_then(counter).unwrap_or(0);
    Some(row)
}

fn counter(token: &str) -> Option<u64> {
    if token.as_bytes().first()?.is_ascii_digit() {
        token.parse().ok()
    } else {
        None
    }
}

fn rows(path: &Path, mut visit: impl FnMut(&str)) -> io::Result<()> {
    visit_rows(File::open(path)?, |line| {
        visit(line);
        Ok(())
    })
}
fn visit_rows(file: File, mut visit: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
    let mut reader = BufReader::new(file);
    let mut buf = Vec::with_capacity(512);
    const MAX: usize = 256 * 1024;
    loop {
        buf.clear();
        if (&mut reader)
            .take((MAX + 1) as u64)
            .read_until(b'\n', &mut buf)?
            == 0
        {
            return Ok(());
        }
        if buf.len() > MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized proc record",
            ));
        }
        if let Ok(line) = std::str::from_utf8(&buf) {
            visit(line)?;
        }
    }
}

pub struct ConnectionReader(File);
impl ConnectionReader {
    pub fn visit(self, mut visitor: impl FnMut(Conn) -> io::Result<()>) -> io::Result<()> {
        visit_rows(self.0, |line| match conn(line) {
            Some(row) => visitor(row),
            None => Ok(()),
        })
    }
}

/// Stream one source device's original-direction rows without retaining the
/// global conntrack table. Used by the optional per-device trace worker.
pub fn device_flows(path: &Path, device: IpAddr, mut visit: impl FnMut(Conn)) -> io::Result<()> {
    rows(path, |line| {
        if let Some(row) = conn(line).filter(|row| row.src == Some(device)) {
            visit(row);
        }
    })
}

#[derive(Debug, Serialize)]
pub struct Connections {
    pub items: Vec<Conn>,
    pub count: usize,
}
#[derive(Debug, Default, Serialize)]
pub struct Device {
    pub ip: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ipv6: Vec<String>,
    pub mac: String,
    pub hostname: String,
    pub iface: String,
    pub total: usize,
    pub established: usize,
    pub failing: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub working: Vec<String>,
    pub failing_dsts: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Devices {
    pub devices: Vec<Device>,
}
#[derive(Default)]
struct Group {
    device: Device,
    v6: HashSet<Ipv6Addr>,
    working: HashSet<(IpAddr, u64)>,
    failing: HashSet<(IpAddr, u64)>,
}
type Groups = HashMap<String, Group>;
type Arp = HashMap<IpAddr, (String, String)>;

fn meaningful_dst(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v) => !v.is_link_local() && v != Ipv4Addr::BROADCAST,
            IpAddr::V6(v) => !v.is_unicast_link_local(),
        }
}
fn add_row(groups: &mut Groups, c: &Conn, arp: &Arp, owners: &HashMap<Ipv6Addr, Option<&str>>) {
    let (Some(src), Some(dst)) = (c.src, c.dst) else {
        return;
    };
    if c.zone == "swan" || !meaningful_dst(dst) {
        return;
    }
    let ndp_mac = match src {
        IpAddr::V4(ip) if ip.is_private() => None,
        IpAddr::V6(ip) => {
            let owner = owners.get(&ip);
            // A delegated global prefix alone does not establish LAN origin.
            // Conntrack's LAN zone or an unambiguous bridge neighbor can.
            let unique = owner.copied().flatten();
            let verified = unique.is_some_and(|mac| c.mac.is_empty() || c.mac == mac);
            if !(ip.is_unique_local()
                || (ip.segments()[0] & 0xe000 == 0x2000 && (c.zone == "slan" || verified)))
                || (owner == Some(&None) && c.mac.is_empty())
            {
                return;
            }
            unique
        }
        _ => return,
    };
    let hw = arp.get(&src);
    let mac = if c.mac.is_empty() {
        ndp_mac
            .or_else(|| hw.map(|(mac, _)| mac.as_str()))
            .unwrap_or("")
    } else {
        &c.mac
    };
    let key = if mac.is_empty() {
        Cow::Owned(format!("ip:{src}"))
    } else {
        Cow::Borrowed(mac)
    };
    let g = if let Some(group) = groups.get_mut(key.as_ref()) {
        group
    } else {
        groups.entry(key.into_owned()).or_insert_with(|| Group {
            device: Device {
                mac: mac.to_string(),
                ..Device::default()
            },
            ..Group::default()
        })
    };
    if g.device.iface.is_empty() {
        if let Some((_, iface)) = hw.filter(|(arp_mac, _)| arp_mac == mac) {
            g.device.iface.clone_from(iface);
        }
    }
    match src {
        IpAddr::V4(ip) if g.device.ip.is_empty() => g.device.ip = ip.to_string(),
        IpAddr::V6(ip) => {
            g.v6.insert(ip);
        }
        _ => {}
    }
    g.device.total += 1;
    g.device.bytes_up = g.device.bytes_up.saturating_add(c.bytes);
    g.device.bytes_down = g.device.bytes_down.saturating_add(c.reply_bytes);
    if c.failing() {
        g.device.failing += 1;
        g.failing.insert((dst, c.dport));
    } else {
        g.device.established += 1;
        g.working.insert((dst, c.dport));
    }
}

fn destinations(dest: HashSet<(IpAddr, u64)>) -> Vec<String> {
    let mut list: Vec<_> = dest
        .into_iter()
        .map(|(ip, port)| {
            if port == 0 {
                ip.to_string()
            } else if ip.is_ipv6() {
                format!("[{ip}]:{port}")
            } else {
                format!("{ip}:{port}")
            }
        })
        .collect();
    list.sort_unstable();
    list
}

fn finish_groups(
    mut groups: Groups,
    ndp: &Neighbors,
    hostnames: &HashMap<String, String>,
) -> Vec<Device> {
    for (mac, addrs) in ndp {
        let g = groups.entry(mac.clone()).or_insert_with(|| Group {
            device: Device {
                mac: mac.clone(),
                ..Device::default()
            },
            ..Group::default()
        });
        g.v6.extend(addrs);
    }
    let mut devices: Vec<_> = groups
        .into_values()
        .map(|g| {
            let mut d = g.device;
            d.ipv6 = g.v6.into_iter().map(|ip| ip.to_string()).collect();
            d.ipv6.sort_unstable();
            if d.ip.is_empty() {
                d.ip = d.ipv6.first().cloned().unwrap_or_default();
            }
            d.working = destinations(g.working);
            d.failing_dsts = destinations(g.failing);
            d.hostname = hostnames.get(&d.mac).cloned().unwrap_or_default();
            d
        })
        .collect();
    devices.sort_by(|a, b| {
        b.failing
            .cmp(&a.failing)
            .then_with(|| a.ip.cmp(&b.ip))
            .then_with(|| a.mac.cmp(&b.mac))
    });
    devices
}

#[derive(Debug, Serialize)]
pub struct QueueStat {
    pub queue: i32,
    pub portid: i64,
    pub queued: i64,
    pub copy_mode: i64,
    pub copy_range: i64,
    pub queue_drop: i64,
    pub user_drop: i64,
    pub id_seq: i64,
}
#[derive(Debug, Serialize)]
pub struct IfaceBytes {
    pub iface: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}
#[derive(Debug, Default, Serialize)]
pub struct Count {
    pub count: u64,
    pub max: u64,
}
#[derive(Debug, Default, Serialize)]
pub struct ConnSummary {
    pub total: usize,
    pub failing: usize,
    pub by_proto: BTreeMap<Cow<'static, str>, usize>,
}
#[derive(Debug, Serialize)]
pub struct StorageUsage {
    pub path: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}
#[derive(Debug, Serialize)]
pub struct NetworkDashboard {
    pub nfqws2_running: bool,
    pub conntrack: Count,
    pub conns: ConnSummary,
    pub queues: Option<Vec<QueueStat>>,
    pub main_queue: i32,
    pub wan: Option<Vec<IfaceBytes>>,
    pub top_devices: Option<Vec<Device>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageUsage>,
}

pub struct NetworkMonitor {
    proc_root: PathBuf,
    router_root: PathBuf,
    ndp: Option<(Instant, Neighbors)>,
    wan_ifaces: Vec<String>,
}
impl NetworkMonitor {
    pub fn new(proc_root: impl Into<PathBuf>, router_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            router_root: router_root.into(),
            ndp: None,
            wan_ifaces: vec![],
        }
    }
    pub fn with_wan_ifaces(mut self, wan: &[String]) -> Self {
        self.wan_ifaces = wan.to_vec();
        self.ndp = None;
        self
    }
    fn scan(&self, mut f: impl FnMut(Conn)) -> io::Result<()> {
        self.connection_reader()?.visit(|row| {
            f(row);
            Ok(())
        })
    }
    pub fn connection_reader(&self) -> io::Result<ConnectionReader> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(self.proc_root.join("net/nf_conntrack"))?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected conntrack proc file",
            ));
        }
        Ok(ConnectionReader(file))
    }
    pub fn connections(&self) -> io::Result<Connections> {
        let mut items = Vec::new();
        self.scan(|c| items.push(c))?;
        Ok(Connections {
            count: items.len(),
            items,
        })
    }
    fn arp(&self) -> Arp {
        let mut table = Arp::new();
        let _ = rows(&self.proc_root.join("net/arp"), |line| {
            let mut f = line.split_ascii_whitespace();
            if let (Some(ip), Some(mac), Some(iface)) =
                (f.next().and_then(|v| v.parse().ok()), f.nth(2), f.nth(1))
            {
                table.insert(ip, (mac.to_ascii_lowercase(), iface.to_owned()));
            }
        });
        table
    }
    fn hostnames(&self) -> HashMap<String, String> {
        let mut names = HashMap::new();
        for rel in [
            "tmp/dhcp.leases",
            "var/dhcp.leases",
            "var/lib/misc/dnsmasq.leases",
            "tmp/dnsmasq.leases",
        ] {
            if rows(&self.router_root.join(rel), |line| {
                let mut f = line.split_ascii_whitespace();
                if let (Some(mac), Some(name)) = (f.nth(1), f.nth(1)) {
                    if name != "*" {
                        names.insert(mac.to_ascii_lowercase(), name.to_string());
                    }
                }
            })
            .is_ok()
            {
                break;
            }
        }
        names
    }
    fn neighbors(&mut self) -> &Neighbors {
        if self
            .ndp
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(5))
        {
            let data = if self.router_root == Path::new("/") {
                read_ndp(&self.wan_ifaces).unwrap_or_default()
            } else {
                Neighbors::new()
            };
            self.ndp = Some((Instant::now(), data));
        }
        &self.ndp.as_ref().unwrap().1
    }
    fn grouped(&mut self, mut each: impl FnMut(&Conn)) -> io::Result<Vec<Device>> {
        let reader = self.connection_reader()?;
        let arp = self.arp();
        let names = self.hostnames();
        let neighbors = self.neighbors();
        let mut owners = HashMap::new();
        for (mac, ips) in neighbors {
            for ip in ips {
                owners
                    .entry(*ip)
                    .and_modify(|owner| *owner = None)
                    .or_insert(Some(mac.as_str()));
            }
        }
        let mut grouped = Groups::new();
        reader.visit(|row| {
            each(&row);
            add_row(&mut grouped, &row, &arp, &owners);
            Ok(())
        })?;
        Ok(finish_groups(grouped, neighbors, &names))
    }
    pub fn devices(&mut self) -> io::Result<Devices> {
        Ok(Devices {
            devices: self.grouped(|_| {})?,
        })
    }
    pub fn dashboard(
        &mut self,
        wan_ifaces: &[String],
        main_queue: i32,
        data_dir: &Path,
    ) -> NetworkDashboard {
        let number = |key: &str| {
            fs::read_to_string(self.proc_root.join("sys/net/netfilter").join(key))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        let conntrack = match (number("nf_conntrack_count"), number("nf_conntrack_max")) {
            (Some(count), Some(max)) => Count { count, max },
            _ => Count::default(),
        };
        let mut queues = Vec::new();
        let _ = rows(
            &self.proc_root.join("net/netfilter/nfnetlink_queue"),
            |line| {
                let mut f = line.split_ascii_whitespace();
                let mut v = [0; 8];
                for dest in &mut v {
                    let Some(token) = f.next() else { return };
                    *dest = token.parse().unwrap_or(0);
                }
                let [queue, portid, queued, copy_mode, copy_range, queue_drop, user_drop, id_seq] =
                    v;
                queues.push(QueueStat {
                    queue: queue as i32,
                    portid,
                    queued,
                    copy_mode,
                    copy_range,
                    queue_drop,
                    user_drop,
                    id_seq,
                });
            },
        );
        let mut wan = Vec::new();
        let _ = rows(&self.proc_root.join("net/dev"), |line| {
            let Some((name, info)) = line.split_once(':') else {
                return;
            };
            let name = name.trim();
            if !wan_ifaces.iter().any(|v| v == name) {
                return;
            }
            let mut f = info.split_ascii_whitespace();
            let rx_bytes = f.next();
            let rx_packets = f.next();
            let tx_bytes = f.nth(6);
            let tx_packets = f.next();
            if f.nth(5).is_none() {
                return;
            }
            let n = |v: Option<&str>| v.and_then(|n| n.parse().ok()).unwrap_or(0);
            wan.push(IfaceBytes {
                iface: name.to_string(),
                rx_bytes: n(rx_bytes),
                rx_packets: n(rx_packets),
                tx_bytes: n(tx_bytes),
                tx_packets: n(tx_packets),
            });
        });
        let mut conns = ConnSummary::default();
        let top_devices = self.grouped(|c| {
            conns.total += 1;
            conns.failing += usize::from(c.failing());
            *conns.by_proto.entry(c.proto.clone()).or_default() += 1;
        });
        let top_devices = match top_devices {
            Ok(mut devs) => {
                devs.sort_by_key(|d| std::cmp::Reverse(d.bytes_up.saturating_add(d.bytes_down)));
                devs.truncate(8);
                Some(devs)
            }
            Err(_) => {
                conns = ConnSummary::default();
                None
            }
        };
        NetworkDashboard {
            nfqws2_running: queues.iter().any(|q| q.queue == main_queue),
            conntrack,
            conns,
            queues: (!queues.is_empty()).then_some(queues),
            main_queue,
            wan: (!wan.is_empty()).then_some(wan),
            top_devices,
            storage: crate::storage::usage(data_dir, &self.router_root),
        }
    }
}
