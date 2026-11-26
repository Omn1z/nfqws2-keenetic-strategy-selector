use super::flow::Tracker;
use crate::{emit, packet, CANCEL};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    io::{self, BufRead, Read},
    os::unix::{
        fs::FileTypeExt,
        io::{AsRawFd, OwnedFd},
    },
    path::Path,
    sync::{atomic::Ordering, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
const SNAP: usize = 96;
const PACKETS_PER_SECOND: usize = 512;
fn valid(n: &str) -> bool {
    n.len() < 16
        && n.strip_prefix("awg")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
fn names(list: Vec<String>) -> io::Result<BTreeSet<String>> {
    if list.len() > 64 || list.iter().any(|n| !valid(n)) {
        return Err(io::Error::other("неверный список интерфейсов AWG"));
    }
    Ok(list.into_iter().collect())
}
fn index(name: &str) -> io::Result<Option<i32>> {
    let net = Path::new("/sys/class/net").join(name);
    if !net.join("tun_flags").try_exists()? {
        return Ok(None);
    }
    let socket = Path::new("/var/run/amneziawg").join(format!("{name}.sock"));
    match socket.symlink_metadata() {
        Ok(m) if m.file_type().is_socket() => (),
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    let flags = fs::read_to_string(net.join("flags"))?;
    if u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).map_err(io::Error::other)? & 1
        == 0
    {
        return Ok(None);
    }
    let idx = unsafe { libc::if_nametoindex(CString::new(name).unwrap().as_ptr()) };
    Ok((idx > 0).then_some(idx as i32))
}
struct Sensor {
    fd: OwnedFd,
    index: i32,
    flows: Tracker,
}
impl Sensor {
    fn open(index: i32) -> io::Result<Self> {
        let mut filter = [libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: SNAP as u32,
        }]; // BPF_RET | BPF_K
        Ok(Self {
            fd: packet::open(index, libc::SOCK_DGRAM, &mut filter)?,
            index,
            flows: Tracker::default(),
        })
    }
    fn read(
        &mut self,
        name: &str,
        generation: u64,
        now: u64,
        budget: &mut usize,
        event_budget: &mut usize,
        limited: &mut bool,
    ) -> io::Result<()> {
        let mut bytes = [0; SNAP];
        for _ in 0..(*budget).min(32) {
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut len = size_of_val(&addr) as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                    (&mut addr as *mut libc::sockaddr_ll).cast(),
                    &mut len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    break;
                }
                return Err(e);
            }
            *budget -= 1;
            if addr.sll_ifindex != self.index || !matches!(addr.sll_pkttype, 0 | 4) {
                continue;
            }
            if let Some(entry) =
                self.flows
                    .observe(&bytes[..n as usize], addr.sll_pkttype == 4, now)
            {
                if *event_budget == 0 {
                    *limited = true;
                    continue;
                }
                emit(json!({"iface":name,"generation":generation,"flow":entry}))?;
                *event_budget -= 1;
            }
            *limited |= self.flows.limited;
        }
        Ok(())
    }
}
pub(super) fn run(list: Vec<String>) -> io::Result<()> {
    let wanted = Arc::new(Mutex::new((0u64, names(list)?)));
    let control = wanted.clone();
    unsafe {
        libc::signal(
            libc::SIGTERM,
            crate::cancel as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            crate::cancel as *const () as libc::sighandler_t,
        );
    }
    thread::Builder::new()
        .name("trace-control".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            let mut input = io::stdin().lock();
            loop {
                let mut line = String::new();
                if (&mut input).take(1025).read_line(&mut line).is_err()
                    || line.len() > 1024
                    || !line.ends_with('\n')
                {
                    break;
                }
                let mut words = line.split_ascii_whitespace();
                if words.next() != Some("set") {
                    break;
                }
                let Some(revision) = words.next().and_then(|v| v.parse::<u64>().ok()) else {
                    break;
                };
                let Ok(new) = names(words.map(str::to_owned).collect()) else {
                    break;
                };
                *control.lock().unwrap() = (revision, new);
            }
            CANCEL.store(true, Ordering::Release);
        })?;
    let mut sensors: BTreeMap<String, Sensor> = BTreeMap::new();
    let start = Instant::now();
    let mut second = u64::MAX;
    let mut budget = 0;
    let mut event_budget = 0;
    let mut limited = false;
    let mut reported = None;
    let mut generation = 0;
    while !CANCEL.load(Ordering::Acquire) {
        let now = start.elapsed().as_secs();
        if now != second {
            second = now;
            budget = PACKETS_PER_SECOND;
            event_budget = 64;
            let (revision, authorized) = wanted.lock().unwrap().clone();
            if revision != generation {
                sensors.clear();
                generation = revision;
            }
            sensors.retain(|name, _| authorized.contains(name));
            let mut active = 0;
            for name in &authorized {
                let idx = match index(name) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                    r => r?,
                };
                if let Some(idx) = idx {
                    active += 1;
                    if sensors.get(name).is_some_and(|s| s.index != idx) {
                        sensors.remove(name);
                    }
                    if !sensors.contains_key(name) && sensors.len() < 8 {
                        match Sensor::open(idx) {
                            Ok(sensor) => {
                                sensors.insert(name.clone(), sensor);
                            }
                            Err(e) if packet::disappeared(&e) => {}
                            Err(e) => return Err(e),
                        }
                    }
                } else {
                    sensors.remove(name);
                }
            }
            for s in sensors.values_mut() {
                s.flows.prune(now);
                limited |= packet::dropped(&s.fd)?;
            }
            limited |= active > 8;
            let state = (sensors.len(), limited, generation);
            if reported != Some(state) {
                emit(
                    json!({"ready":true,"observed_interfaces":state.0,"limited":state.1,"generation":generation}),
                )?;
                reported = Some(state);
            }
        }
        if budget == 0 {
            limited = true;
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let mut fds: Vec<_> = sensors
            .values()
            .map(|s| libc::pollfd {
                fd: s.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let count = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 200) };
        if count < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let mut expired = Vec::new();
        for ((name, s), fd) in sensors.iter_mut().zip(&fds) {
            if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                expired.push(name.clone());
                continue;
            }
            if fd.revents & libc::POLLIN != 0 {
                if let Err(e) = s.read(
                    name,
                    generation,
                    now,
                    &mut budget,
                    &mut event_budget,
                    &mut limited,
                ) {
                    if packet::disappeared(&e) {
                        expired.push(name.clone());
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        for name in expired {
            sensors.remove(&name);
        }
    }
    Ok(())
}
