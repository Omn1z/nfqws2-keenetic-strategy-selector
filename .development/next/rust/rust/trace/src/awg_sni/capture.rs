use crate::{emit, hello::single_ipv4_sni, packet, CANCEL};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const SNAP: usize = 2048;
const BRIDGES: usize = 8;
const PACKETS_PER_SECOND: usize = 512;

fn filter() -> [libc::sock_filter; 20] {
    // IPv4 Ethernet, TCP :443, unfragmented, payload starts a ClientHello.
    // Require the filter before binding a socket to a LAN bridge.
    [
        (0x28, 0, 0, 12),          // ldh  ether type
        (0x15, 0, 17, 0x0800),     // jeq  IPv4 or drop
        (0x30, 0, 0, 23),          // ldb  IPv4 protocol
        (0x15, 0, 15, 6),          // jeq  TCP or drop
        (0x28, 0, 0, 20),          // ldh  IPv4 flags and fragment offset
        (0x45, 13, 0, 0x3fff),     // jset MF or fragment offset to drop
        (0xb1, 0, 0, 14),          // ldxb IPv4 header length
        (0x48, 0, 0, 16),          // ldh  TCP destination port
        (0x15, 0, 10, 443),        // jeq  443 or drop
        (0x50, 0, 0, 26),          // ldb  TCP data offset and reserved bits
        (0x54, 0, 0, 0xf0),        // and  isolate the data offset
        (0x74, 0, 0, 2),           // rsh  data offset in bytes
        (0x0c, 0, 0, 0),           // add  IPv4 header length
        (0x07, 0, 0, 0),           // tax  combined IPv4 and TCP header length
        (0x48, 0, 0, 14),          // ldh  TLS record type and major version
        (0x15, 0, 3, 0x1603),      // jeq  TLS handshake record or drop
        (0x50, 0, 0, 19),          // ldb  handshake type
        (0x15, 0, 1, 1),           // jeq  ClientHello or drop
        (0x06, 0, 0, SNAP as u32), // ret  accept only the snapshot length
        (0x06, 0, 0, 0),           // ret  drop from this capture socket
    ]
    .map(|(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k })
}

fn bridge_indices(root: &Path) -> io::Result<Vec<i32>> {
    let mut indices = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let path = entry.path();
        if !name.as_encoded_bytes().starts_with(b"br") || !path.join("bridge").is_dir() {
            continue;
        }
        // An interface can vanish between the directory scan and these reads.
        let Ok(flags) = fs::read_to_string(path.join("flags")) else {
            continue;
        };
        if !u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
            .is_ok_and(|flags| flags & libc::IFF_UP as u32 != 0)
        {
            continue;
        }
        if let Ok(index) = fs::read_to_string(path.join("ifindex")) {
            if let Ok(index) = index.trim().parse::<i32>() {
                if index > 0 {
                    indices.push(index);
                }
            }
        }
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

fn refresh(sockets: &mut BTreeMap<i32, OwnedFd>, root: &Path) -> io::Result<bool> {
    let mut wanted = bridge_indices(root)?;
    let mut limited = wanted.len() > BRIDGES;
    wanted.truncate(BRIDGES);
    sockets.retain(|index, _| wanted.binary_search(index).is_ok());
    let mut error = None;
    for index in wanted {
        if let std::collections::btree_map::Entry::Vacant(entry) = sockets.entry(index) {
            match packet::open(index, libc::SOCK_RAW, &mut filter()) {
                Ok(socket) => {
                    entry.insert(socket);
                }
                Err(e) if packet::disappeared(&e) => (),
                Err(e) => {
                    error = Some(e);
                }
            }
        }
    }
    if let Some(error) = error {
        if sockets.is_empty() {
            return Err(error);
        }
        limited = true;
    }
    for socket in sockets.values() {
        limited |= packet::dropped(socket)?;
    }
    Ok(limited)
}

fn read(index: i32, fd: &OwnedFd, budget: &mut usize) -> io::Result<()> {
    let mut frame = [0; SNAP];
    for _ in 0..(*budget).min(32) {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut len = size_of_val(&addr) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                frame.as_mut_ptr().cast(),
                frame.len(),
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
        if addr.sll_ifindex != index {
            continue;
        }
        if let Some((dst, name)) = single_ipv4_sni(&frame[..n as usize]) {
            emit(json!({"sni":{"name":name,"dst":dst}}))?;
        }
    }
    Ok(())
}

pub(super) fn run() -> io::Result<()> {
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
        .name("trace-sni-control".into())
        .stack_size(64 * 1024)
        .spawn(|| {
            let _ = io::stdin().read(&mut [0]);
            CANCEL.store(true, Ordering::Release);
        })?;
    let root = Path::new("/sys/class/net");
    let mut sockets = BTreeMap::new();
    let mut budget = 0;
    let start = Instant::now();
    let mut second = None;
    let mut reported = None;
    let mut limited = false;
    while !CANCEL.load(Ordering::Acquire) {
        let now = start.elapsed().as_secs();
        if Some(now) != second {
            second = Some(now);
            budget = PACKETS_PER_SECOND;
            limited |= refresh(&mut sockets, root)?;
        }
        let state = (sockets.len(), limited);
        if reported != Some(state) {
            emit(json!({"ready":true,"observed_interfaces":state.0,"limited":state.1}))?;
            reported = Some(state);
        }
        if budget == 0 {
            limited = true;
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let mut fds: Vec<_> = sockets
            .values()
            .map(|fd| libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 200) };
        if ready < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let mut expired = Vec::new();
        for ((index, socket), fd) in sockets.iter().zip(fds) {
            if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                expired.push(*index);
                continue;
            }
            if fd.revents & libc::POLLIN != 0 {
                if let Err(e) = read(*index, socket, &mut budget) {
                    if packet::disappeared(&e) {
                        expired.push(*index);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        for index in expired {
            sockets.remove(&index);
        }
    }
    Ok(())
}
