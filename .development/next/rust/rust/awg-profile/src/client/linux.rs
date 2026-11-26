use super::{
    conf, invalid, nested, resolve_endpoint, supervisor, uapi_message, ActiveReplacementPeer,
    Managed, NativeRemovalSeal, NestedOuter, Runtime, Spec, Tunnel,
};
use crate::runtime::request;
use nfqws2_router_command::{Runner, System};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    net::{IpAddr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Child,
    thread,
    time::{Duration, Instant},
};

fn call(program: &str, args: &[&str]) -> io::Result<String> {
    System.run(program, args, Instant::now() + Duration::from_secs(4))
}
fn direct_socket_mark(ip: IpAddr, wan: &[String]) -> io::Result<Option<u32>> {
    let tool = if Path::new("/opt/libexec/ip-full").is_file() {
        "/opt/libexec/ip-full"
    } else {
        "ip"
    };
    let (tables, xt) = if ip.is_ipv4() {
        ("/proc/net/ip_tables_names", "iptables")
    } else {
        ("/proc/net/ip6_tables_names", "ip6tables")
    };
    let grouped = match fs::read_to_string(tables) {
        Ok(names) if names.lines().any(|t| t == "mangle") => super::transport::grouped_output(
            &call(xt, &["-w", "-t", "mangle", "-S", "OUTPUT"])?,
            ip.is_ipv4(),
        )?,
        Ok(_) => false,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    super::transport::direct_socket_mark(ip, wan, tool, grouped, call)
}

pub(super) fn verify_direct_wan(
    runtime: &Runtime,
    endpoint: SocketAddr,
    wan: &[String],
) -> io::Result<()> {
    let mark = direct_socket_mark(endpoint.ip(), wan)?.unwrap_or(0);
    if !runtime.verifies_live_wan_path(endpoint, mark, wan, true) {
        return Err(invalid(
            "не подтверждён прямой маршрут WAN для зависимого AWG",
        ));
    }
    verify_transport_path(endpoint)
}

fn check_path(endpoint: SocketAddr, addresses: &[String]) -> io::Result<()> {
    let ip = endpoint.ip();
    let used = call("ip", &["-o", "addr", "show"])?;
    for addr in addresses {
        let host = addr
            .split('/')
            .next()
            .unwrap()
            .parse::<IpAddr>()
            .map_err(|_| invalid("неверный адрес туннеля"))?;
        if host == ip
            || host.is_loopback()
            || host.is_multicast()
            || host.is_unspecified()
            || used
                .split_ascii_whitespace()
                .filter_map(|t| t.split('/').next()?.parse::<IpAddr>().ok())
                .any(|v| v == host)
        {
            return Err(invalid("адрес туннеля уже занят или зарезервирован"));
        }
    }
    verify_transport_path(endpoint)
}

fn verify_transport_path(endpoint: SocketAddr) -> io::Result<()> {
    // Read the installed transport exclusions before handing UDP to the engine.
    let names = if endpoint.is_ipv4() {
        "/proc/net/ip_tables_names"
    } else {
        "/proc/net/ip6_tables_names"
    };
    let nft = Path::new("/sys/module/nf_tables").try_exists()?;
    super::transport::verify(endpoint, fs::read_to_string(names), nft, call)
}
mod launcher;
mod nested_transport;
mod receipt;
pub use launcher::run_launcher;
use nested_transport::NestedTransport;
pub(super) use nested_transport::{
    check_ip_names, check_names as check_nested_names, ip as nested_ip, lock_table,
};

pub(super) fn preflight_nested_mtu(
    runtime: &Runtime,
    spec: &Spec,
    endpoint: SocketAddr,
    shared_wan: Option<&[String]>,
) -> io::Result<()> {
    if runtime.root != Path::new("/") {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let outer = spec
        .outer
        .as_ref()
        .ok_or_else(|| invalid("нет выбранного внешнего туннеля"))?;
    let cfg = conf::parse(&spec.conf, 0)?;
    let peer = NestedTransport::preflight_mtu(outer, endpoint.ip(), &cfg)?;
    if let Some(wan) = shared_wan {
        nested::verify_shared_outer_wan(endpoint, peer, |udp, mark| {
            runtime.verifies_live_wan(udp, mark, wan)
        })?;
    }
    Ok(())
}
struct Owner {
    root: PathBuf,
    socket: PathBuf,
    tx_packets: PathBuf,
    pid: u32,
    peer_hex: String,
    interval: String,
    proof: Option<receipt::Receipt>,
    resumed: bool,
    temporary: Option<launcher::Launch>,
    marker: Option<fs::File>,
    nested: Option<NestedTransport>,
}
fn read_hex_flags(path: &Path) -> io::Result<u32> {
    fs::read_to_string(path)?
        .trim()
        .strip_prefix("0x")
        .and_then(|flags| u32::from_str_radix(flags, 16).ok())
        .ok_or_else(|| invalid("не подтверждены параметры интерфейса полного туннеля AWG"))
}

impl Owner {
    fn native_peer_sample(
        &self,
        spec: &Spec,
        config: &serde_json::Value,
        provisional: bool,
        expected_outer: Option<&NestedOuter>,
        require_handshake: bool,
    ) -> io::Result<(ActiveReplacementPeer, Option<nested::OuterPeer>, u64)> {
        let changed = || invalid("не подтверждён владелец работающего AWG");
        let r = self.proof.as_ref().ok_or_else(changed)?;
        if self.root != Path::new("/")
            || self.temporary.is_some() != provisional
            || self.nested.is_some() != expected_outer.is_some()
            || self.nested.as_ref().map(NestedTransport::snapshot) != r.nested
            || !r.matches_spec(spec)
            || receipt::read(&self.socket)?.as_ref() != Some(r)
        {
            return Err(changed());
        }
        r.owner(&self.root, &self.socket)?;
        let bytes = request(
            &self.socket,
            b"get=1\n\n",
            Duration::from_millis(700),
            Some(r.pid),
        )?;
        if !r.matches_keys(&bytes) {
            return Err(changed());
        }
        let mut mark = None;
        let mut last_handshake = 0;
        let (endpoint, allowed) = crate::runtime::routing_peer_sample(
            &bytes,
            config,
            crate::now(),
            require_handshake,
            |s| {
                mark = s["socket_mark"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok());
                last_handshake = s["last_handshake"].as_u64().unwrap_or_default();
            },
        )?;
        // Official amneziawg-go omits fwmark for an unmarked socket.
        // A nested owner must still report its exact nonzero mark.
        let socket_mark = match (mark, expected_outer) {
            (Some(mark), _) => mark,
            (None, None) => 0,
            (None, Some(_)) => return Err(changed()),
        };
        let (mtu, outer) = match (&self.nested, expected_outer) {
            (Some(nested), Some(outer)) if !provisional => {
                let cfg = conf::parse(&spec.conf, 0)?;
                let (mtu, observed) =
                    nested.verified_mtu(outer, endpoint.ip(), socket_mark, &cfg)?;
                (mtu, Some(observed))
            }
            (None, None) if matches!(socket_mark, 0 | crate::DIRECT_SOCKET_MARK) => {
                let mtu = fs::read_to_string(
                    self.root
                        .join("sys/class/net")
                        .join(&spec.iface)
                        .join("mtu"),
                )?
                .trim()
                .parse::<u16>()
                .map_err(|_| changed())?;
                (mtu, None)
            }
            _ => return Err(changed()),
        };
        r.owner(&self.root, &self.socket)?;
        if receipt::read(&self.socket)?.as_ref() != Some(r) {
            return Err(changed());
        }
        Ok((
            ActiveReplacementPeer {
                owner: r.removal_seal()?,
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                endpoint: SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()),
                socket_mark,
                mtu,
                allowed,
                underlay: None,
                nested_only: false,
            },
            outer,
            last_handshake,
        ))
    }

    fn require_live_tun(&self, spec: &Spec) -> io::Result<()> {
        let device = self.root.join("sys/class/net").join(&spec.iface);
        let flags = read_hex_flags(&device.join("flags"))?;
        let tun = read_hex_flags(&device.join("tun_flags"))?;
        if flags & libc::IFF_UP as u32 == 0 || tun & 3 != libc::IFF_TUN as u32 {
            return Err(invalid("не подтверждён активный TUN-интерфейс AWG"));
        }
        Ok(())
    }
}

impl Tunnel for Owner {
    fn resumed(&self) -> bool {
        self.resumed
    }
    fn detach(&mut self) -> io::Result<()> {
        if self.temporary.is_some() {
            return self.stop();
        }
        // The guardian has already transferred the engine to init. On an
        // ambiguous identity leave both the process and its recovery record.
        let result = self.proof.as_ref().map_or(Ok(()), |r| {
            if receipt::read(&self.socket)?.as_ref() != Some(r) {
                return Err(invalid("заменена запись владения клиентом"));
            }
            r.verify(&self.root, &self.socket)
        });
        self.proof = None;
        self.nested.take();
        self.marker.take();
        result
    }
    fn matches_response(&self, bytes: &[u8]) -> bool {
        self.proof
            .as_ref()
            .is_some_and(|r| r.matches_keys(bytes) && r.owner(&self.root, &self.socket).is_ok())
    }
    fn alive(&mut self) -> bool {
        self.proof
            .as_ref()
            .is_some_and(|r| r.owner(&self.root, &self.socket).is_ok())
    }
    fn stop(&mut self) -> io::Result<()> {
        let Some(r) = &self.proof else {
            return Ok(());
        };
        match (&self.nested, &r.nested) {
            (Some(nested), Some(saved)) if self.root == Path::new("/") => {
                nested.verify_retirement(saved)?;
            }
            (None, None) => (),
            _ => return Err(invalid("запись владельца вложенного AWG изменилась")),
        }
        if let Some(launch) = &self.temporary {
            if launch.pid() != r.pid || receipt::read(&self.socket)?.as_ref() != Some(r) {
                return Err(invalid("запись временного владельца AWG изменилась"));
            }
            // The guardian still owns this child. Closing its private control
            // socket also waits for it to reap the engine.
            drop(self.temporary.take());
        }
        terminate_receipt(&self.root, &self.socket, r)?;
        if let Some(n) = &self.nested {
            n.release()?;
        }
        r.remove_stale_socket(&self.socket)?;
        r.remove(&self.socket)?;
        self.nested.take();
        self.proof = None;
        self.marker.take();
        Ok(())
    }
    fn active_replacement_peer(
        &self,
        spec: &Spec,
        config: &serde_json::Value,
        provisional: bool,
        expected_outer: Option<&NestedOuter>,
    ) -> io::Result<(ActiveReplacementPeer, Option<nested::OuterPeer>)> {
        self.native_peer_sample(spec, config, provisional, expected_outer, true)
            .map(|(peer, outer, _)| (peer, outer))
    }

    fn configured_cold_replacement_peer(
        &self,
        spec: &Spec,
        config: &serde_json::Value,
        provisional: bool,
        before_first_handshake: bool,
    ) -> io::Result<ActiveReplacementPeer> {
        let (peer, _, last_handshake) =
            self.native_peer_sample(spec, config, provisional, None, false)?;
        if before_first_handshake && last_handshake != 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.require_live_tun(spec)?;
        Ok(peer)
    }

    fn go_full_primary_peer(
        &self,
        spec: &Spec,
        config: &serde_json::Value,
    ) -> io::Result<ActiveReplacementPeer> {
        let (peer, _, _) = self.native_peer_sample(spec, config, false, None, false)?;
        let device = self.root.join("sys/class/net").join(&spec.iface);
        let flags = read_hex_flags(&device.join("flags"))?;
        let tun = read_hex_flags(&device.join("tun_flags"))?;
        if flags & libc::IFF_UP as u32 == 0 || tun & libc::IFF_TUN as u32 == 0 {
            return Err(invalid(
                "не подтверждён активный интерфейс полного туннеля AWG",
            ));
        }
        Ok(peer)
    }

    fn commit_temporary_replacement(&mut self, expected: &NativeRemovalSeal) -> io::Result<()> {
        let changed = || invalid("запись временного владельца AWG изменилась");
        let record = self.proof.as_ref().ok_or_else(changed)?;
        if record.nested.is_some()
            || record.removal_seal()?.ne(expected)
            || receipt::read(&self.socket)?.as_ref() != Some(record)
        {
            return Err(changed());
        }
        record.verify(&self.root, &self.socket)?;
        self.temporary.take().ok_or_else(changed)?.commit()?;
        record.owner(&self.root, &self.socket)
    }

    fn native_removal_seal(&self) -> io::Result<NativeRemovalSeal> {
        self.proof
            .as_ref()
            .ok_or_else(|| invalid("нет записи владельца AWG"))?
            .removal_seal()
    }
    fn nested_iface(&self) -> Option<&str> {
        self.nested.as_ref().map(|n| n.routes.outer.as_str())
    }
    fn verified_routed_mtu(
        &self,
        spec: &Spec,
        outer: Option<&NestedOuter>,
        connected: bool,
    ) -> io::Result<super::settings::RoutedMtuSample> {
        let stale = || invalid("не подтверждено владение работающим AWG после правки профиля");
        if self.root != Path::new("/") || self.temporary.is_some() {
            return Err(stale());
        }
        let proof = self.proof.as_ref().ok_or_else(stale)?;
        if !proof.matches_spec(spec)
            || proof.nested != self.nested.as_ref().map(NestedTransport::snapshot)
            || receipt::read(&self.socket)?.as_ref() != Some(proof)
        {
            return Err(stale());
        }
        let status = self.snapshot()?;
        if connected && status["connected"] != true {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let endpoint = supervisor::live_transport_endpoint(&status).ok_or_else(stale)?;
        let socket_mark = match status.get("socket_mark") {
            Some(mark) => mark.as_u64().and_then(|m| u32::try_from(m).ok()).ok_or_else(stale)?,
            // The official engine omits fwmark for an unmarked direct socket.
            None if outer.is_none() && self.nested.is_none() => 0,
            None => return Err(stale()),
        };
        let (effective_mtu, outer_endpoint) = match (outer, &self.nested) {
            (Some(outer), Some(nested)) => {
                let cfg = conf::parse(&spec.conf, 0)?;
                let (mtu, outer_peer) =
                    nested.verified_mtu(outer, endpoint.ip(), socket_mark, &cfg)?;
                (mtu, outer_peer.endpoint)
            }
            (None, None) if [0, crate::DIRECT_SOCKET_MARK].contains(&socket_mark) => {
                let mtu = fs::read_to_string(
                    self.root
                        .join("sys/class/net")
                        .join(&spec.iface)
                        .join("mtu"),
                )?
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|mtu| (576..=9000).contains(mtu))
                .ok_or_else(stale)?;
                (mtu, None)
            }
            _ => return Err(stale()),
        };
        proof.owner(&self.root, &self.socket)?;
        if receipt::read(&self.socket)?.as_ref() != Some(proof) {
            return Err(stale());
        }
        Ok(super::settings::RoutedMtuSample {
            endpoint,
            effective_mtu,
            socket_mark,
            connected: status["connected"] == true,
            outer_endpoint,
        })
    }
    fn repair_nested(&mut self) -> io::Result<()> {
        let n = self.nested.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        let buf = request(
            &self.socket,
            b"get=1\n\n",
            Duration::from_secs(1),
            Some(self.pid),
        )?;
        let mark = n.routes.mark()?.to_string();
        let mut status = serde_json::json!({});
        crate::runtime::uapi(&buf, crate::now(), &mut status)?;
        if std::str::from_utf8(&buf).ok().is_some_and(|s| {
            s.lines()
                .any(|l| l.strip_prefix("fwmark=") == Some(mark.as_str()))
                && s.lines()
                    .any(|l| l.strip_prefix("public_key=") == Some(self.peer_hex.as_str()))
        }) {
            n.repair()
        } else {
            Err(invalid("движок не подтвердил метку вложенного туннеля"))
        }
    }
    fn snapshot(&self) -> io::Result<serde_json::Value> {
        if let Some(r) = &self.proof {
            r.owner(&self.root, &self.socket)?;
        }
        let bytes = request(
            &self.socket,
            b"get=1\n\n",
            Duration::from_millis(700),
            Some(self.pid),
        )?;
        let mut status = serde_json::json!({});
        if self.proof.as_ref().is_some_and(|r| !r.matches_keys(&bytes))
            || !std::str::from_utf8(&bytes)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.strip_prefix("public_key="))
                .any(|key| key.eq_ignore_ascii_case(&self.peer_hex))
        {
            return Err(invalid("UAPI подтвердил другого пира, проверьте профиль"));
        }
        crate::runtime::uapi(&bytes, crate::now(), &mut status)?;
        // TUN TX counts inner packets. UAPI TX includes encrypted keepalives
        // and handshake retries, even when the router is completely idle.
        if let Some(count) = fs::read_to_string(&self.tx_packets)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            status["tun_tx_packets"] = count.into();
        }
        Ok(status)
    }
    fn probe(&mut self) -> io::Result<()> {
        if let Some(r) = &self.proof {
            r.verify(&self.root, &self.socket)?;
        }
        use std::fmt::Write;
        let peer = &self.peer_hex;
        let interval = if self.interval == "0" {
            "25"
        } else {
            &self.interval
        };
        let mut msg = format!(
            "set=1\npublic_key={peer}\nupdate_only=true\npersistent_keepalive_interval=0\npersistent_keepalive_interval={interval}\n"
        );
        if self.interval == "0" {
            // Beginning the next peer stanza flushes the pending keepalive.
            // Restore disabled keepalives within the same UAPI transaction.
            writeln!(
                msg,
                "public_key={peer}\nupdate_only=true\npersistent_keepalive_interval=0"
            )
            .unwrap();
        }
        msg.push('\n');
        if request(
            &self.socket,
            msg.as_bytes(),
            Duration::from_secs(2),
            Some(self.pid),
        )? != b"errno=0\n\n"
        {
            return Err(invalid("движок отклонил проверку keepalive"));
        }
        Ok(())
    }
}
pub(super) fn observed_warm_direct_peer(
    runtime: &Runtime,
    spec: &Spec,
    config: &serde_json::Value,
    expected: &NativeRemovalSeal,
) -> io::Result<ActiveReplacementPeer> {
    let changed = || io::Error::from(io::ErrorKind::WouldBlock);
    if runtime.root != Path::new("/") || spec.outer.is_some() || spec.permanent {
        return Err(changed());
    }
    let socket = socket_path(&runtime.root, &spec.iface);
    let saved = receipt::read(&socket)?.ok_or_else(changed)?;
    if saved.nested.is_some() || !saved.matches_spec(spec) || saved.removal_seal()? != *expected {
        return Err(changed());
    }
    saved.owner(&runtime.root, &socket)?;
    let bytes = request(&socket, b"get=1\n\n", Duration::from_millis(700), Some(saved.pid))?;
    if !saved.matches_keys(&bytes) {
        return Err(changed());
    }
    let mut mark = None;
    let (endpoint, allowed) = crate::runtime::routing_peer_sample(
        &bytes, config, crate::now(), true,
        |status| mark = status["socket_mark"].as_u64(),
    )?;
    if !endpoint.is_ipv6() || mark != Some(u64::from(crate::DIRECT_SOCKET_MARK)) {
        return Err(changed());
    }
    let mtu = fs::read_to_string(runtime.root.join("sys/class/net").join(&spec.iface).join("mtu"))?
        .trim()
        .parse::<u16>()
        .map_err(|_| changed())?;
    saved.owner(&runtime.root, &socket)?;
    if receipt::read(&socket)?.as_ref() != Some(&saved) {
        return Err(changed());
    }
    Ok(ActiveReplacementPeer {
        owner: saved.removal_seal()?,
        fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
        endpoint: SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()),
        socket_mark: crate::DIRECT_SOCKET_MARK,
        mtu,
        allowed,
        underlay: None,
        nested_only: false,
    })
}

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn soft_limit() -> (&'static str, &'static str) {
    let kb = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|v| {
            v.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")?
                    .split_ascii_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(0);
    match kb {
        0 => ("64MiB", "50"),
        1..=262144 => ("48MiB", "50"),
        262145..=524288 => ("64MiB", "50"),
        524289..=1048576 => ("96MiB", "75"),
        _ => ("128MiB", "100"),
    }
}
fn identity(path: &Path) -> io::Result<String> {
    let m = fs::symlink_metadata(path)?;
    use std::os::unix::fs::FileTypeExt;
    if !m.file_type().is_socket() {
        return Err(invalid("путь UAPI занят другим файлом"));
    }
    Ok(format!(
        "{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.ctime(),
        m.ctime_nsec()
    ))
}
pub(super) fn lock_marker(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    let marker = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = marker.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
    {
        return Err(invalid("неверный файл владельца AWG"));
    }
    if unsafe { libc::flock(marker.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(invalid("интерфейс занят другим менеджером"));
    }
    Ok(marker)
}
fn lock_interface(socket: &Path, iface: &str) -> io::Result<fs::File> {
    use std::io::Read;
    let mut marker = lock_marker(&socket.with_extension("n2s-owner"))?;
    if Path::new("/sys/class/net").join(iface).try_exists()? {
        return Err(invalid("интерфейс AWG уже существует"));
    }
    match identity(socket) {
        Ok(id) => {
            let mut saved = String::new();
            (&mut marker).take(256).read_to_string(&mut saved)?;
            let probe = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
            if id != saved
                || !matches!(probe.connect_timeout(&socket2::SockAddr::unix(socket)?,Duration::from_millis(100)),Err(ref e) if e.kind()==io::ErrorKind::ConnectionRefused)
                || identity(socket)? != id
            {
                return Err(invalid(
                    "существующий сокет AWG не принадлежит завершённому клиенту панели",
                ));
            }
            fs::remove_file(socket)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    Ok(marker)
}
fn terminate(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    // The child handle has not been reaped, so this PID cannot have been reused.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    for _ in 0..25 {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(40));
    }
    child.kill()?;
    child.wait().map(|_| ())
}
fn configure(
    launch: &mut launcher::Launch,
    socket: &Path,
    iface: &str,
    addresses: &[String],
    mtu: u64,
    message: &str,
    marker: &mut fs::File,
) -> io::Result<()> {
    use std::io::{Seek, Write};
    let timeout = Instant::now() + Duration::from_secs(5);
    loop {
        if !launch.running()? {
            return Err(invalid("движок AWG завершился до настройки"));
        }
        if socket.try_exists()? {
            let before = identity(socket)?;
            if let Ok(response) = request(
                socket,
                b"get=1\n\n",
                Duration::from_secs(1),
                Some(launch.pid()),
            ) {
                if identity(socket)? != before
                    || !response
                        .split(|b| *b == b'\n')
                        .any(|line| line == b"errno=0")
                {
                    return Err(invalid("сокет UAPI был заменён или вернул ошибку"));
                }
                marker.set_len(0)?;
                marker.rewind()?;
                marker.write_all(before.as_bytes())?;
                marker.sync_data()?;
                break;
            }
        }
        if Instant::now() >= timeout {
            return Err(invalid("движок не открыл свой сокет UAPI"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    for address in addresses {
        call(
            "ip",
            &["address", "add", address, "dev", iface, "noprefixroute"],
        )?;
    }
    call(
        "ip",
        &["link", "set", "dev", iface, "mtu", &mtu.to_string(), "up"],
    )?;
    if request(
        socket,
        message.as_bytes(),
        Duration::from_secs(3),
        Some(launch.pid()),
    )? != b"errno=0\n\n"
    {
        return Err(invalid("движок отклонил настройки WireGuard/AWG"));
    }
    Ok(())
}
fn socket_path(root: &Path, iface: &str) -> PathBuf {
    root.join("var/run/amneziawg").join(format!("{iface}.sock"))
}

fn terminate_receipt(root: &Path, socket: &Path, r: &receipt::Receipt) -> io::Result<()> {
    let confirmed = || {
        if receipt::read(socket)?.as_ref() != Some(r) {
            return Err(invalid("заменена запись владения клиентом"));
        }
        Ok(())
    };
    confirmed()?;
    if !r.vacant(root, socket)? {
        let target = super::legacy::SignalTarget::open(r.pid as i32)?;
        r.verify(root, socket)?;
        confirmed()?;
        target.terminate()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !r.vacant(root, socket)? {
            if Instant::now() >= deadline {
                return Err(invalid("движок ещё не освободил интерфейс"));
            }
            thread::sleep(Duration::from_millis(40));
        }
    }
    Ok(())
}

pub(super) fn retire_sealed(runtime: &Runtime, seal: &NativeRemovalSeal) -> io::Result<()> {
    let socket = socket_path(&runtime.root, &seal.iface);
    let Some(record) = receipt::read(&socket)? else {
        if runtime.present(&seal.iface)? {
            return Err(invalid("интерфейс управляется другим процессом"));
        }
        if let Some(scope) = &seal.nested {
            if runtime.root != Path::new("/") {
                return Err(invalid(
                    "маршруты вложенного AWG доступны только в рабочей системе роутера",
                ));
            }
            fs::create_dir_all(socket.parent().ok_or_else(|| invalid("нет каталога AWG"))?)?;
            let _marker = lock_marker(&socket.with_extension("n2s-owner"))?;
            if receipt::read(&socket)?.is_some()
                || runtime.present(&seal.iface)?
                || !matches!(fs::symlink_metadata(&socket), Err(e) if e.kind() == io::ErrorKind::NotFound)
            {
                return Err(invalid("интерфейс управляется другим процессом"));
            }
            NestedTransport::vacant_retirement(&socket, &seal.iface, scope)?;
        }
        return Ok(());
    };
    if runtime.root != Path::new("/") || record.removal_seal()? != *seal {
        return Err(invalid("личность удаляемого AWG не подтверждена"));
    }
    let _marker = lock_marker(&socket.with_extension("n2s-owner"))?;
    let nested = record
        .nested
        .as_ref()
        .map(|saved| {
            NestedTransport::prepare_saved_retirement(
                &socket,
                &seal.iface,
                saved,
                record.same_boot(&runtime.root)?,
            )
        })
        .transpose()?;
    terminate_receipt(&runtime.root, &socket, &record)?;
    if let Some(nested) = nested {
        nested.release()?;
    }
    record.remove_stale_socket(&socket)?;
    record.remove(&socket)
}

pub(super) fn has_receipt(root: &Path, iface: &str, id: &str) -> io::Result<bool> {
    Ok(receipt::read(&socket_path(root, iface))?.is_some_and(|r| r.id == id))
}

pub(super) fn retire_vacant_plain_delete(
    runtime: &Runtime,
    doc: &serde_json::Value,
    row: &serde_json::Value,
    iface: &str,
) -> io::Result<()> {
    let socket = socket_path(&runtime.root, iface);
    if let Some(receipt) = receipt::read(&socket)? {
        let spec = Runtime::spec_for_release(doc, row)?;
        if !receipt.matches_spec(&spec) {
            return Err(invalid("запись удаляемого клиента AWG изменилась"));
        }
        retire_sealed(runtime, &receipt.removal_seal()?)?;
    }
    ensure_plain_delete_scope_vacant(runtime, iface)
}

pub(super) fn ensure_plain_delete_scope_vacant(runtime: &Runtime, iface: &str) -> io::Result<()> {
    let socket = socket_path(&runtime.root, iface);
    for ext in ["n2s-native.json", "n2s-nested.json", "double-tunnel.json"] {
        match fs::symlink_metadata(socket.with_extension(ext)) {
            Ok(_) => return Err(invalid("не завершена очистка маршрутов удаляемого AWG")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn owns_nested_socket(
    root: &Path,
    spec: &Spec,
    outer: &NestedOuter,
    endpoint: SocketAddr,
    deadline: Instant,
) -> io::Result<bool> {
    let socket = socket_path(root, &spec.iface);
    let Some(record) = receipt::read(&socket)? else {
        return Ok(false);
    };
    let Some(nested) = &record.nested else {
        return Ok(false);
    };
    if !record.matches_spec(spec)
        || !nested.owns_socket_routes(&socket, outer, &spec.iface, endpoint.ip())?
    {
        return Ok(false);
    }
    record.owner(root, &socket)?;
    let budget = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(io::ErrorKind::TimedOut)?
        .min(Duration::from_millis(200));
    let bytes = request(&socket, b"get=1\n\n", budget, Some(record.pid))?;
    if !record.matches_keys(&bytes) {
        return Ok(false);
    }
    let mut status = serde_json::json!({});
    crate::runtime::uapi(&bytes, crate::now(), &mut status)?;
    let (mark, _) = super::nested_socket_selector(&spec.iface)?;
    if status["socket_mark"] != mark
        || crate::s(&status, "endpoint")
            .parse()
            .ok()
            .and_then(super::supervisor::canonical_transport)
            != Some(endpoint)
    {
        return Ok(false);
    }
    record.owner(root, &socket)?;
    Ok(receipt::read(&socket)?.as_ref() == Some(&record)
        && nested.owns_socket_routes(&socket, outer, &spec.iface, endpoint.ip())?)
}

pub(super) fn owned_interfaces(root: &Path) -> io::Result<Vec<(String, String)>> {
    let dir = root.join("var/run/amneziawg");
    let entries = match fs::read_dir(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        result => result?,
    };
    let mut claims = vec![];
    for entry in entries {
        let name = entry?.file_name();
        let Some(iface) = name
            .to_str()
            .and_then(|s| s.strip_suffix(".n2s-native.json"))
        else {
            continue;
        };
        if let Some(r) = receipt::read(&socket_path(root, iface))? {
            claims.push((r.id, iface.to_owned()));
        }
    }
    Ok(claims)
}
pub(super) fn resume(runtime: &Runtime, spec: &Spec) -> io::Result<Option<Box<dyn Tunnel>>> {
    Ok(resume_after_edit(runtime, spec, None)?.map(|managed| managed.tunnel))
}
pub(super) fn resume_after_edit(
    runtime: &Runtime,
    spec: &Spec,
    previous: Option<[u8; 32]>,
) -> io::Result<Option<Managed>> {
    let socket = socket_path(&runtime.root, &spec.iface);
    let Some(seen) = receipt::read(&socket)? else {
        return Ok(None);
    };
    let marker = lock_marker(&socket.with_extension("n2s-owner"))?;
    if receipt::read(&socket)?.as_ref() != Some(&seen) {
        return Err(invalid("запись клиента изменилась во время восстановления"));
    }
    // Stale proofs may only be discarded after verifying the interface is vacant.
    if seen.vacant(&runtime.root, &socket)? {
        if let Some(saved) = &seen.nested {
            if runtime.root != Path::new("/") {
                return Err(invalid(
                    "маршруты вложенного AWG доступны только в рабочей системе роутера",
                ));
            }
            NestedTransport::retire_saved(
                &socket,
                &spec.iface,
                saved,
                seen.same_boot(&runtime.root)?,
            )?;
            seen.remove_stale_socket(&socket)?;
        } else {
            seen.remove_stale_socket(&socket)?;
            NestedTransport::recover(&socket, &spec.iface)?;
        }
        seen.remove(&socket)?;
        return Ok(None);
    }
    let fingerprint = if seen.matches_spec(spec) {
        seen.verify(&runtime.root, &socket)?;
        Sha256::digest(spec.conf.as_bytes()).into()
    } else if let Some(previous) = previous.filter(|hash| seen.matches_config(spec, *hash)) {
        // A pending profile replacement may inherit only the proved daemon it
        // superseded. The unchanged client keys must also match the new spec.
        seen.verify_for_spec(&runtime.root, &socket, spec)?;
        previous
    } else {
        return Err(invalid("профиль сохранённого AWG-процесса изменился"));
    };
    let key = spec
        .conf
        .lines()
        .find_map(|l| l.strip_prefix("PublicKey = "))
        .ok_or_else(|| invalid("нет ключа пира"))?;
    let peer_hex = conf::key(key, false)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let interval = spec
        .conf
        .lines()
        .find_map(|l| l.strip_prefix("PersistentKeepalive = "))
        .unwrap_or("0")
        .to_string();
    let nested = seen
        .nested
        .clone()
        .map(|n| NestedTransport::resume(&socket, &spec.iface, n))
        .transpose()?;
    let owner = Owner {
        root: runtime.root.clone(),
        tx_packets: runtime
            .root
            .join("sys/class/net")
            .join(&spec.iface)
            .join("statistics/tx_packets"),
        pid: seen.pid,
        peer_hex,
        interval,
        proof: Some(seen),
        resumed: true,
        temporary: None,
        marker: Some(marker),
        socket,
        nested,
    };
    Ok(Some(Managed {
        tunnel: Box::new(owner),
        iface: spec.iface.clone(),
        fingerprint,
        recovery: Default::default(),
    }))
}
pub(super) fn start(
    runtime: &Runtime,
    spec: Spec,
    wan: &[String],
    temporary: bool,
    require_direct_mark: bool,
    transport: Option<supervisor::TransportPreparation<'_>>,
) -> io::Result<Box<dyn Tunnel>> {
    if runtime.root != Path::new("/") {
        return Err(invalid(
            "клиент AWG доступен только в рабочей системе роутера",
        ));
    }
    let engine = runtime.engine();
    if engine["installed"] != true || engine["tun_ok"] != true {
        return Err(invalid(
            "требуются установленный amneziawg-go и /dev/net/tun",
        ));
    }
    let cfg = conf::parse(&spec.conf, 0)?;
    if cfg["protocol_version"] == "3.1" && engine["awg3_supported"] != true {
        return Err(invalid("этому профилю требуется движок AWG 3.1"));
    }
    let endpoint = resolve_endpoint(&spec.endpoint)?;
    let socket = Path::new("/var/run/amneziawg").join(format!("{}.sock", spec.iface));
    let addresses: Vec<String> = super::s(&cfg["peers"][0], "address")
        .split(',')
        .map(|s| s.trim().to_owned())
        .collect();
    if addresses.len() > 32 {
        return Err(invalid("слишком много локальных адресов для интерфейса"));
    }
    supervisor::prepare_transport(transport, endpoint)?;
    let direct_mark = if spec.outer.is_none() {
        let normal_mark = direct_socket_mark(endpoint.ip(), wan)?;
        if require_direct_mark {
            if !temporary
                || !endpoint.is_ipv6()
                || !runtime.verifies_live_wan_path(endpoint, crate::DIRECT_SOCKET_MARK, wan, true)
            {
                return Err(invalid("не подтверждён маркированный IPv6-транспорт AWG"));
            }
            Some(crate::DIRECT_SOCKET_MARK)
        } else {
            normal_mark
        }
    } else if require_direct_mark {
        return Err(invalid("не подтверждён прямой IPv6-транспорт AWG"));
    } else {
        None
    };
    check_path(endpoint, &addresses)?;
    fs::create_dir_all("/var/run/amneziawg")?;
    let marker = lock_interface(&socket, &spec.iface)?;
    NestedTransport::recover(&socket, &spec.iface)?;
    let mut message = uapi_message(&spec.conf, endpoint)?;
    let field = |name: &str| {
        message
            .lines()
            .find_map(|s| s.strip_prefix(name))
            .map(str::to_owned)
            .ok_or_else(|| invalid("неполная конфигурация UAPI"))
    };
    let peer_hex = field("public_key=")?;
    let interval = field("persistent_keepalive_interval=")?;
    let tx_packets = Path::new("/sys/class/net")
        .join(&spec.iface)
        .join("statistics/tx_packets");
    let nested = spec
        .outer
        .clone()
        .map(|outer| NestedTransport::prepare(&socket, &spec.iface, outer, endpoint.ip(), &cfg))
        .transpose()?;
    let mut mtu = cfg["mtu"].as_u64().unwrap_or(1420);
    if let Some(n) = &nested {
        // The socket mark precedes every peer stanza, including the first keepalive.
        message.insert_str("set=1\n".len(), &format!("fwmark={}\n", n.routes.mark()?));
        mtu = n.mtu;
    } else if let Some(mark) = direct_mark {
        message.insert_str("set=1\n".len(), &format!("fwmark={mark}\n"));
    }
    let mut marker = marker;
    // The launcher terminates an unclaimed engine on panel death. Publish the
    // boot-scoped proof before allowing the engine to outlive its launcher.
    let started = (|| {
        let mut launch = launcher::spawn(&runtime.engine, &spec.iface)?;
        configure(
            &mut launch,
            &socket,
            &spec.iface,
            &addresses,
            mtu,
            &message,
            &mut marker,
        )?;
        let r = receipt::Receipt::capture(
            runtime,
            &spec,
            launch.pid(),
            &socket,
            nested.as_ref().map(NestedTransport::snapshot),
        )?;
        r.persist(&socket)?;
        let lease = if temporary {
            Some(launch)
        } else {
            launch.commit()?;
            None
        };
        Ok::<_, io::Error>((r, lease))
    })();
    let (proof, temporary) = match started {
        Ok(r) => r,
        Err(error) => {
            // A failed acknowledgement can follow detach. Preserve nested
            // guards if the engine still holds an interface.
            if !Path::new("/sys/class/net").join(&spec.iface).try_exists()? {
                if let Some(n) = nested {
                    n.release()?;
                }
            }
            return Err(error);
        }
    };
    let mut owner = Owner {
        root: runtime.root.clone(),
        pid: proof.pid,
        socket,
        tx_packets,
        peer_hex,
        interval,
        proof: Some(proof),
        resumed: false,
        temporary,
        marker: Some(marker),
        nested,
    };
    if owner.nested.is_some() {
        owner.repair_nested()?;
    }
    if owner.interval == "0" {
        owner.probe()?;
    }
    Ok(Box::new(owner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Seek, Write},
        os::unix::net::UnixListener,
    };
    #[test]
    #[ignore = "requires isolated Linux guest with no NIC and the synthetic UAPI worker"]
    fn confirmed_go_full_primary_checks_actual_linux_tun_receipt_and_peer() {
        assert!(Path::new("/synthetic-guest").is_file());
        for (kind, variable) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
            let parent = std::env::var(variable).unwrap();
            let current = fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
            assert!(parent.starts_with(&format!("{kind}:[")));
            assert_ne!(current.to_str(), Some(parent.as_str()));
        }
        let ip = |args: &[&str]| {
            let result = std::process::Command::new("ip")
                .args(args)
                .status()
                .unwrap();
            assert!(result.success());
        };
        ip(&["tuntap", "add", "dev", "awg0", "mode", "tun"]);
        ip(&["link", "set", "dev", "awg0", "mtu", "1420", "up"]);
        let temp = tempfile::tempdir().unwrap();
        let db = nfqws2_store::Store::open(temp.path().join("data")).unwrap();
        let cfg = crate::tests::input().replace("[2001:db8::1]:51820", "192.0.2.44:443");
        crate::import(&db, &cfg, "synthetic owned tunnel").unwrap();
        crate::edit_document(&db, |doc| {
            let row = doc["servers"].as_array_mut().unwrap().last_mut().unwrap();
            let cfg = &mut row["config"];
            cfg["enabled"] = true.into();
            cfg["client"]["enabled"] = true.into();
            cfg["client"]["rust_managed"] = true.into();
            cfg["client_iface"] = "awg0".into();
            cfg["routing"] = serde_json::json!({"mode":"full","active":true});
            Ok(())
        })
        .unwrap();
        let doc = crate::read(&db).unwrap();
        let row = doc["servers"].as_array().unwrap().last().unwrap();
        let spec = crate::client::enabled_spec_for_release(&doc, row).unwrap();
        let endpoint = spec.endpoint.parse().unwrap();
        let command = crate::client::uapi_message(&spec.conf, endpoint).unwrap();
        let keys: Vec<_> = command
            .lines()
            .filter(|line| line.starts_with("private_key=") || line.starts_with("public_key="))
            .collect();
        assert_eq!(keys.len(), 2);
        let write_reply = |handshake, address: &str, grant: &str, peer: &str| {
            fs::write(
                temp.path().join("reply"),
                format!("{}\nfwmark=0\n{peer}\nendpoint={address}\nallowed_ip={grant}\nlast_handshake_time_sec={handshake}\nerrno=0\n\n", keys[0]),
            ).unwrap();
        };
        write_reply(1, &spec.endpoint, "0.0.0.0/0", keys[1]);
        let socket = temp.path().join("awg0.sock");
        let engine = PathBuf::from(std::env::var_os("N2S_R104_UAPI_WORKER").unwrap());
        let runtime = Runtime::new(Path::new("/"), engine.clone());
        let mut child = std::process::Command::new(engine)
            .args(["-f", "awg0"])
            .env("N2S_R104_SOCKET", &socket)
            .env("N2S_R104_REPLY", temp.path().join("reply"))
            .spawn()
            .unwrap();
        for _ in 0..80 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let proof = receipt::Receipt::capture(&runtime, &spec, child.id(), &socket, None).unwrap();
        proof.persist(&socket).unwrap();
        let owner = Owner {
            root: "/".into(),
            pid: child.id(),
            tx_packets: "/sys/class/net/awg0/statistics/tx_packets".into(),
            peer_hex: keys[1].trim_start_matches("public_key=").into(),
            interval: "0".into(),
            socket,
            proof: Some(proof),
            resumed: false,
            temporary: None,
            marker: None,
            nested: None,
        };
        assert!(owner
            .active_replacement_peer(&spec, &row["config"], false, None)
            .is_err());
        let id = spec.id.clone();
        runtime.clients.0.lock().unwrap().insert(
            id.clone(),
            crate::client::Managed {
                fingerprint: Sha256::digest(spec.conf.as_bytes()).into(),
                iface: spec.iface.clone(),
                tunnel: Box::new(owner),
                recovery: Default::default(),
            },
        );
        let checked = runtime.routing_go_full_primary(&db, &id).unwrap().unwrap();
        assert_eq!(checked.endpoint, endpoint);
        assert_eq!(checked.mtu, 1420);
        assert_eq!(checked.allowed, ["0.0.0.0/0"]);
        write_reply(crate::now(), &spec.endpoint, "0.0.0.0/0", keys[1]);
        assert!(runtime.routing_go_full_primary(&db, &id).unwrap().is_some());
        write_reply(1, &spec.endpoint, "203.0.113.0/24", keys[1]);
        assert!(runtime.routing_go_full_primary(&db, &id).is_err());
        write_reply(1, "192.0.2.70:443", "0.0.0.0/0", keys[1]);
        assert!(runtime.routing_go_full_primary(&db, &id).is_err());
        write_reply(
            1,
            &spec.endpoint,
            "0.0.0.0/0",
            &format!("public_key={}", "32".repeat(32)),
        );
        assert!(runtime.routing_go_full_primary(&db, &id).is_err());
        write_reply(1, &spec.endpoint, "0.0.0.0/0", keys[1]);
        ip(&["link", "set", "dev", "awg0", "down"]);
        assert!(runtime.routing_go_full_primary(&db, &id).is_err());
        ip(&["link", "set", "dev", "awg0", "up"]);
        ip(&["tuntap", "del", "dev", "awg0", "mode", "tun"]);
        ip(&["link", "add", "awg0", "type", "dummy"]);
        assert!(runtime.routing_go_full_primary(&db, &id).is_err());
        ip(&["link", "del", "awg0"]);
        let _ = child.kill();
        child.wait().unwrap();
        assert!(runtime.routing_go_full_primary(&db, &id).is_err());
    }
    #[test]
    fn owned_peer_reads_tun_demand_and_restores_keepalive_in_one_request() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("peer.sock");
        let tx_packets = dir.path().join("tx_packets");
        fs::write(&tx_packets, "125\n").unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let worker = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut request = String::new();
            client.read_to_string(&mut request).unwrap();
            assert_eq!(request, "get=1\n\n");
            client.write_all(b"public_key=test-peer\nendpoint=192.0.2.1:1000\nlast_handshake_time_sec=100\nrx_bytes=10\ntx_bytes=20\nerrno=0\n\n").unwrap();
            drop(client);
            for interval in ["0", "30"] {
                let (mut client, _) = listener.accept().unwrap();
                request.clear();
                client.read_to_string(&mut request).unwrap();
                let header = "public_key=test-peer\nupdate_only=true\n";
                let mut expected = format!("set=1\n{header}persistent_keepalive_interval=0\n");
                if interval == "0" {
                    expected.push_str("persistent_keepalive_interval=25\n");
                    expected.push_str(header);
                    expected.push_str("persistent_keepalive_interval=0\n\n");
                } else {
                    expected.push_str("persistent_keepalive_interval=30\n\n");
                }
                assert_eq!(request, expected);
                client.write_all(b"errno=0\n\n").unwrap();
            }
        });
        let mut owner = Owner {
            socket,
            tx_packets,
            pid: std::process::id(),
            peer_hex: "test-peer".into(),
            interval: "0".into(),
            root: dir.path().to_owned(),
            proof: None,
            resumed: false,
            temporary: None,
            nested: None,
            marker: None,
        };
        assert_eq!(owner.snapshot().unwrap()["tun_tx_packets"], 125);
        owner.probe().unwrap();
        owner.interval = "30".into();
        owner.probe().unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn exclusive_owner_recovers_only_its_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("fixture.sock");
        let unavailable_iface = "n2s-missing-iface-test";
        let mut marker = lock_interface(&socket, unavailable_iface).unwrap();
        assert!(lock_interface(&socket, unavailable_iface).is_err());
        let listener = UnixListener::bind(&socket).unwrap();
        let token = identity(&socket).unwrap();
        marker.rewind().unwrap();
        marker.write_all(token.as_bytes()).unwrap();
        drop(marker);
        assert!(lock_interface(&socket, unavailable_iface).is_err());
        assert!(socket.exists());
        drop(listener);
        drop(lock_interface(&socket, unavailable_iface).unwrap());
        assert!(!socket.exists());
        fs::write(&socket, b"foreign").unwrap();
        assert!(lock_interface(&socket, unavailable_iface).is_err());
        assert_eq!(fs::read(&socket).unwrap(), b"foreign");
    }
}
