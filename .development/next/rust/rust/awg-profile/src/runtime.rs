use serde_json::{json, Value};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime},
};

#[cfg(any(test, target_os = "linux"))]
mod ipv6;

pub(crate) const TARGET: &str = "v3.1.20260828";
pub(crate) const REV: &str = "b5928efb6ca19f0153958460c3d141f04abc5c2e";
const MAGIC: &[u8] = b"\xff Go buildinf:";
fn string(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut n = 0usize;
    for i in 0..4 {
        let mut b = [0];
        r.read_exact(&mut b)?;
        n |= usize::from(b[0] & 127) << (7 * i);
        if n > max {
            return Err(io::Error::other("oversized Go build info"));
        }
        if b[0] < 128 {
            let mut buf = vec![0; n];
            r.read_exact(&mut buf)?;
            return Ok(buf);
        }
    }
    Err(io::Error::other("invalid Go build info"))
}
fn go_build_info(path: &Path) -> io::Result<(String, String)> {
    let mut file = File::open(path)?;
    let mut off = 0u64;
    let mut chunk = vec![0; 32768];
    loop {
        let n = file.read(&mut chunk)?;
        if n < 32 {
            break;
        }
        for i in (0..=n - 32).step_by(16) {
            if chunk[i..].starts_with(MAGIC)
                && matches!(chunk[i + 14], 4 | 8)
                && chunk[i + 15] & 2 != 0
            {
                file.seek(SeekFrom::Start(off + i as u64 + 32))?;
                if let Ok(ver) = string(&mut file, 128) {
                    if ver.starts_with(b"go1.") {
                        let v = string(&mut file, 1 << 20)?;
                        if v.len() >= 32 {
                            return Ok((
                                String::from_utf8_lossy(&ver).into_owned(),
                                String::from_utf8_lossy(&v[16..v.len() - 16]).into_owned(),
                            ));
                        }
                    }
                }
            }
        }
        if n < chunk.len() {
            break;
        }
        off += n as u64 - 32;
        file.seek(SeekFrom::Start(off))?;
    }
    Err(io::Error::other("не удалось прочитать Go build info"))
}
fn release(s: &str) -> Option<semver::Version> {
    let s = s.trim_start_matches("go").trim_start_matches('v');
    let s = if s.split('.').count() == 2 {
        format!("{s}.0")
    } else {
        s.into()
    };
    semver::Version::parse(&s).ok()
}
fn inspect(ver: &str, mods: &str) -> Value {
    let mut path = "";
    let mut version = "";
    let mut rev = "";
    let mut mem = false;
    let mut deps = std::collections::BTreeMap::new();
    let mut last_dep = None;
    for l in mods.lines() {
        let mut w = l.split('\t');
        match w.next() {
            Some("mod") => {
                path = w.next().unwrap_or_default();
                version = w.next().unwrap_or_default();
                last_dep = None;
            }
            Some("dep") => {
                let name = w.next().unwrap_or_default();
                deps.insert(name, w.next().unwrap_or_default());
                last_dep = Some(name);
            }
            Some("=>") => {
                if let Some(orig) = last_dep.take() {
                    let name = w.next().unwrap_or_default();
                    deps.insert(
                        orig,
                        if name == orig {
                            w.next().unwrap_or_default()
                        } else {
                            ""
                        },
                    );
                }
            }
            Some("build") => {
                let setting = w.next().unwrap_or_default();
                if let Some(v) = setting.strip_prefix("vcs.revision=") {
                    rev = v;
                }
                if let Some(tags) = setting.strip_prefix("-tags=") {
                    mem = tags
                        .trim_matches('"')
                        .split(|c: char| c == ',' || c.is_whitespace())
                        .any(|s| s == "n2s_router_memory_v1");
                }
            }
            _ => (),
        }
    }
    let is_v3 = path == "github.com/amnezia-vpn/amneziawg-go/v3"
        && (rev == REV || release(version).is_some_and(|v| v >= semver::Version::new(3, 1, 0)));
    if matches!(version, "" | "(devel)") && rev == REV {
        version = TARGET;
    }
    let current_go = release(ver)
        .is_some_and(|v| v >= semver::Version::new(1, 26, 11) && (v.minor != 27 || v.patch >= 4));
    let current_deps = [
        ("golang.org/x/crypto", 57),
        ("golang.org/x/net", 59),
        ("golang.org/x/sys", 48),
    ]
    .iter()
    .all(|(name, min)| {
        deps.get(name)
            .and_then(|v| release(v))
            .is_some_and(|v| v >= semver::Version::new(0, *min, 0))
    });
    json!({"installed":true,"awg_version":version,"awg3_supported":is_v3,"target_version":TARGET,"update_available":!(is_v3&&mem&&current_go&&current_deps)})
}
type EngineCache = Option<(u64, Option<SystemTime>, Value)>;
pub struct Runtime {
    #[cfg(target_os = "linux")]
    ipv6_probe: ipv6::Cache,
    pub(crate) deployment: Mutex<()>,
    pub(crate) deploy_history: super::deploy::history::History,
    route_inspector: std::sync::OnceLock<RouteInspector>,
    route_cache: Mutex<Option<(std::time::Instant, u64, Value)>>,
    pub(crate) remote: super::remote::State,
    pub(crate) root: PathBuf,
    pub(crate) engine: PathBuf,
    pub(crate) clients: super::client::Clients,
    pub(crate) dashboard_cache: Mutex<super::view::DashboardCache>,
    cache: Mutex<EngineCache>,
}
pub type RouteInspector = fn(&nfqws2_store::Store) -> io::Result<Value>;
impl Runtime {
    pub fn new(root: &Path, engine: PathBuf) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            ipv6_probe: Default::default(),
            deployment: Mutex::new(()),
            deploy_history: Default::default(),
            route_inspector: Default::default(),
            route_cache: Default::default(),
            remote: Default::default(),
            root: root.into(),
            engine,
            clients: Default::default(),
            dashboard_cache: Default::default(),
            cache: Mutex::new(None),
        }
    }
    pub fn register_routing(&self, read: RouteInspector) {
        let _ = self.route_inspector.set(read);
    }
    pub fn invalidate_routing(&self) {
        self.route_cache.lock().unwrap().take();
    }
    pub(crate) fn routing(&self, db: &nfqws2_store::Store, revision: u64) -> Option<Value> {
        let read = self.route_inspector.get()?;
        let mut cache = self.route_cache.lock().unwrap();
        if let Some((_, _, v)) = cache
            .as_ref()
            .filter(|(t, r, _)| *r == revision && t.elapsed() < Duration::from_secs(3))
        {
            return Some(v.clone());
        }
        let v = read(db)
            .unwrap_or_else(|e| json!({"active":false,"ready":false,"error":e.to_string()}));
        *cache = Some((std::time::Instant::now(), revision, v.clone()));
        Some(v)
    }
    pub fn routing_peer(
        &self,
        config: &Value,
        iface: &str,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>)> {
        self.routing_peer_with_budget(config, iface, Duration::from_secs(1))
    }
    /// Only routing policy needs to check public IPv6 reachability. Dashboard
    /// and DNS inventory reads keep their existing latency budget.
    pub fn routing_policy_peer(
        &self,
        config: &Value,
        iface: &str,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>, u32, bool)> {
        let peer = self.marked_routing_peer(config, iface, Duration::from_secs(1))?;
        #[cfg(target_os = "linux")]
        {
            let (endpoint, mut allowed, mark) = peer;
            let reachable = self.routing_policy_ipv6(config, iface, endpoint, &mut allowed);
            Ok((endpoint, allowed, mark, reachable))
        }
        #[cfg(not(target_os = "linux"))]
        Ok((peer.0, peer.1, peer.2, false))
    }

    pub fn routing_policy_ipv6(
        &self,
        config: &Value,
        iface: &str,
        endpoint: std::net::SocketAddr,
        allowed: &mut Vec<String>,
    ) -> bool {
        #[cfg(target_os = "linux")]
        {
            let reach = if allowed.iter().any(|cidr| cidr == "::/0") {
                self.ipv6_probe
                    .reach(iface, super::s(config, "public_key"), endpoint)
            } else {
                ipv6::Reach::Split
            };
            if reach == ipv6::Reach::Offline
                && config["client"]["double_tunnel_mode"] != "permanent"
            {
                allowed.retain(|cidr| !cidr.contains(':'));
            }
            reach == ipv6::Reach::Online
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, iface, endpoint, allowed);
            false
        }
    }

    /// Sample the exact peer on a kernel-verified device-bound probe path.
    /// Retain its raw grants while reporting whether TCP was actually tried.
    pub fn routing_policy_peer_with_fresh_ipv6_probe(
        &self,
        config: &Value,
        iface: &str,
        expected: std::net::SocketAddr,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>, u32, Option<bool>)> {
        let (endpoint, allowed, mark) =
            self.marked_routing_peer_inner(config, iface, Duration::from_secs(1), false, false)?;
        #[cfg(target_os = "linux")]
        let fresh = if self.root == Path::new("/")
            && endpoint == expected
            && matches!(mark, 0 | crate::DIRECT_SOCKET_MARK)
            && allowed.iter().any(|net| net == "::/0")
            && self.has_usable_ipv6(iface)
        {
            self.ipv6_probe
                .fresh_bound(iface, super::s(config, "public_key"), endpoint)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let fresh = {
            let _ = expected;
            None
        };
        Ok((endpoint, allowed, mark, fresh))
    }
    /// A still-running Go panel owns packet handling. Snapshot its authenticated
    /// UAPI peer and socket mark without originating a connectivity check.
    pub fn handoff_peer(
        &self,
        config: &Value,
        iface: &str,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>, u32)> {
        self.marked_routing_peer_inner(config, iface, Duration::from_secs(1), true, true)
    }
    pub(crate) fn routing_peer_with_budget(
        &self,
        config: &Value,
        iface: &str,
        budget: Duration,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>)> {
        self.marked_routing_peer(config, iface, budget)
            .map(|(ep, allowed, _)| (ep, allowed))
    }
    fn marked_routing_peer(
        &self,
        config: &Value,
        iface: &str,
        budget: Duration,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>, u32)> {
        self.marked_routing_peer_inner(config, iface, budget, true, false)
    }

    fn marked_routing_peer_inner(
        &self,
        config: &Value,
        iface: &str,
        budget: Duration,
        require_ipv6_address: bool,
        go_handoff: bool,
    ) -> io::Result<(std::net::SocketAddr, Vec<String>, u32)> {
        #[cfg(target_os = "linux")]
        {
            if !iface.strip_prefix("awg").is_some_and(|n| {
                !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && iface.len() < 16
            }) {
                return Err(io::Error::other("неверный интерфейс AWG"));
            }
            let flags = std::fs::read_to_string(
                self.root
                    .join("sys/class/net")
                    .join(iface)
                    .join("tun_flags"),
            )?;
            if !u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
                .is_ok_and(|f| f & 3 == 1)
            {
                return Err(io::Error::other("интерфейс не является TUN"));
            }
            let socket = self
                .root
                .join("var/run/amneziawg")
                .join(format!("{iface}.sock"));
            let buf = query(&socket, budget)?;
            let now = super::now();
            let mut mark = 0;
            let (endpoint, mut allowed) = routing_peer(&buf, config, now, |v| {
                mark = v["socket_mark"].as_u64().unwrap_or_default() as u32;
                if !go_handoff {
                    self.supplement_activity(iface, v, now, &buf);
                }
            })?;
            if require_ipv6_address
                && allowed.iter().any(|net| net.contains(':'))
                && !self.has_usable_ipv6(iface)
            {
                allowed.retain(|net| !net.contains(':'));
            }
            Ok((endpoint, allowed, mark))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, iface, budget, require_ipv6_address, go_handoff);
            Err(io::Error::other(
                "применение маршрутов доступно на Linux-роутере",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn has_usable_ipv6(&self, iface: &str) -> bool {
        File::open(self.root.join("proc/net/if_inet6"))
            .is_ok_and(|file| usable_ipv6(std::io::BufReader::new(file.take(128 << 10)), iface))
    }
    pub fn engine_path(&self) -> &Path {
        &self.engine
    }
    pub fn engine(&self) -> Value {
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            "mips" if cfg!(target_endian = "little") => "mipsle",
            a => a,
        };
        if !cfg!(target_os = "linux") {
            return json!({"installed":false,"arch":arch,"supported":false,"tun_ok":false,"error":"клиент AWG2 поддерживается только на роутере (Linux)","awg_version":"","awg3_supported":false,"update_available":false,"target_version":""});
        }
        let mut info = json!({"installed":false,"target_version":TARGET,"awg_version":"","awg3_supported":false,"update_available":false});
        if let Ok(meta) = self.engine.metadata() {
            let key = (meta.len(), meta.modified().ok());
            let mut cache = self.cache.lock().unwrap();
            if let Some((_, _, saved)) =
                cache.as_ref().filter(|(len, time, _)| (*len, *time) == key)
            {
                info = saved.clone();
            } else {
                info=go_build_info(&self.engine).map(|(v,m)|inspect(&v,&m)).unwrap_or_else(|e|json!({"installed":true,"target_version":TARGET,"error":e.to_string(),"awg_version":"","awg3_supported":false,"update_available":true}));
                *cache = Some((key.0, key.1, info.clone()));
            }
        }
        info["arch"] = json!(arch);
        info["supported"] = json!(matches!(arch, "arm64" | "arm" | "mips" | "mipsle"));
        info["tun_ok"] = json!(self.root.join("dev/net/tun").exists());
        info
    }
    pub fn client(&self, cfg: &Value, iface: &str, budget: Duration) -> Value {
        self.client_observation(cfg, iface, budget).0
    }
    pub(crate) fn client_observation(
        &self,
        cfg: &Value,
        iface: &str,
        budget: Duration,
    ) -> (Value, bool) {
        let address = super::view::router_address(cfg);
        self.client_detail(cfg["mtu"].as_u64().unwrap_or(1420), address, iface, budget)
    }
    pub(crate) fn client_detail(
        &self,
        mtu: u64,
        address: &str,
        iface: &str,
        budget: Duration,
    ) -> (Value, bool) {
        if !cfg!(target_os = "linux") {
            return (Value::Null, false);
        }
        let valid = iface.strip_prefix("awg").is_some_and(|n| {
            !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && iface.len() < 16
        });
        let mut v = json!({"iface_present":false,"running":false,"connected":false,"last_handshake":0,"rx_bytes":0,"tx_bytes":0,"endpoint":"","endpoint_index":0,
            "address":address,"mtu":mtu,"recovering":false,"retry_count":0,"retry_at":0});
        if !valid {
            v["status_unavailable"] = json!(true);
            v["error"] = json!("неверное имя интерфейса");
            return (v, false);
        }
        v["iface_present"] = json!(self.root.join("sys/class/net").join(iface).exists());
        let socket = self
            .root
            .join("var/run/amneziawg")
            .join(format!("{iface}.sock"));
        if !socket.exists() {
            return (v, false);
        }
        #[cfg(unix)]
        let endpoint_verified = {
            let r = query(&socket, budget).and_then(|buf| {
                let now = super::now();
                uapi(&buf, now, &mut v)?;
                Ok(self.supplement_activity(iface, &mut v, now, &buf))
            });
            match r {
                Ok(verified) => verified,
                Err(e) => {
                    v["status_unavailable"] = json!(true);
                    v["error"] = json!(e.to_string());
                    false
                }
            }
        };
        #[cfg(not(unix))]
        let endpoint_verified = {
            let _ = budget;
            false
        };
        (v, endpoint_verified)
    }
}
#[cfg(any(target_os = "linux", test))]
fn usable_ipv6(mut input: impl std::io::BufRead, iface: &str) -> bool {
    let mut line = String::new();
    loop {
        line.clear();
        if !matches!(input.read_line(&mut line), Ok(n) if n > 0) {
            return false;
        }
        let mut parts = line.split_ascii_whitespace();
        let Some(address) = parts.next() else {
            continue;
        };
        let scope = parts.nth(2);
        let flags = parts.next().and_then(|f| u32::from_str_radix(f, 16).ok());
        // if_inet6 scope 00 includes GUA and ULA. Tentative and failed-DAD
        // addresses cannot supply the IPv6 source for tunnel masquerading.
        if parts.next() == Some(iface)
            && scope == Some("00")
            && flags.is_some_and(|f| f & (0x40 | 0x08) == 0)
            && address.len() == 32
            && u128::from_str_radix(address, 16).is_ok_and(|n| n > 1)
        {
            return true;
        }
    }
}
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn routing_peer(
    buf: &[u8],
    config: &Value,
    now: u64,
    activity: impl FnOnce(&mut Value),
) -> io::Result<(std::net::SocketAddr, Vec<String>)> {
    routing_peer_sample(buf, config, now, true, activity)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn routing_peer_sample(
    buf: &[u8],
    config: &Value,
    now: u64,
    require_handshake: bool,
    activity: impl FnOnce(&mut Value),
) -> io::Result<(std::net::SocketAddr, Vec<String>)> {
    use std::fmt::Write;
    let mut status = json!({});
    uapi(buf, now, &mut status)?;
    activity(&mut status);
    if config["client"]["double_tunnel_mode"] == "permanent" && status["nested_transport"] != true {
        return Err(io::Error::other(
            "постоянный двойной туннель ещё не подтверждён",
        ));
    }
    if require_handshake && status["connected"] != true {
        return Err(io::Error::other("у пира нет свежего рукопожатия"));
    }
    let mut key = String::with_capacity(64);
    for b in super::conf::key(super::s(config, "public_key"), false)? {
        write!(key, "{b:02x}").unwrap();
    }
    let mut found = false;
    let mut allowed = Vec::new();
    for line in std::str::from_utf8(buf).map_err(io::Error::other)?.lines() {
        if let Some(value) = line.strip_prefix("public_key=") {
            if !value.eq_ignore_ascii_case(&key) {
                return Err(io::Error::other(
                    "публичный ключ UAPI отличается от профиля",
                ));
            }
            found = true;
        }
        if let Some(value) = line.strip_prefix("allowed_ip=") {
            if !found || allowed.len() == 1024 {
                return Err(io::Error::other("неверный список AllowedIPs"));
            }
            allowed.push(value.to_owned());
        }
    }
    let endpoint = super::s(&status, "endpoint")
        .parse::<std::net::SocketAddr>()
        .map_err(|_| io::Error::other("неверный адрес пира UAPI"))?;
    if !found || endpoint.port() == 0 || allowed.is_empty() {
        return Err(io::Error::other(
            "UAPI не подтвердил параметры маршрутизации",
        ));
    }
    Ok((endpoint, allowed))
}
#[cfg(unix)]
fn query(path: &Path, budget: Duration) -> io::Result<Vec<u8>> {
    request(path, b"get=1\n\n", budget, None)
}
#[cfg(unix)]
pub(crate) fn request(
    path: &Path,
    message: &[u8],
    budget: Duration,
    expected_pid: Option<u32>,
) -> io::Result<Vec<u8>> {
    use std::io::Write;
    if budget.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    let start = std::time::Instant::now();
    sock.connect_timeout(&socket2::SockAddr::unix(path)?, budget)?;
    #[cfg(target_os = "linux")]
    if let Some(pid) = expected_pid {
        use std::os::fd::AsRawFd;
        let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut n,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if n as usize != std::mem::size_of::<libc::ucred>()
            || unsafe { cred.assume_init() }.pid as u32 != pid
        {
            return Err(io::Error::other("сокет UAPI принадлежит другому процессу"));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = expected_pid;
    let mut stream = std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(sock));
    stream.set_write_timeout(Some(budget))?;
    stream.write_all(message)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut buf = Vec::new();
    let mut part = [0; 2048];
    while buf.len() <= 65536 {
        let left = budget
            .checked_sub(start.elapsed())
            .filter(|t| !t.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(left))?;
        let n = stream.read(&mut part)?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&part[..n]);
        if buf.len() > 65536 {
            break;
        }
        if buf.ends_with(b"\n\n") {
            return Ok(buf);
        }
    }
    Err(io::Error::other("слишком большой ответ UAPI"))
}
#[cfg(any(unix, test))]
pub(crate) fn uapi(buf: &[u8], now: u64, v: &mut Value) -> io::Result<()> {
    let mut parsed = v.clone();
    let mut peer = false;
    let mut complete = false;
    for line in buf.split(|b| *b == b'\n') {
        let Some((key, val)) = std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.split_once('='))
        else {
            continue;
        };
        match key {
            "fwmark" => {
                let mark = val
                    .parse::<u32>()
                    .or_else(|_| u32::from_str_radix(val.trim_start_matches("0x"), 16))
                    .map_err(|_| io::Error::other("неверная метка транспорта UAPI"))?;
                parsed["nested_transport"] = json!(mark >> 28 == 0xa);
                parsed["socket_mark"] = json!(mark);
            }
            "public_key" if !peer => peer = true,
            "public_key" => {
                return Err(io::Error::other("несколько пиров на клиентском интерфейсе"))
            }
            "errno" => {
                if val != "0" {
                    return Err(io::Error::other("ошибка запроса UAPI"));
                }
                complete = true;
            }
            "last_handshake_time_sec" => {
                parsed["last_handshake"] = json!(val
                    .parse::<u64>()
                    .map_err(|_| io::Error::other("неверное время UAPI"))?)
            }
            "rx_bytes" | "tx_bytes" => {
                parsed[key] = json!(val
                    .parse::<u64>()
                    .map_err(|_| io::Error::other("неверный счётчик UAPI"))?)
            }
            "endpoint" if val.parse::<std::net::SocketAddr>().is_ok() => {
                parsed["endpoint"] = json!(val)
            }
            _ => (),
        }
    }
    if !peer || !complete {
        return Err(io::Error::other("неполный ответ UAPI"));
    }
    *v = parsed;
    v["running"] = json!(!super::s(v, "endpoint").is_empty());
    let hs = v["last_handshake"].as_u64().unwrap_or(0);
    v["connected"] = json!(hs > 0 && now.checked_sub(hs).is_some_and(|age| age < 180));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_tunnel_requires_a_usable_global_scope_address_on_its_own_interface() {
        let address = "fd123456000000000000000000000001";
        let check = |rows: &str| usable_ipv6(rows.as_bytes(), "awg0");
        assert!(check(&format!("{address} 04 40 00 80 awg0\n")));
        for (scope, flags, device) in [
            ("20", "80", "awg0"),
            ("00", "48", "awg0"),
            ("00", "08", "awg0"),
            ("00", "80", "awg1"),
        ] {
            assert!(!check(&format!(
                "{address} 04 40 {scope} {flags} {device}\n"
            )));
        }
    }
    #[test]
    fn routing_accepts_only_matching_fresh_uapi_peer_and_allowed_networks() {
        let cfg = json!({"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="});
        let data=format!("private_key=unused\npublic_key={}\nendpoint=192.0.2.20:443\nlast_handshake_time_sec=10\nallowed_ip=203.0.113.0/24\nerrno=0\n\n","01".repeat(32));
        let (ep, nets) = routing_peer(data.as_bytes(), &cfg, 11, |_| {}).unwrap();
        assert_eq!(ep.to_string(), "192.0.2.20:443");
        assert_eq!(nets, ["203.0.113.0/24"]);
        let mut permanent = cfg.clone();
        permanent["client"] = json!({"double_tunnel_mode":"permanent"});
        assert!(routing_peer(data.as_bytes(), &permanent, 11, |_| {}).is_err());
        let marked = format!("fwmark=2684354561\n{data}");
        assert!(routing_peer(marked.as_bytes(), &permanent, 11, |_| {}).is_ok());
        assert!(routing_peer(data.as_bytes(), &cfg, 190, |_| {}).is_err());
        assert!(routing_peer(
            data.replace(&"01".repeat(32), &"02".repeat(32)).as_bytes(),
            &cfg,
            11,
            |_| {}
        )
        .is_err());
        assert!(routing_peer(
            data.replace("allowed_ip=", "unused=").as_bytes(),
            &cfg,
            11,
            |_| {}
        )
        .is_err());
    }
    #[test]
    fn native_owner_can_inspect_stale_uapi_without_relaxing_default_routing() {
        let cfg = json!({"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="});
        let response = format!(
            "fwmark=0\npublic_key={}\nendpoint=192.0.2.20:443\nlast_handshake_time_sec=10\nallowed_ip=0.0.0.0/0\nerrno=0\n\n",
            "01".repeat(32),
        );
        assert!(routing_peer(response.as_bytes(), &cfg, 190, |_| {}).is_err());
        let mut state = None;
        let (endpoint, grants) = routing_peer_sample(response.as_bytes(), &cfg, 190, false, |live| {
            state = live["connected"].as_bool();
        }).unwrap();
        assert_eq!(state, Some(false));
        assert_eq!(endpoint.to_string(), "192.0.2.20:443");
        assert_eq!(grants, ["0.0.0.0/0"]);
        assert!(routing_peer_sample(
            response.replace(&"01".repeat(32), &"02".repeat(32)).as_bytes(),
            &cfg,
            190,
            false,
            |_| {}
        ).is_err());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn local_unix_fixture_checks_peer_identity_and_exact_requests() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixListener,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.sock");
        let socket = UnixListener::bind(&path).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for i in 0..2 {
                    let (mut peer, _) = socket.accept().unwrap();
                    let mut bytes = Vec::new();
                    peer.read_to_end(&mut bytes).unwrap();
                    if i == 0 {
                        assert!(bytes.is_empty());
                    } else {
                        assert_eq!(bytes, b"get=1\n\n");
                        peer.write_all(b"errno=0\n\n").unwrap();
                    }
                }
            });
            assert!(request(&path, b"get=1\n\n", Duration::from_secs(1), Some(0)).is_err());
            assert_eq!(
                request(
                    &path,
                    b"get=1\n\n",
                    Duration::from_secs(1),
                    Some(std::process::id())
                )
                .unwrap(),
                b"errno=0\n\n"
            );
        });
    }
    #[test]
    fn uapi_counts_and_handshake_without_secrets_or_partial_results() {
        let mut v = json!({});
        let good=b"private_key=sensitive-fixture\npublic_key=peer\npreshared_key=private-fixture\nendpoint=[2001:db8::1]:42\nlast_handshake_time_sec=97\nrx_bytes=1234567890123\ntx_bytes=72\nerrno=0\n\n";
        uapi(good, 100, &mut v).unwrap();
        assert_eq!(v["rx_bytes"], 1234567890123u64);
        assert_eq!(v["connected"], true);
        assert!(!v.to_string().contains("fixture"));
        uapi(good, 277, &mut v).unwrap();
        assert_eq!(v["connected"], false);
        for partial in [
            b"rx_bytes=999\nerrno=1\n".as_slice(),
            b"public_key=a\nendpoint=192.0.2.1:80\n",
            b"public_key=a\nrx_bytes=-1\nerrno=0\n",
        ] {
            let before = v.clone();
            assert!(uapi(partial, 100, &mut v).is_err());
            assert_eq!(v, before);
        }
    }
    #[test]
    fn go_inline_buildinfo_across_chunks_with_dependency_replacement() {
        fn string(out: &mut Vec<u8>, bytes: &[u8]) {
            let mut n = bytes.len();
            while n >= 128 {
                out.push((n as u8) | 0x80);
                n >>= 7;
            }
            out.push(n as u8);
            out.extend(bytes);
        }
        let mut fixture = vec![0; 32768 - 16];
        let mut h = [0u8; 32];
        h[..14].copy_from_slice(MAGIC);
        h[14] = 8;
        h[15] = 2;
        fixture.extend(h);
        string(&mut fixture, b"go1.26.11");
        let deps=format!("mod\tgithub.com/amnezia-vpn/amneziawg-go/v3\t(devel)\nbuild\tvcs.revision={REV}\nbuild\t-tags=n2s_router_memory_v1\ndep\tgolang.org/x/crypto\tv0.57.0\ndep\tgolang.org/x/net\tv0.59.0\ndep\tgolang.org/x/sys\tv0.48.0\n");
        let mut m = vec![0; 16];
        m.extend(deps.as_bytes());
        m.extend([0; 16]);
        string(&mut fixture, &m);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine");
        std::fs::write(&path, fixture).unwrap();
        let (v, m) = go_build_info(&path).unwrap();
        let info = inspect(&v, &m);
        assert_eq!(info["awg3_supported"], true);
        assert_eq!(info["update_available"], false);
        assert_eq!(
            inspect(&v, &format!("{m}=>\tlocal.invalid/replacement\tv100.0.0"))["update_available"],
            true
        );
    }
}
