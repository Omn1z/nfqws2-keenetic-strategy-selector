use super::*;
mod nested_go;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};
mod signal;
pub(in crate::client) use signal::Target as SignalTarget;
#[cfg(test)]
mod tests;

fn changed() -> io::Error {
    invalid("владелец или конфигурация прежнего AWG-туннеля изменились")
}
fn file_id(m: &fs::Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}
fn number(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| changed())
}
pub(in crate::client) fn start_time(dir: &Path) -> io::Result<u64> {
    let (started, terminal) = process_start(dir)?;
    if terminal {
        Err(changed())
    } else {
        Ok(started)
    }
}
pub(in crate::client) fn process_start(dir: &Path) -> io::Result<(u64, bool)> {
    let stat = fs::read_to_string(dir.join("stat"))?;
    let mut fields = stat
        .rsplit_once(')')
        .ok_or_else(changed)?
        .1
        .split_whitespace();
    let state = fields.next().ok_or_else(changed)?;
    let started = fields
        .nth(18)
        .and_then(|s| s.parse().ok())
        .ok_or_else(changed)?;
    Ok((started, matches!(state, "Z" | "X" | "x")))
}
fn socket_name(iface: &str) -> String {
    format!("var/run/amneziawg/{iface}.sock")
}
fn socket_id(path: &Path) -> io::Result<(u64, u64)> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } {
        return Err(changed());
    }
    Ok(file_id(&m))
}
fn listener_inode(table: &str, name: &str) -> io::Result<u64> {
    let mut matches = table.lines().filter_map(|line| {
        let mut f = line.split_whitespace();
        let flags = f.nth(3)?;
        let ty = f.next()?;
        let state = f.next()?;
        let inode = f.next()?.parse().ok()?;
        let path = f.next()?.strip_prefix('/')?;
        (flags == "00010000" && ty == "0001" && state == "01" && name == path).then_some(inode)
    });
    let found = matches.next().ok_or_else(changed)?;
    if matches.next().is_some() {
        return Err(changed());
    }
    Ok(found)
}
fn command(dir: &Path, iface: &str) -> bool {
    let Ok(bytes) = fs::read(dir.join("cmdline")) else {
        return false;
    };
    let mut a = bytes.split(|v| *v == 0);
    a.next().and_then(|s| s.rsplit(|v| *v == b'/').next()) == Some(b"amneziawg-go")
        && a.next() == Some(iface.as_bytes())
        && a.next() == Some(b"")
        && a.next().is_none()
}

#[derive(Serialize, Deserialize)]
pub(super) struct Receipt {
    boot: String,
    iface: String,
    spec: [u8; 32],
    ifindex: u64,
    socket: (u64, u64),
    listener: u64,
    fd: u32,
    pid: i32,
    started: u64,
    exe: (u64, u64),
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nested: Option<nested_go::Nested>,
}

impl Receipt {
    pub(super) fn nested_iface_is(&self, iface: &str) -> bool {
        self.iface == iface && self.nested.is_some()
    }

    fn seal(&self) -> io::Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(io::Error::other)?).into())
    }

    fn matches_spec(&self, spec: &Spec) -> bool {
        self.iface == spec.iface && Sha256::digest(spec.conf.as_bytes()).as_slice() == self.spec
    }

    fn matches_transport(&self, response: &[u8]) -> bool {
        self.nested.as_ref().map_or_else(
            || direct(response),
            |nested| {
                nested
                    .mark()
                    .is_ok_and(|mark| socket_mark(response) == Some(mark))
            },
        )
    }

    fn proc_dir(&self, root: &Path) -> PathBuf {
        root.join("proc").join(self.pid.to_string())
    }
    fn owner(&self, root: &Path) -> io::Result<()> {
        let dir = self.proc_dir(root);
        if self.pid <= 1
            || !command(&dir, &self.iface)
            || start_time(&dir)? != self.started
            || file_id(&fs::metadata(dir.join("exe"))?) != self.exe
            || fs::read_link(dir.join("fd").join(self.fd.to_string()))?
                != Path::new(&format!("socket:[{}]", self.listener))
            || socket_id(&root.join(socket_name(&self.iface)))? != self.socket
            || number(&root.join("sys/class/net").join(&self.iface).join("ifindex"))?
                != self.ifindex
        {
            return Err(changed());
        }
        Ok(())
    }
}

pub(super) fn capture(runtime: &Runtime, spec: &Spec) -> io::Result<Receipt> {
    capture_owner(runtime, spec, None)
}

pub(super) fn capture_nested(runtime: &Runtime, spec: &Spec, outer: &Spec) -> io::Result<Receipt> {
    let outer_owner = capture(runtime, outer)?;
    capture_owner(runtime, spec, Some((outer_owner, outer)))
}

fn capture_owner(
    runtime: &Runtime,
    spec: &Spec,
    outer: Option<(Receipt, &Spec)>,
) -> io::Result<Receipt> {
    let root = &runtime.root;
    let proc = root.join("proc");
    let socket = socket_name(&spec.iface);
    let listener = listener_inode(&fs::read_to_string(proc.join("net/unix"))?, &socket)?;
    let exe = file_id(&fs::metadata(&runtime.engine)?);
    let expected = PathBuf::from(format!("socket:[{listener}]"));
    let mut owner = None;
    for entry in fs::read_dir(&proc)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<i32>().ok())
            .filter(|p| *p > 1)
        else {
            continue;
        };
        let dir = entry.path();
        if !command(&dir, &spec.iface) {
            continue;
        }
        if owner.is_some() || file_id(&fs::metadata(dir.join("exe"))?) != exe {
            return Err(changed());
        }
        let fd = fs::read_dir(dir.join("fd"))?
            .filter_map(Result::ok)
            .find_map(|fd| {
                (fs::read_link(fd.path()).ok()? == expected)
                    .then(|| fd.file_name().to_str()?.parse::<u32>().ok())
                    .flatten()
            })
            .ok_or_else(changed)?;
        owner = Some((pid, fd, start_time(&dir)?));
    }
    let (pid, fd, started) = owner.ok_or_else(changed)?;
    let mut receipt = Receipt {
        boot: fs::read_to_string(proc.join("sys/kernel/random/boot_id"))?,
        iface: spec.iface.clone(),
        spec: Sha256::digest(spec.conf.as_bytes()).into(),
        ifindex: number(&root.join("sys/class/net").join(&spec.iface).join("ifindex"))?,
        socket: socket_id(&root.join(&socket))?,
        listener,
        fd,
        pid,
        started,
        exe,
        nested: None,
    };
    let reply = crate::runtime::request(
        &root.join(&socket),
        b"get=1\n\n",
        Duration::from_secs(1),
        None,
    )?;
    matching_peer(spec, &reply).ok_or_else(changed)?;
    if let Some((outer_owner, outer_profile)) = outer {
        receipt.nested = Some(nested_go::Nested::capture(
            root,
            spec,
            &reply,
            outer_owner,
            outer_profile,
        )?);
    }
    if !receipt.matches_transport(&reply) {
        return Err(changed());
    }
    receipt.owner(root)?;
    Ok(receipt)
}

fn socket_mark(bytes: &[u8]) -> Option<u32> {
    let mut fields = std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .filter_map(|line| line.strip_prefix("fwmark="));
    let mark = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some(mark)
}

fn direct(reply: &[u8]) -> bool {
    std::str::from_utf8(reply).is_ok_and(|text| {
        text.lines()
            .filter_map(|l| l.strip_prefix("fwmark="))
            .all(|s| s == "0")
    })
}
fn reply(reader: &mut UnixStream) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(750);
    let mut bytes = Vec::new();
    let mut buf = [0; 2048];
    while bytes.len() <= 65536 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|t| !t.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        reader.set_read_timeout(Some(remaining))?;
        let size = reader.read(&mut buf)?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..size]);
        if bytes.ends_with(b"\n\n") && bytes.len() <= 65536 {
            return Ok(bytes);
        }
    }
    Err(invalid("неполный ответ UAPI"))
}

pub(super) struct Inherited {
    root: PathBuf,
    receipt: Receipt,
    identity: [u8; 32],
    nested_mtu: Option<NestedMtu>,
}
impl Inherited {
    pub(super) fn observe_direct_carrier(
        runtime: &Runtime,
        spec: &Spec,
        config: &Value,
    ) -> io::Result<([u8; 32], bool)> {
        let device = runtime.root.join("sys/class/net").join(&spec.iface);
        let flags = |name| -> io::Result<u32> {
            let value = fs::read_to_string(device.join(name))?;
            u32::from_str_radix(value.trim().trim_start_matches("0x"), 16).map_err(|_| changed())
        };
        if flags("flags")? & 1 == 0 || flags("tun_flags")? & 3 != 1 {
            return Err(changed());
        }
        let owner = Self {
            root: runtime.root.clone(),
            receipt: capture(runtime, spec)?,
            identity: expected_identity(spec).ok_or_else(changed)?,
            nested_mtu: None,
        };
        let (_stream, response) = owner.session()?;
        let now = crate::now();
        let mut fresh = None;
        let (endpoint, allowed) =
            crate::runtime::routing_peer_sample(&response, config, now, false, |status| {
                fresh = status["last_handshake"]
                    .as_u64()
                    .filter(|timestamp| *timestamp <= now)
                    .and_then(|_| status["connected"].as_bool());
            })?;
        let expected = s(config, "endpoint")
            .parse::<std::net::SocketAddr>()
            .map_err(|_| changed())?;
        if endpoint != expected
            || !endpoint.is_ipv4()
            || !allowed.iter().any(|ip| ip == "0.0.0.0/0")
        {
            return Err(changed());
        }
        Ok((owner.receipt.seal()?, fresh.ok_or_else(changed)?))
    }

    pub(super) fn retire_disabled(
        runtime: &Runtime,
        spec: &Spec,
        receipt: Receipt,
    ) -> io::Result<()> {
        if !receipt.matches_spec(spec)
            || another_panel(&runtime.root.join("proc"), std::process::id())?
        {
            return Err(changed());
        }
        if fs::read_to_string(runtime.root.join("proc/sys/kernel/random/boot_id"))? != receipt.boot
        {
            return Self::retire_vacant(runtime, spec, receipt);
        }
        let mut old_owner = Self {
            root: runtime.root.clone(),
            receipt,
            identity: expected_identity(spec).ok_or_else(changed)?,
            nested_mtu: None,
        };
        old_owner.stop()
    }

    pub(super) fn observe_nested(
        runtime: &Runtime,
        spec: &Spec,
        outer: &Spec,
        config: &Value,
        receipt: Receipt,
        identity: [u8; 32],
        trial: bool,
    ) -> io::Result<(Vec<String>, crate::RoutedNestedTransport)> {
        if !receipt.matches_spec(spec)
            || fs::read_to_string(runtime.root.join("proc/sys/kernel/random/boot_id"))?
                != receipt.boot
        {
            return Err(changed());
        }
        let owner = Self {
            root: runtime.root.clone(),
            receipt,
            identity,
            nested_mtu: None,
        };
        let (_stream, response) = owner.session()?;
        let (endpoint, allowed) =
            crate::runtime::routing_peer(&response, config, crate::now(), |_| {})?;
        let nested = owner.receipt.nested.as_ref().ok_or_else(changed)?;
        let proof = nested.observe(&owner.root, &response, spec, outer, endpoint, trial)?;
        owner.receipt.owner(&owner.root)?;
        Ok((allowed, proof))
    }

    pub(super) fn bind(
        runtime: &Runtime,
        spec: &Spec,
        receipt: Receipt,
        identity: [u8; 32],
    ) -> io::Result<Self> {
        if !receipt.matches_spec(spec)
            || fs::read_to_string(runtime.root.join("proc/sys/kernel/random/boot_id"))?
                != receipt.boot
        {
            return Err(changed());
        }
        let nested_mtu = receipt
            .nested
            .as_ref()
            .map(|nested| nested.mtu_policy(spec))
            .transpose()?;
        let engine = Self {
            root: runtime.root.clone(),
            receipt,
            identity,
            nested_mtu,
        };
        let (_, response) = engine.session()?;
        if let Some((nested, policy)) = engine.receipt.nested.as_ref().zip(nested_mtu) {
            nested.verify_repairable(&engine.root, &response, policy)?;
            engine.receipt.owner(&engine.root)?;
        }
        Ok(engine)
    }
    pub(super) fn replay(
        runtime: &Runtime,
        spec: &Spec,
        receipt: Receipt,
        identity: [u8; 32],
        seal: [u8; 32],
    ) -> io::Result<Option<Self>> {
        if !receipt.matches_spec(spec) || receipt.seal()? != seal || receipt.nested.is_some() {
            return Err(changed());
        }
        let boot = fs::read_to_string(runtime.root.join("proc/sys/kernel/random/boot_id"))?;
        if boot != receipt.boot {
            return if [
                runtime.root.join("sys/class/net").join(&spec.iface),
                runtime.root.join(socket_name(&spec.iface)),
            ]
            .iter()
            .all(|path| {
                fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            }) {
                Ok(None)
            } else {
                Err(changed())
            };
        }
        let owner = Self {
            root: runtime.root.clone(),
            receipt,
            identity,
            nested_mtu: None,
        };
        if owner.vacant() {
            return Ok(None);
        }
        owner.session()?;
        Ok(Some(owner))
    }
    fn session(&self) -> io::Result<(UnixStream, Vec<u8>)> {
        use std::os::fd::OwnedFd;
        self.receipt.owner(&self.root)?;
        let raw = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        let addr = socket2::SockAddr::unix(self.root.join(socket_name(&self.receipt.iface)))?;
        raw.connect_timeout(&addr, Duration::from_millis(750))?;
        let mut sock = UnixStream::from(OwnedFd::from(raw));
        sock.set_write_timeout(Some(Duration::from_millis(750)))?;
        sock.write_all(b"get=1\n\n")?;
        let bytes = reply(&mut sock)?;
        let mut state = json!({});
        crate::runtime::uapi(&bytes, crate::now(), &mut state)?;
        if state["running"] != true
            || reported_identity(&bytes) != Some(self.identity)
            || !self.receipt.matches_transport(&bytes)
        {
            return Err(changed());
        }
        self.receipt.owner(&self.root)?;
        Ok((sock, bytes))
    }
    fn vacant(&self) -> bool {
        let dir = self.receipt.proc_dir(&self.root);
        let exited = match start_time(&dir) {
            Ok(time) => time != self.receipt.started,
            Err(e) => e.kind() == io::ErrorKind::NotFound,
        };
        exited
            && [
                self.root.join("sys/class/net").join(&self.receipt.iface),
                self.root.join(socket_name(&self.receipt.iface)),
            ]
            .iter()
            .all(|p| fs::symlink_metadata(p).is_err_and(|e| e.kind() == io::ErrorKind::NotFound))
    }

    pub(super) fn retire_vacant(
        runtime: &Runtime,
        spec: &Spec,
        receipt: Receipt,
    ) -> io::Result<()> {
        if receipt.nested.is_none() {
            return Ok(());
        }
        if !receipt.matches_spec(spec)
            || another_panel(&runtime.root.join("proc"), std::process::id())?
        {
            return Err(changed());
        }
        let owner = Self {
            root: runtime.root.clone(),
            receipt,
            identity: expected_identity(spec).ok_or_else(changed)?,
            nested_mtu: None,
        };
        if !owner.vacant() {
            return Err(changed());
        }
        let nested = owner.receipt.nested.as_ref().ok_or_else(changed)?;
        if fs::read_to_string(runtime.root.join("proc/sys/kernel/random/boot_id"))?
            != owner.receipt.boot
        {
            return nested.previous_boot_vacant(&owner.root);
        }
        nested.retire(&owner.root, nested.prepare_retirement(&owner.root)?)
    }
}
impl Tunnel for Inherited {
    fn inherited(&self) -> bool {
        true
    }
    fn matches_response(&self, bytes: &[u8]) -> bool {
        reported_identity(bytes) == Some(self.identity)
            && self.receipt.matches_transport(bytes)
            && self.receipt.owner(&self.root).is_ok()
    }
    fn alive(&mut self) -> bool {
        self.receipt.owner(&self.root).is_ok()
    }
    fn snapshot(&self) -> io::Result<Value> {
        let (_, bytes) = self.session()?;
        let mut state = json!({});
        crate::runtime::uapi(&bytes, crate::now(), &mut state)?;
        let tx = self
            .root
            .join("sys/class/net")
            .join(&self.receipt.iface)
            .join("statistics/tx_packets");
        if let Ok(n) = number(&tx) {
            state["tun_tx_packets"] = n.into();
        }
        Ok(state)
    }

    fn nested_iface(&self) -> Option<&str> {
        self.receipt
            .nested
            .as_ref()
            .map(nested_go::Nested::outer_iface)
    }

    fn repair_nested(&mut self) -> io::Result<()> {
        let nested = self.receipt.nested.as_ref().ok_or_else(changed)?;
        let policy = self.nested_mtu.ok_or_else(changed)?;
        let (_session, response) = self.session()?;
        nested.repair(&self.root, &self.receipt, &response, policy)
    }

    fn verified_legacy_predecessor(
        &self,
        spec: &Spec,
        endpoint: std::net::SocketAddr,
        mtu: u16,
        connected: bool,
    ) -> io::Result<crate::client::settings::RoutedLegacyPredecessor> {
        if self.receipt.nested.is_some()
            || !self.receipt.matches_spec(spec)
            || fs::read_to_string(self.root.join("proc/sys/kernel/random/boot_id"))?
                != self.receipt.boot
            || another_panel(&self.root.join("proc"), std::process::id())?
        {
            return Err(changed());
        }
        if connected || !self.vacant() {
            let status = self.snapshot()?;
            if crate::client::supervisor::live_transport_endpoint(&status) != Some(endpoint)
                || connected && status["connected"] != true
                || number(
                    &self
                        .root
                        .join("sys/class/net")
                        .join(&self.receipt.iface)
                        .join("mtu"),
                )? != u64::from(mtu)
            {
                return Err(changed());
            }
        }
        Ok(crate::client::settings::RoutedLegacyPredecessor {
            receipt_sha256: self.receipt.seal()?,
            endpoint,
        })
    }
    fn probe(&mut self) -> io::Result<()> {
        // Keep the authenticated stream open across get/set. A replacement
        // daemon binding the same pathname can never receive this message.
        let (mut sock, bytes) = self.session()?;
        let get = std::str::from_utf8(&bytes).map_err(|_| changed())?;
        let peer = get
            .lines()
            .find_map(|s| s.strip_prefix("public_key="))
            .ok_or_else(changed)?;
        let interval = get
            .lines()
            .find_map(|s| s.strip_prefix("persistent_keepalive_interval="))
            .unwrap_or("0");
        let interval = conf::range(interval, u16::MAX.into())?;
        let next = if interval == "0" { "25" } else { &interval };
        let mut msg = format!("set=1\npublic_key={peer}\nupdate_only=true\npersistent_keepalive_interval=0\npersistent_keepalive_interval={next}\n");
        if interval == "0" {
            msg.push_str(&format!(
                "public_key={peer}\nupdate_only=true\npersistent_keepalive_interval=0\n"
            ));
        }
        msg.push('\n');
        sock.write_all(msg.as_bytes())?;
        if reply(&mut sock)? != b"errno=0\n\n" {
            return Err(changed());
        }
        Ok(())
    }

    fn stop(&mut self) -> io::Result<()> {
        let retirement = self
            .receipt
            .nested
            .as_ref()
            .map(|nested| nested.prepare_retirement(&self.root))
            .transpose()?;
        let retire = |vacant| {
            if let Some((nested, hold)) = self.receipt.nested.as_ref().zip(vacant) {
                nested.retire(&self.root, hold)?;
            }
            Ok(())
        };
        if self.vacant() {
            return retire(retirement);
        }
        let target = signal::Target::open(self.receipt.pid)?;
        self.session()?;
        target.terminate()?;
        let until = Instant::now() + Duration::from_secs(4);
        while !self.vacant() {
            if Instant::now() >= until {
                return Err(invalid("прежний движок ещё не освободил интерфейс"));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        retire(retirement)
    }
}
