use super::{
    command::{Runner, System},
    err,
    ownership::{go_json, Binding, Snapshot},
    uci::{conditional, valid_id, Configuration, OptionValue, Options},
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const SNAP: &str = "openwrt-dns-binding.json";
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
const LIMIT: u64 = 64 * 1024;
const UNFINISHED: &str = "Предыдущее применение не завершено. Восстановите прежние DNS-настройки.";
const STAGED: &str =
    "В UCI есть несохранённые изменения network или dhcp. Сначала примените или отмените их.";
const UNMATCHED: &str = "Сохранённый экземпляр dnsmasq больше не совпадает с конфигурацией UCI.";
const STALE: &str = "Настройки OpenWrt изменились; обновите состояние.";
const UNSUPPORTED: &str = "Автоматическая настройка доступна только на OpenWrt с UCI и dnsmasq";

#[derive(Default, Debug, Serialize)]
pub struct State {
    pub supported: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub interfaces: Vec<Value>,
    pub instances: Vec<Value>,
    pub managed: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub conflict: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rebind_instance: String,
    pub warnings: Vec<String>,
    pub revision: String,
}
pub struct Manager {
    root: PathBuf,
    supported: bool,
    runner: Box<dyn Runner>,
    mutex: Mutex<()>,
}
struct View {
    network: Configuration,
    dhcp: Configuration,
    stored: Option<Snapshot>,
    bound: Option<Snapshot>,
    candidate: Option<Snapshot>,
    conflict: String,
    staged: bool,
    revision: String,
}
impl View {
    fn revision(&self, want: &str) -> io::Result<()> {
        if !want.is_empty() && want != self.revision {
            return Err(err(STALE));
        }
        Ok(())
    }
    fn writable(&self) -> io::Result<()> {
        if !self.conflict.is_empty() {
            return Err(err(&self.conflict));
        }
        Ok(())
    }
}
impl Manager {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            root: data_dir.as_ref().into(),
            supported: cfg!(target_os = "linux")
                && nfqws2_config::Resolver::current().platform()
                    == nfqws2_config::Platform::OpenWrt
                && Path::new("/etc/openwrt_release").is_file(),
            runner: Box::new(System),
            mutex: Mutex::new(()),
        }
    }
    pub fn current_binding(&self) -> io::Result<Option<Binding>> {
        let _guard = self.mutex.lock().unwrap();
        if !self.supported {
            return Ok(None);
        }
        Ok(self.read()?.map(|s| s.binding))
    }
    fn supported(&self) -> io::Result<()> {
        if self.supported {
            Ok(())
        } else {
            Err(err(UNSUPPORTED))
        }
    }
    fn until() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn lock(&self, end: Instant) -> io::Result<File> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&self.root)?;
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let f = opts.open(self.root.join(format!("{SNAP}.lock")))?;
        if !f.metadata()?.is_file() {
            return Err(err("invalid UCI transaction lock file"));
        }
        loop {
            match f.try_lock() {
                Ok(()) => return Ok(f),
                Err(fs::TryLockError::WouldBlock) if Instant::now() < end => {
                    thread::sleep(Duration::from_millis(25))
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    fn read(&self) -> io::Result<Option<Snapshot>> {
        let path = self.root.join(SNAP);
        let m = match path.symlink_metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            v => v?,
        };
        if !m.is_file() || m.len() > LIMIT {
            return Err(err("invalid OpenWrt DNS snapshot file"));
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let f = opts.open(path)?;
        if !f.metadata()?.is_file() {
            return Err(err("snapshot is not a regular file"));
        }
        let mut bytes = Vec::new();
        f.take(LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > LIMIT {
            return Err(err("snapshot exceeds 64 KiB"));
        }
        let s: Snapshot = serde_json::from_slice(&bytes)?;
        s.validate()?;
        Ok(Some(s))
    }
    fn save(&self, s: Option<&Snapshot>) -> io::Result<()> {
        let path = self.root.join(SNAP);
        if let Some(s) = s {
            s.validate()?;
            let bytes = serde_json::to_vec_pretty(s)?;
            if bytes.len() as u64 > LIMIT {
                return Err(err("snapshot exceeds 64 KiB"));
            }
            let mut tmp = tempfile::NamedTempFile::new_in(&self.root)?;
            tmp.write_all(&bytes)?;
            tmp.as_file().sync_all()?;
            tmp.persist(&path)?;
        } else {
            match fs::remove_file(path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                v => v?,
            }
        }
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn call(&self, end: Instant, name: &str, args: &[&str]) -> io::Result<String> {
        if Instant::now() >= end {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.runner.run(name, args, end)
    }
    fn package(&self, pkg: &str, end: Instant) -> io::Result<Configuration> {
        let raw = self.call(end, "uci", &["-q", "-N", "export", pkg])?;
        Configuration::parse(&raw, pkg)
    }
    fn inspect(&self, end: Instant) -> io::Result<View> {
        let mut staged = false;
        for pkg in ["network", "dhcp"] {
            staged |= !self
                .call(end, "uci", &["-q", "changes", pkg])?
                .trim()
                .is_empty();
        }
        let network = self.package("network", end)?;
        let dhcp = self.package("dhcp", end)?;
        let stored = self.read()?;
        let mut candidate = None;
        let mut conflict = String::new();
        let bound = match stored.as_ref().map(|s| s.resolve(&dhcp)).transpose() {
            Ok(Some(Some(s))) => {
                if let Err(e) = s.binding.options(&network, &dhcp) {
                    conflict = e.to_string();
                }
                Some(s)
            }
            Ok(Some(None)) => {
                conflict = UNMATCHED.into();
                if !staged {
                    candidate = stored
                        .as_ref()
                        .and_then(|s| s.rebind_candidate(&network, &dhcp));
                }
                None
            }
            Ok(None) => None,
            Err(e) => {
                conflict = e.to_string();
                None
            }
        };
        let mut hash = Sha256::new();
        hash.update(network.digest);
        hash.update(dhcp.digest);
        hash.update(go_json(&stored)?);
        Ok(View {
            network,
            dhcp,
            stored,
            bound,
            candidate,
            conflict,
            staged,
            revision: super::hex(&hash.finalize()),
        })
    }
    pub fn status(&self) -> io::Result<State> {
        let _guard = self.mutex.lock().unwrap();
        let mut state = State {
            supported: self.supported,
            ..State::default()
        };
        if !self.supported {
            state.reason = UNSUPPORTED.into();
            return Ok(state);
        }
        let end = Self::until();
        let v = self.inspect(end)?;
        state.revision.clone_from(&v.revision);
        state.conflict.clone_from(&v.conflict);
        if let Some(s) = v.bound.as_ref().or(v.stored.as_ref()) {
            state.binding = Some(s.binding.clone());
            state.managed = true;
            state.pending = s.pending;
            if let Some(candidate) = v.candidate {
                state.rebind_instance = candidate.binding.instance;
            }
            if s.pending {
                state.warnings.push(UNFINISHED.into());
            }
            if state.conflict.is_empty() {
                let current = s.binding.options(&v.network, &v.dhcp)?;
                if let Err(e) = s.check(&current) {
                    state.conflict = e.to_string();
                } else if v.staged && (!s.pending || self.guard(&current, end).is_err()) {
                    state.conflict = STAGED.into();
                }
            }
        } else if v.staged {
            state.conflict = STAGED.into();
        }
        let live = self
            .call(end, "ubus", &["call", "network.interface", "dump"])
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        for s in v
            .network
            .sections
            .iter()
            .filter(|s| s.kind == "interface" && s.id != "loopback" && valid_id(&s.id))
        {
            let data = live
                .as_ref()
                .and_then(|v| v["interface"].as_array())
                .and_then(|a| a.iter().find(|v| v["interface"] == s.id));
            let default = data.and_then(|d| d["route"].as_array()).is_some_and(|rs| {
                rs.iter().any(|r| {
                    r["mask"] == 0 && matches!(r["target"].as_str(), Some("0.0.0.0" | "::"))
                })
            });
            state.interfaces.push(json!({"id":s.id,"label":s.id,"protocol":s.scalar("proto"),"dns":s.values("dns"),"default":default,
                "device":data.and_then(|d|d["l3_device"].as_str()).filter(|v|!v.is_empty()).unwrap_or(s.scalar("device")),"up":data.is_some_and(|d|d["up"]==true)}));
        }
        state.interfaces.sort_by(|a, b| {
            b["default"]
                .as_bool()
                .cmp(&a["default"].as_bool())
                .then(a["id"].as_str().cmp(&b["id"].as_str()))
        });
        for s in v.dhcp.sections.iter().filter(|s| s.kind == "dnsmasq") {
            state.instances.push(json!({"id":s.id,"label":s.id,"networks":s.values("interface"),"enabled":s.enabled()}));
            for key in ["confdir", "serversfile"] {
                if !s.scalar(key).is_empty() {
                    state.warnings.push(format!("dnsmasq {}: дополнительные {key} могут задавать DNS вне управляемой привязки; их содержимое не изменяется.",s.id));
                }
            }
        }
        state.warnings.push("DNS-forwarding выбранного dnsmasq применяется ко всем сетям, которые обслуживает этот экземпляр. Локальные и специальные доменные DNS-правила сохраняются.".into());
        Ok(state)
    }
    fn reload_id(&self, id: &str, end: Instant) -> io::Result<String> {
        if !id.starts_with('@') {
            return Ok(id.to_owned());
        }
        let out = self.call(end, "uci", &["-q", "-X", "show", &format!("dhcp.{id}")])?;
        out.lines()
            .next()
            .and_then(|s| s.trim().strip_prefix("dhcp.")?.strip_suffix("=dnsmasq"))
            .filter(|s| valid_id(s))
            .map(str::to_owned)
            .ok_or_else(|| err("invalid dnsmasq section name"))
    }
    fn guard(&self, owned: &Options, end: Instant) -> io::Result<()> {
        let mut allowed: HashSet<String> = owned.keys().cloned().collect();
        let anonymous = owned.keys().find_map(|s| {
            s.strip_prefix("dhcp.")?
                .split_once('.')
                .map(|v| v.0)
                .filter(|id| id.starts_with('@'))
        });
        if let Some(id) = anonymous {
            let actual = self.reload_id(id, end)?;
            allowed.extend(["server", "noresolv"].map(|key| format!("dhcp.{actual}.{key}")));
        }
        for pkg in ["network", "dhcp"] {
            for line in self
                .call(end, "uci", &["-q", "changes", pkg])?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
            {
                let line = line.strip_prefix('-').unwrap_or(line);
                let key = line
                    .split_once('=')
                    .map_or(line, |(k, _)| k.trim_end_matches(['+', '-']));
                if !allowed.contains(key) {
                    return Err(err(STAGED));
                }
            }
        }
        Ok(())
    }
    fn replace(
        &self,
        s: &Snapshot,
        current: &Options,
        desired: &Options,
        end: Instant,
    ) -> io::Result<()> {
        // Re-read the expected staged state before modifying a key. An
        // unrelated UCI client does not participate in the panel's file lock.
        let mut expected = current.clone();
        for (key, v) in desired {
            if &current[key] == v {
                continue;
            }
            self.verify(s, &expected, end)?;
            if !current[key].kind.is_empty() {
                self.call(end, "uci", &["-q", "delete", key])?;
            }
            let op = if v.kind == "list" { "add_list" } else { "set" };
            for val in &v.values {
                self.call(end, "uci", &["-q", op, &format!("{key}={val}")])?;
            }
            expected.insert(key.clone(), v.clone());
        }
        for pkg in ["network", "dhcp"] {
            self.verify(s, desired, end)?;
            self.call(end, "uci", &["-q", "commit", pkg])?;
        }
        self.call(end, "ubus", &["call", "network", "reload"])?;
        self.call(
            end,
            "/etc/init.d/dnsmasq",
            &["reload", &self.reload_id(&s.binding.instance, end)?],
        )?;
        self.verify(s, desired, end)
    }
    fn verify(&self, s: &Snapshot, desired: &Options, end: Instant) -> io::Result<()> {
        let dhcp = self.package("dhcp", end)?;
        let after = s.binding.options(&self.package("network", end)?, &dhcp)?;
        if &after != desired {
            return Err(err("managed DNS options changed concurrently"));
        }
        s.check_identity(&dhcp)?;
        self.guard(desired, end)
    }
    fn commit(
        &self,
        pending: Snapshot,
        previous: Option<&Snapshot>,
        restore: bool,
        end: Instant,
    ) -> io::Result<()> {
        self.save(Some(&pending))?;
        let result = self
            .replace(&pending, &pending.before, &pending.applied, end)
            .and_then(|_| {
                if restore {
                    return self.save(None);
                }
                let mut done = pending.clone();
                done.pending = false;
                done.before.clear();
                self.save(Some(&done))
            });
        if let Err(cause) = result {
            let rollback = (|| {
                let end = Instant::now() + Duration::from_secs(15);
                let dhcp = self.package("dhcp", end)?;
                let actual = pending
                    .binding
                    .options(&self.package("network", end)?, &dhcp)?;
                pending.check_identity(&dhcp)?;
                pending.check(&actual)?;
                self.guard(&pending.before, end)?;
                self.replace(&pending, &actual, &pending.before, end)?;
                self.save(previous)
            })();
            return Err(match rollback {
                Ok(()) => cause,
                Err(e) => err(format!(
                    "{cause}; восстановление не завершено, резервная копия сохранена: {e}"
                )),
            });
        }
        Ok(())
    }
    pub fn apply(&self, binding: Binding, revision: &str) -> io::Result<()> {
        self.supported()?;
        binding.validate()?;
        let _guard = self.mutex.lock().unwrap();
        let end = Self::until();
        let _file = self.lock(end)?;
        let v = self.inspect(end)?;
        v.writable()?;
        v.revision(revision)?;
        if v.staged {
            return Err(err(STAGED));
        }
        let current = binding.options(&v.network, &v.dhcp)?;
        if !v.dhcp.find(&binding.instance, "dnsmasq")?.enabled() {
            return Err(err("dnsmasq is disabled"));
        }
        let original = if let Some(s) = &v.bound {
            if s.binding.interface != binding.interface || s.binding.instance != binding.instance {
                return Err(err("restore the previous DNS binding first"));
            }
            s.check(&current)?;
            if s.pending {
                return Err(err(UNFINISHED));
            }
            s.original.clone()
        } else {
            current.clone()
        };
        let ip = binding.endpoint.address()?.to_string();
        let [peer, dns, noresolv, server] = binding.keys();
        let mut servers = vec![format!("{ip}#{}", binding.endpoint.port)];
        servers.extend(
            current[&server]
                .values
                .iter()
                .filter(|s| conditional(s))
                .cloned(),
        );
        let applied = Options::from([
            (peer, OptionValue::scalar("0")),
            (dns, OptionValue::list(vec![ip])),
            (noresolv, OptionValue::scalar("1")),
            (server, OptionValue::list(servers)),
        ]);
        let mut next = Snapshot {
            version: 1,
            binding,
            original,
            applied,
            pending: true,
            before: current,
            identity: String::new(),
            scope: String::new(),
        };
        next.capture(&v.dhcp)?;
        if v.bound.as_ref().is_some_and(|s| s.binding == next.binding)
            && next.applied == next.before
        {
            next.pending = false;
            next.before.clear();
            if Some(&next) != v.stored.as_ref() {
                self.save(Some(&next))?;
            }
            return Ok(());
        }
        self.commit(next, v.stored.as_ref(), false, end)
    }
    pub fn rebind(&self, instance: &str, revision: &str) -> io::Result<()> {
        self.supported()?;
        let _guard = self.mutex.lock().unwrap();
        let end = Self::until();
        let _file = self.lock(end)?;
        let v = self.inspect(end)?;
        if revision.is_empty() {
            return Err(err(STALE));
        }
        v.revision(revision)?;
        let mut s = v
            .candidate
            .filter(|s| s.binding.instance == instance)
            .ok_or_else(|| err("no unique matching dnsmasq instance to confirm"))?;
        s.capture(&v.dhcp)?;
        self.save(Some(&s))
    }
    pub fn restore(&self, revision: &str) -> io::Result<()> {
        self.supported()?;
        let _guard = self.mutex.lock().unwrap();
        if self.read()?.is_none() {
            return Ok(());
        }
        let end = Self::until();
        let _file = self.lock(end)?;
        let v = self.inspect(end)?;
        v.writable()?;
        v.revision(revision)?;
        let Some(mut s) = v.bound else {
            return Ok(());
        };
        let current = s.binding.options(&v.network, &v.dhcp)?;
        if v.staged {
            if !s.pending {
                return Err(err(STAGED));
            }
            self.guard(&current, end)?;
        }
        s.check(&current)?;
        s.capture(&v.dhcp)?;
        s.pending = true;
        s.before = current;
        s.applied = s.original.clone();
        self.commit(s, v.stored.as_ref(), true, end)
    }
}
