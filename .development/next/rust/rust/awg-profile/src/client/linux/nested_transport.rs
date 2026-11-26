use super::{call, invalid, nested, request, NestedOuter};
use nested::Routes;
use serde_json::Value;
use std::{
    fs,
    io::{self, Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

fn ip_tool() -> io::Result<(&'static str, bool)> {
    static TOOL: std::sync::OnceLock<(&str, bool)> = std::sync::OnceLock::new();
    if let Some(t) = TOOL.get() {
        return Ok(*t);
    }
    let program = if Path::new("/opt/libexec/ip-full").try_exists()? {
        "/opt/libexec/ip-full"
    } else {
        "ip"
    };
    if !call(program, &["-V"])?.starts_with("ip utility, iproute2-") {
        return Err(invalid("для вложенного туннеля требуется ip-full"));
    }
    let tool = (program, call(program, &["-N", "-V"]).is_ok());
    Ok(*TOOL.get_or_init(|| tool))
}
pub(in crate::client) fn ip(args: &[&str]) -> io::Result<String> {
    let (program, numeric) = ip_tool()?;
    if numeric && args.first() == Some(&"-o") {
        let mut flags = vec!["-N"];
        flags.extend_from_slice(args);
        call(program, &flags)
    } else {
        call(program, args)
    }
}
pub(in crate::client) fn check_names(routes: &Routes) -> io::Result<()> {
    check_ip_names(routes.table()?, 99)
}
pub(in crate::client) fn check_ip_names(table: u32, protocol: u32) -> io::Result<()> {
    if ip_tool()?.1 {
        return Ok(());
    }
    for dir in [
        "/etc/iproute2",
        "/usr/lib/iproute2",
        "/opt/etc/iproute2",
        "/opt/usr/lib/iproute2",
    ] {
        for (file, id) in [("rt_tables", table), ("rt_protos", protocol)] {
            let mut files = vec![Path::new(dir).join(file)];
            let extras = files[0].with_extension("d");
            if extras.try_exists()? {
                for f in fs::read_dir(extras)? {
                    let p = f?.path();
                    if p.extension().is_some_and(|e| e == "conf") {
                        files.push(p);
                    }
                }
            }
            for path in files {
                if !path.try_exists()? {
                    continue;
                }
                let names = fs::read_to_string(path)?;
                for l in names.lines() {
                    let w: Vec<_> = l
                        .split('#')
                        .next()
                        .unwrap()
                        .split_ascii_whitespace()
                        .collect();
                    if let [raw, name, ..] = w.as_slice() {
                        let parse = |v: &str| {
                            v.strip_prefix("0x")
                                .map_or_else(|| v.parse(), |v| u32::from_str_radix(v, 16))
                        };
                        if parse(raw) == Ok(id) || parse(name) == Ok(id) {
                            return Err(invalid(
                                "псевдоним iproute2 препятствует проверке владения маршрутом",
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
pub(in crate::client) fn lock_table(socket: &Path, r: &Routes) -> io::Result<fs::File> {
    super::lock_marker(&socket.with_file_name(format!("n2s-nested-table-{}.lock", r.table()?)))
}
fn numeric(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| invalid("некорректные параметры интерфейса"))
}
fn facts(outer: &NestedOuter, endpoint: IpAddr) -> io::Result<(IpAddr, u64, nested::OuterPeer)> {
    let dir = Path::new("/sys/class/net").join(&outer.iface);
    let flags = |name: &str| -> io::Result<u32> {
        let raw = fs::read_to_string(dir.join(name))?;
        u32::from_str_radix(raw.trim().trim_start_matches("0x"), 16)
            .map_err(|_| invalid("неверные флаги внешнего TUN"))
    };
    if flags("tun_flags")? & 3 != 1 || flags("flags")? & 1 == 0 {
        return Err(invalid("внешний интерфейс TUN недоступен"));
    }
    let socket = Path::new("/var/run/amneziawg").join(format!("{}.sock", outer.iface));
    let buf = request(&socket, b"get=1\n\n", Duration::from_secs(1), None)?;
    let peer = nested::check_outer_peer(&buf, &outer.peer_hex, endpoint, crate::now())?;
    let family = if endpoint.is_ipv4() { "-4" } else { "-6" };
    let addrs = ip(&["-o", family, "address", "show", "dev", &outer.iface])?;
    Ok((
        nested::source(&addrs, endpoint)?,
        numeric(&dir.join("mtu"))?,
        peer,
    ))
}
fn receipt(path: &Path, iface: &str) -> io::Result<Option<Routes>> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => result?,
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.len() > 2048
    {
        return Err(invalid("неверный файл владения маршрутом вложенного AWG"));
    }
    let r: Routes = serde_json::from_reader(file.take(2049))
        .map_err(|_| invalid("повреждён файл владения маршрутом вложенного AWG"))?;
    r.validate(iface)?;
    Ok(Some(r))
}
fn owns_retiring_routes(path: &Path, expected: &Routes) -> io::Result<bool> {
    match receipt(path, &expected.iface)? {
        None => Ok(false),
        Some(found) if found == *expected => Ok(true),
        Some(_) => Err(invalid("изменился владелец маршрута вложенного AWG")),
    }
}

fn release_routes(
    path: &Path,
    expected: &Routes,
    ip: &dyn Fn(&[&str]) -> io::Result<String>,
) -> io::Result<()> {
    release_routes_on_boot(path, expected, ip, true)
}

fn release_routes_on_boot(
    path: &Path,
    expected: &Routes,
    ip: &dyn Fn(&[&str]) -> io::Result<String>,
    current_boot: bool,
) -> io::Result<()> {
    let owned = owns_retiring_routes(path, expected)?;
    expected.reconcile(owned && current_boot, false, ip)?;
    if owned {
        expected.verify_retirement(false, ip)?;
        if !owns_retiring_routes(path, expected)? {
            return Err(invalid("изменилась запись владельца вложенного AWG"));
        }
        fs::remove_file(path)?;
    }
    fs::File::open(
        path.parent()
            .ok_or_else(|| invalid("нет каталога вложенного AWG"))?,
    )?
    .sync_all()
}

fn release(path: &Path, expected: &Routes) -> io::Result<()> {
    check_names(expected)?;
    release_routes(path, expected, &ip)
}
pub(super) struct NestedTransport {
    _table: fs::File,
    path: PathBuf,
    outer: NestedOuter,
    pub routes: Routes,
    pub mtu: u64,
    outer_mtu: u64,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    outer: NestedOuter,
    routes: Routes,
    mtu: u64,
    outer_mtu: u64,
}

pub(super) struct Retirement {
    _table: fs::File,
    path: PathBuf,
    routes: Routes,
    current_boot: bool,
}

impl Retirement {
    fn prepare(
        socket: &Path,
        routes: Routes,
        owns_receipt: bool,
        current_boot: bool,
    ) -> io::Result<Self> {
        let path = socket.with_extension("n2s-nested.json");
        let table = lock_table(socket, &routes)?;
        let observed = owns_retiring_routes(&path, &routes)?;
        if !owns_receipt && observed {
            return Err(invalid("не подтверждено владение маршрутом вложенного AWG"));
        }
        check_names(&routes)?;
        routes.verify_retirement(observed && current_boot, &ip)?;
        Ok(Self {
            _table: table,
            path,
            routes,
            current_boot,
        })
    }

    pub fn release(self) -> io::Result<()> {
        check_names(&self.routes)?;
        release_routes_on_boot(&self.path, &self.routes, &ip, self.current_boot)
    }
}

impl Saved {
    pub(super) fn owns_socket_routes(
        &self,
        socket: &Path,
        spec: &NestedOuter,
        iface: &str,
        endpoint: IpAddr,
    ) -> io::Result<bool> {
        let scope = self.removal_scope(iface)?;
        Ok(&self.outer == spec
            && scope.endpoint == endpoint
            && receipt(&socket.with_extension("n2s-nested.json"), iface)?.as_ref()
                == Some(&self.routes))
    }

    pub fn removal_scope(&self, iface: &str) -> io::Result<super::super::NativeNestedRemovalScope> {
        self.routes.validate(iface)?;
        if self.outer.iface != self.routes.outer {
            return Err(invalid("запись внешнего AWG изменилась"));
        }
        Ok(super::super::NativeNestedRemovalScope {
            outer_iface: self.routes.outer.clone(),
            endpoint: self.routes.endpoint,
            source: self.routes.source,
        })
    }
}
impl NestedTransport {
    pub fn verify_retirement(&self, saved: &Saved) -> io::Result<()> {
        if self.snapshot() != *saved {
            return Err(invalid("запись владельца вложенного AWG изменилась"));
        }
        let owned = owns_retiring_routes(&self.path, &self.routes)?;
        check_names(&self.routes)?;
        self.routes.verify_retirement(owned, &ip)
    }

    pub fn retire_saved(
        socket: &Path,
        iface: &str,
        saved: &Saved,
        current_boot: bool,
    ) -> io::Result<()> {
        Self::prepare_saved_retirement(socket, iface, saved, current_boot)?.release()
    }

    pub fn prepare_saved_retirement(
        socket: &Path,
        iface: &str,
        saved: &Saved,
        current_boot: bool,
    ) -> io::Result<Retirement> {
        let scope = saved.removal_scope(iface)?;
        Retirement::prepare(socket, scope.routes(iface), true, current_boot)
    }

    pub fn vacant_retirement(
        socket: &Path,
        iface: &str,
        scope: &super::super::NativeNestedRemovalScope,
    ) -> io::Result<()> {
        Retirement::prepare(socket, scope.routes(iface), false, false).map(drop)
    }

    pub fn preflight_mtu(
        outer: &NestedOuter,
        endpoint: IpAddr,
        cfg: &Value,
    ) -> io::Result<nested::OuterPeer> {
        let (_, outer_mtu, peer) = facts(outer, endpoint)?;
        nested::mtu(cfg, outer_mtu, endpoint)?;
        Ok(peer)
    }

    pub fn verified_mtu(
        &self,
        expected: &NestedOuter,
        endpoint: IpAddr,
        mark: u32,
        cfg: &Value,
    ) -> io::Result<(u16, nested::OuterPeer)> {
        let stale = || invalid("ядро не подтвердило действующий MTU и внешний путь вложенного AWG");
        if &self.outer != expected
            || self.routes.endpoint != endpoint
            || self.routes.mark()? != mark
            || receipt(&self.path, &self.routes.iface)?.as_ref() != Some(&self.routes)
        {
            return Err(stale());
        }
        let (source, outer_mtu, peer) = facts(expected, endpoint)?;
        if self.routes.source != source || outer_mtu != self.outer_mtu {
            return Err(stale());
        }
        self.routes.verify_installed(&ip)?;
        self.verify_path()?;
        let mtu = numeric(
            &Path::new("/sys/class/net")
                .join(&self.routes.iface)
                .join("mtu"),
        )?;
        if mtu != self.mtu || mtu != nested::mtu(cfg, outer_mtu, endpoint)? {
            return Err(stale());
        }
        Ok((u16::try_from(mtu).map_err(|_| stale())?, peer))
    }

    pub fn snapshot(&self) -> Saved {
        Saved {
            outer: self.outer.clone(),
            routes: self.routes.clone(),
            mtu: self.mtu,
            outer_mtu: self.outer_mtu,
        }
    }
    pub fn resume(socket: &Path, iface: &str, saved: Saved) -> io::Result<Self> {
        let path = socket.with_extension("n2s-nested.json");
        saved.routes.validate(iface)?;
        let table = lock_table(socket, &saved.routes)?;
        if saved.outer.iface != saved.routes.outer
            || receipt(&path, iface)?.as_ref() != Some(&saved.routes)
        {
            return Err(invalid("владелец маршрутов вложенного клиента изменился"));
        }
        Ok(Self {
            _table: table,
            path,
            routes: saved.routes,
            outer: saved.outer,
            mtu: saved.mtu,
            outer_mtu: saved.outer_mtu,
        })
    }
    pub fn recover(socket: &Path, iface: &str) -> io::Result<()> {
        let path = socket.with_extension("n2s-nested.json");
        if let Some(old) = receipt(&path, iface)? {
            let _table = lock_table(socket, &old)?;
            release(&path, &old)?;
        }
        Ok(())
    }
    pub fn prepare(
        socket: &Path,
        iface: &str,
        outer: NestedOuter,
        endpoint: IpAddr,
        cfg: &Value,
    ) -> io::Result<Self> {
        let (source, outer_mtu, _) = facts(&outer, endpoint)?;
        let mtu = nested::mtu(cfg, outer_mtu, endpoint)?;
        let routes = Routes {
            iface: iface.into(),
            outer: outer.iface.clone(),
            endpoint,
            source,
        };
        routes.validate(iface)?;
        let table = lock_table(socket, &routes)?;
        check_names(&routes)?;
        routes.reconcile(false, false, &ip)?;
        let path = socket.with_extension("n2s-nested.json");
        let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
        serde_json::to_writer(&mut file, &routes)?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist_noclobber(&path).map_err(|e| e.error)?;
        let n = Self {
            _table: table,
            path,
            outer,
            routes,
            mtu,
            outer_mtu,
        };
        if let Err(failure) = n.apply() {
            n.release()?;
            return Err(failure);
        }
        Ok(n)
    }
    fn apply(&self) -> io::Result<()> {
        if receipt(&self.path, &self.routes.iface)?.as_ref() != Some(&self.routes) {
            return Err(invalid("не подтверждено владение маршрутом вложенного AWG"));
        }
        check_names(&self.routes)?;
        self.routes.reconcile(true, true, &ip)?;
        self.verify_path()
    }
    fn verify_path(&self) -> io::Result<()> {
        let family = if self.routes.endpoint.is_ipv4() {
            "-4"
        } else {
            "-6"
        };
        let resolved = ip(&[
            family,
            "route",
            "get",
            &self.routes.endpoint.to_string(),
            "mark",
            &format!("0x{:x}", self.routes.mark()?),
        ])?;
        let first: Vec<_> = resolved
            .lines()
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .collect();
        if !first
            .windows(2)
            .any(|w| w == ["dev", self.routes.outer.as_str()])
        {
            return Err(invalid(
                "ядро не подтвердило выбор внешнего туннеля для UDP",
            ));
        }
        Ok(())
    }
    pub fn repair(&self) -> io::Result<()> {
        let (source, outer_mtu, _) = facts(&self.outer, self.routes.endpoint)?;
        if self.routes.source != source || outer_mtu != self.outer_mtu {
            return Err(invalid(
                "изменились адрес или MTU внешнего AWG, требуется переподключение",
            ));
        }
        self.apply()?;
        let mtu = Path::new("/sys/class/net")
            .join(&self.routes.iface)
            .join("mtu");
        if numeric(&mtu)? != self.mtu {
            ip(&[
                "link",
                "set",
                "dev",
                &self.routes.iface,
                "mtu",
                &self.mtu.to_string(),
            ])?;
        }
        Ok(())
    }
    pub fn release(&self) -> io::Result<()> {
        release(&self.path, &self.routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::nested::tests::{routes, Fib};
    use std::cell::RefCell;

    fn write_sidecar(path: &Path, routes: &Routes) {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        serde_json::to_writer(file, routes).unwrap();
    }

    #[test]
    fn native_nested_retirement_replays_companion_after_each_accepted_write() {
        for interrupted in 0..7 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("awg1.n2s-nested.json");
            let expected = routes();
            write_sidecar(&path, &expected);
            let fib = RefCell::new(Fib::default());
            let run = |args: &[&str]| fib.borrow_mut().run(args);
            expected.reconcile(true, true, &run).unwrap();
            fib.borrow_mut().fail_after = Some(7 + interrupted);

            assert!(release_routes(&path, &expected, &run).is_err());
            assert_eq!(
                receipt(&path, &expected.iface).unwrap().as_ref(),
                Some(&expected)
            );
            release_routes(&path, &expected, &run).unwrap();
            assert!(!path.exists());
            expected.verify_retirement(false, &run).unwrap();
            release_routes(&path, &expected, &run).unwrap();
            assert_eq!(fib.borrow().writes.len(), 14);
        }
    }

    #[test]
    fn native_nested_retirement_rejects_replaced_and_unproved_route_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("awg1.n2s-nested.json");
        let expected = routes();
        let mut foreign = expected.clone();
        foreign.outer = "awg2".into();
        write_sidecar(&path, &foreign);
        assert!(release_routes(&path, &expected, &|_| panic!(
            "foreign receipt reached kernel"
        ))
        .is_err());
        assert_eq!(receipt(&path, &expected.iface).unwrap(), Some(foreign));
        fs::remove_file(&path).unwrap();

        let fib = RefCell::new(Fib::default());
        let run = |args: &[&str]| fib.borrow_mut().run(args);
        expected.reconcile(true, true, &run).unwrap();
        assert!(release_routes(&path, &expected, &run).is_err());
        assert_eq!(fib.borrow().writes.len(), 7);
        expected.verify_installed(&run).unwrap();
    }

    #[test]
    fn previous_boot_nested_retirement_can_only_remove_a_vacant_companion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("awg1.n2s-nested.json");
        let expected = routes();
        write_sidecar(&path, &expected);
        let fib = RefCell::new(Fib::default());
        let run = |args: &[&str]| fib.borrow_mut().run(args);
        expected.reconcile(true, true, &run).unwrap();
        assert!(release_routes_on_boot(&path, &expected, &run, false).is_err());
        assert_eq!(
            receipt(&path, &expected.iface).unwrap().as_ref(),
            Some(&expected)
        );
        assert_eq!(fib.borrow().writes.len(), 7);
        expected.verify_installed(&run).unwrap();

        *fib.borrow_mut() = Fib::default();
        release_routes_on_boot(&path, &expected, &run, false).unwrap();
        assert!(!path.exists());
        assert!(fib.borrow().writes.is_empty());
    }
}
