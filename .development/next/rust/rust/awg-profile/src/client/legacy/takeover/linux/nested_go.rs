//! The inherited Go process and its original transport sidecar are read separately.
use super::{changed, expected_identity, number, reported_identity, socket_name, Receipt};
use crate::client::{
    conf,
    legacy::matching_peer,
    linux::{check_nested_names, lock_table, nested_ip as ip},
    nested, NestedMtu, NestedOuter, Spec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const NOTE_LIMIT: u64 = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    outer_iface: String,
    endpoint: IpAddr,
    mtu: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Nested {
    routes: nested::Routes,
    endpoint: SocketAddr,
    mtu: u16,
    sidecar: [u8; 32],
    outer: Box<Receipt>,
    outer_peer: NestedOuter,
    outer_identity: [u8; 32],
    outer_mtu: u64,
}

fn path(root: &Path, iface: &str) -> PathBuf {
    root.join(socket_name(iface))
        .with_extension("double-tunnel.json")
}

fn read(root: &Path, iface: &str) -> io::Result<(Transport, [u8; 32])> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path(root, iface))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.len() > NOTE_LIMIT
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
    {
        return Err(changed());
    }
    let mut bytes = Vec::new();
    file.take(NOTE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > NOTE_LIMIT {
        return Err(changed());
    }
    let state = serde_json::from_slice(&bytes).map_err(|_| changed())?;
    Ok((state, Sha256::digest(&bytes).into()))
}

fn live_endpoint(bytes: &[u8]) -> io::Result<SocketAddr> {
    let mut state = serde_json::json!({});
    crate::runtime::uapi(bytes, crate::now(), &mut state)?;
    crate::client::supervisor::live_transport_endpoint(&state).ok_or_else(changed)
}

fn verified_route(
    routes: &nested::Routes,
    run: &dyn Fn(&[&str]) -> io::Result<String>,
) -> io::Result<()> {
    routes.verify_installed(run)?;
    let address = routes.endpoint.to_string();
    let source = routes.source.to_string();
    let mark = format!("{:#x}", routes.mark()?);
    let table = routes.table()?.to_string();
    let family = if routes.endpoint.is_ipv4() {
        "-4"
    } else {
        "-6"
    };
    let row = run(&["-o", family, "route", "get", &address, "mark", &mark])?;
    let words: Vec<_> = row
        .lines()
        .next()
        .ok_or_else(changed)?
        .split_ascii_whitespace()
        .collect();
    for (field, expected) in [
        ("dev", routes.outer.as_str()),
        ("table", table.as_str()),
        ("src", source.as_str()),
    ] {
        let mut seen = words.windows(2).filter(|word| word[0] == field);
        if seen.next().is_none_or(|word| word[1] != expected) || seen.next().is_some() {
            return Err(changed());
        }
    }
    Ok(())
}

impl Nested {
    pub(super) fn capture(
        root: &Path,
        source: &Spec,
        source_reply: &[u8],
        outer: Receipt,
        outer_spec: &Spec,
    ) -> io::Result<Self> {
        let (value, sidecar) = read(root, &source.iface)?;
        let endpoint = live_endpoint(source_reply)?;
        if matching_peer(source, source_reply).is_none()
            || outer.iface != value.outer_iface
            || outer.nested.is_some()
            || !outer.matches_spec(outer_spec)
            || endpoint.ip() != value.endpoint
        {
            return Err(changed());
        }
        let family = if endpoint.is_ipv4() { "-4" } else { "-6" };
        let address = nested::source(
            &ip(&["-o", family, "address", "show", "dev", &outer.iface])?,
            endpoint.ip(),
        )?;
        let routes = nested::Routes {
            iface: source.iface.clone(),
            outer: outer.iface.clone(),
            endpoint: endpoint.ip(),
            source: address,
        };
        let nested = Self {
            outer_mtu: number(&root.join("sys/class/net").join(&outer.iface).join("mtu"))?,
            routes,
            endpoint,
            mtu: value.mtu,
            sidecar,
            outer: Box::new(outer),
            outer_peer: NestedOuter::from_spec(outer_spec)?,
            outer_identity: expected_identity(outer_spec).ok_or_else(changed)?,
        };
        nested.installed(root, source_reply, nested.mtu_policy(source)?, true)?;
        Ok(nested)
    }

    pub(super) fn outer_iface(&self) -> &str {
        &self.routes.outer
    }

    pub(super) fn mark(&self) -> io::Result<u32> {
        self.routes.mark()
    }

    pub(super) fn observe(
        &self,
        root: &Path,
        response: &[u8],
        inner: &Spec,
        outer: &Spec,
        endpoint: SocketAddr,
        trial: bool,
    ) -> io::Result<crate::RoutedNestedTransport> {
        if endpoint != self.endpoint || !self.outer.matches_spec(outer) {
            return Err(changed());
        }
        let (outer_endpoint, effective_mtu) =
            self.installed(root, response, self.mtu_policy(inner)?, trial)?;
        Ok(crate::RoutedNestedTransport {
            outer_endpoint,
            peer: crate::RoutedMtuPeer {
                iface: self.routes.iface.clone(),
                outer_id: outer.id.clone(),
                outer_iface: self.routes.outer.clone(),
                endpoint,
                effective_mtu,
                socket_mark: self.mark()?,
            },
        })
    }

    pub(super) fn prepare_retirement(&self, root: &Path) -> io::Result<fs::File> {
        let socket = root.join(socket_name(&self.routes.iface));
        let lock = lock_table(&socket, &self.routes)?;
        check_nested_names(&self.routes)?;
        match self.verify_sidecar(root) {
            Ok(()) => self.routes.verify_retirement(true, &ip)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.routes.verify_retirement(false, &ip)?;
            }
            Err(error) => return Err(error),
        }
        Ok(lock)
    }

    pub(super) fn retire(&self, root: &Path, _hold: fs::File) -> io::Result<()> {
        match self.verify_sidecar(root) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return self.routes.verify_retirement(false, &ip);
            }
            Err(error) => return Err(error),
        }
        self.routes.reconcile(true, false, &ip)?;
        self.routes.verify_retirement(false, &ip)?;
        self.verify_sidecar(root)?;
        let sidecar = path(root, &self.routes.iface);
        fs::remove_file(&sidecar)?;
        fs::File::open(sidecar.parent().ok_or_else(changed)?)?.sync_all()
    }

    pub(super) fn previous_boot_vacant(&self, root: &Path) -> io::Result<()> {
        check_nested_names(&self.routes)?;
        match fs::symlink_metadata(path(root, &self.routes.iface)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.routes.verify_retirement(false, &ip)
            }
            _ => Err(changed()),
        }
    }

    pub(super) fn mtu_policy(&self, spec: &Spec) -> io::Result<NestedMtu> {
        let cfg = conf::parse(&spec.conf, 0)?;
        let policy = NestedMtu::from_config(&cfg, self.endpoint.ip())?;
        if policy.effective(self.outer_mtu)? != u64::from(self.mtu) {
            return Err(changed());
        }
        Ok(policy)
    }

    fn installed(
        &self,
        root: &Path,
        response: &[u8],
        policy: NestedMtu,
        trial: bool,
    ) -> io::Result<(SocketAddr, u16)> {
        let (outer_endpoint, outer_mtu) = self.verify_transport(root, response)?;
        let mtu = policy.effective(outer_mtu)?;
        if (trial && outer_mtu != self.outer_mtu) || number(&self.mtu_path(root))? != mtu {
            return Err(changed());
        }
        verified_route(&self.routes, &ip)?;
        Ok((outer_endpoint, mtu.try_into().map_err(|_| changed())?))
    }

    pub(super) fn verify_repairable(
        &self,
        root: &Path,
        response: &[u8],
        policy: NestedMtu,
    ) -> io::Result<()> {
        let (_, outer_mtu) = self.verify_transport(root, response)?;
        policy.effective(outer_mtu)?;
        self.routes.verify_retirement(true, &ip)
    }

    pub(super) fn repair(
        &self,
        root: &Path,
        inner: &Receipt,
        response: &[u8],
        policy: NestedMtu,
    ) -> io::Result<()> {
        let _hold = lock_table(&root.join(socket_name(&self.routes.iface)), &self.routes)?;
        let (_, outer_mtu) = self.verify_transport(root, response)?;
        let mtu = policy.effective(outer_mtu)?;
        inner.owner(root)?;
        self.routes.reconcile(true, true, &ip)?;
        verified_route(&self.routes, &ip)?;
        if number(&self.mtu_path(root))? != mtu {
            self.outer.owner(root)?;
            if self.outer_mtu(root)? != outer_mtu {
                return Err(changed());
            }
            inner.owner(root)?;
            ip(&[
                "link",
                "set",
                "dev",
                &self.routes.iface,
                "mtu",
                &mtu.to_string(),
            ])?;
        }
        Ok(())
    }

    fn mtu_path(&self, root: &Path) -> PathBuf {
        root.join("sys/class/net")
            .join(&self.routes.iface)
            .join("mtu")
    }

    fn outer_mtu(&self, root: &Path) -> io::Result<u64> {
        number(
            &root
                .join("sys/class/net")
                .join(&self.routes.outer)
                .join("mtu"),
        )
    }

    fn verify_transport(&self, root: &Path, response: &[u8]) -> io::Result<(SocketAddr, u64)> {
        self.verify_sidecar(root)?;
        check_nested_names(&self.routes)?;
        if live_endpoint(response)? != self.endpoint
            || self.outer.nested.is_some()
            || self.outer.iface != self.routes.outer
            || self.outer_peer.iface != self.routes.outer
        {
            return Err(changed());
        }
        self.outer.owner(root)?;
        let outer = &self.routes.outer;
        let family = if self.endpoint.is_ipv4() { "-4" } else { "-6" };
        let addresses = ip(&["-o", family, "address", "show", "dev", outer])?;
        if nested::source(&addresses, self.endpoint.ip())? != self.routes.source {
            return Err(changed());
        }
        let probe = crate::runtime::request(
            &root.join(socket_name(outer)),
            b"get=1\n\n",
            Duration::from_secs(1),
            None,
        )?;
        if reported_identity(&probe) != Some(self.outer_identity)
            || !self.outer.matches_transport(&probe)
        {
            return Err(changed());
        }
        let peer = nested::check_outer_peer(
            &probe,
            &self.outer_peer.peer_hex,
            self.endpoint.ip(),
            crate::now(),
        )?;
        let mtu = self.outer_mtu(root)?;
        self.outer.owner(root)?;
        Ok((peer.endpoint.ok_or_else(changed)?, mtu))
    }

    fn verify_sidecar(&self, root: &Path) -> io::Result<()> {
        let (found, stamp) = read(root, &self.routes.iface)?;
        if stamp != self.sidecar
            || found.outer_iface != self.routes.outer
            || found.endpoint != self.routes.endpoint
            || found.mtu != self.mtu
        {
            return Err(changed());
        }
        self.routes.validate(&self.routes.iface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::nested::tests::{routes, Fib};
    use std::cell::RefCell;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn go_nested_sidecar_requires_exact_regular_private_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path(), "awg7");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let original = br#"{"outer_iface":"awg9","endpoint":"198.51.100.10","mtu":1360}"#;
        fs::write(&file, original).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let (receipt, digest) = read(dir.path(), "awg7").unwrap();
        assert_eq!(receipt.outer_iface, "awg9");
        assert_eq!(receipt.endpoint, "198.51.100.10".parse::<IpAddr>().unwrap());
        assert_eq!(receipt.mtu, 1360);
        assert_eq!(digest.as_slice(), &Sha256::digest(original)[..]);
        let linked = path(dir.path(), "awg6");
        fs::hard_link(&file, &linked).unwrap();
        assert!(read(dir.path(), "awg7").is_err());
        fs::remove_file(linked).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(dir.path(), "awg7").is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = path(dir.path(), "awg8");
        symlink(&file, alias).unwrap();
        assert!(read(dir.path(), "awg8").is_err());
        fs::write(&file, [b' '; NOTE_LIMIT as usize + 1]).unwrap();
        assert!(read(dir.path(), "awg7").is_err());
    }

    #[test]
    fn go_route_requires_both_family_guards_and_exact_marked_path() {
        let route = routes();
        let fib = RefCell::new(Fib::default());
        let installed = |a: &[&str]| fib.borrow_mut().run(a);
        let marked_path = |fields: &'static str| {
            move |a: &[&str]| {
                if a.contains(&"get") {
                    assert_eq!(
                        a,
                        [
                            "-o",
                            "-4",
                            "route",
                            "get",
                            "192.0.2.1",
                            "mark",
                            "0xa0000001"
                        ]
                    );
                    Ok(fields.to_owned())
                } else {
                    installed(a)
                }
            }
        };
        let exact = marked_path("192.0.2.1 dev awg0 table 829 src 10.0.0.8 uid 0\n    cache");
        assert!(verified_route(&route, &exact).is_err());
        route.reconcile(true, true, &installed).unwrap();
        verified_route(&route, &exact).unwrap();
        for wrong in [
            "192.0.2.1 dev wan table 829 src 10.0.0.8",
            "192.0.2.1 dev awg0 table 830 src 10.0.0.8",
            "192.0.2.1 dev awg0 table 829 src 10.0.0.9",
            "192.0.2.1 dev awg0 table 829 src 10.0.0.8 dev awg0",
            "192.0.2.1 dev awg0 src 10.0.0.8\n    table 829",
        ] {
            assert!(verified_route(&route, &marked_path(wrong)).is_err());
        }
        installed(&["-6", "rule", "del", "pref", "61"]).unwrap();
        assert!(verified_route(&route, &exact).is_err());
    }
}
