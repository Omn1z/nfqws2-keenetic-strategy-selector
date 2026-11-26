//! Immutable path lookup for Entware and native OpenWrt installations.
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Entware,
    OpenWrt,
}

macro_rules! paths {
    ($($key:ident, $name:literal, $entware:literal, $openwrt:literal;)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Key { $($key),* }
        impl Key {
            pub fn from_name(name: &str) -> Option<Self> {
                match name { $($name => Some(Self::$key),)* _ => None }
            }
        }
        const PATHS: &[(&str, &str)] = &[$(($entware, $openwrt)),*];
    };
}

paths! {
    DataDir, "data_dir", "/opt/etc/nfqws2-strategy", "/etc/nfqws2-strategy";
    Nfqws2Conf, "nfqws2_conf", "/opt/etc/nfqws2/nfqws2.conf", "/etc/nfqws2/nfqws2.conf";
    Nfqws2Bin, "nfqws2_bin", "/opt/usr/bin/nfqws2", "/usr/bin/nfqws2";
    Nfqws2Dir, "nfqws2_dir", "/opt/etc/nfqws2", "/etc/nfqws2";
    Nfqws2ListsDir, "nfqws2_lists_dir", "/opt/etc/nfqws2/lists", "/etc/nfqws2/lists";
    Nfqws2LuaDir, "nfqws2_lua_dir", "/opt/etc/nfqws2/lua", "/etc/nfqws2/lua";
    Nfqws2BlobsDir, "nfqws2_blobs_dir", "/opt/etc/nfqws2/blobs", "/etc/nfqws2/blobs";
    Nfqws2Init, "nfqws2_init", "/opt/etc/init.d/S51nfqws2", "/etc/init.d/nfqws2-keenetic";
    Nfqws2Pid, "nfqws2_pid", "/opt/var/run/nfqws2.pid", "/var/run/nfqws2.pid";
    StrategyBin, "strategy_bin", "/opt/usr/bin/n2s", "/usr/bin/n2s";
    ModuleDir, "module_dir", "/opt/lib/nfqws2-strategy/modules", "/usr/lib/nfqws2-strategy/modules";
    StrategyOldBin, "strategy_old_bin", "/opt/usr/bin/nfqws2-strategy", "/usr/bin/nfqws2-strategy";
    StrategyInit, "strategy_init", "/opt/etc/init.d/S52nfqws2-strategy", "/etc/init.d/nfqws2-strategy";
    StrategyRunDir, "strategy_run_dir", "/opt/var/run", "/var/run";
    StrategyLogDir, "strategy_log_dir", "/opt/var/log", "/var/log";
    AwgEngineDir, "awg_engine_dir", "/opt/usr/bin", "/usr/bin";
    AwgConfigDir, "awg_config_dir", "/opt/etc/amnezia/amneziawg", "/etc/amnezia/amneziawg";
    AwgSetDir, "awg_set_dir", "/opt/etc/nfqws2-strategy", "/etc/nfqws2-strategy";
    AwgListsDir, "awg_lists_dir", "/opt/etc/nfqws2/lists", "/etc/nfqws2/lists";
    AwgHook, "awg_hook", "/opt/etc/ndm/netfilter.d/90-awg2.sh", "/etc/nfqws2-strategy/90-awg2.sh";
    AwgMultiHook, "awg_multi_hook", "/opt/etc/ndm/netfilter.d/91-awg2-multi.sh", "/etc/nfqws2-strategy/91-awg2-multi.sh";
    AwgFw4Hook, "awg_fw4_hook", "/opt/etc/ndm/netfilter.d/92-awg2-fw4.sh", "/etc/nfqws2-strategy/92-awg2-fw4.sh";
    AwgLegacyWatchdog, "awg_legacy_watchdog", "/opt/etc/init.d/S53awg1-watchdog", "";
    NfqwsBypass, "nfqws_bypass", "/opt/etc/nfqws2/nfqws-bypass.sh", "/etc/nfqws2/nfqws-bypass.sh";
    NfqwsBypassFw4, "nfqws_bypass_fw4", "", "/etc/nfqws2/nfqws-bypass-fw4.sh";
    PortForwardHook, "port_forward_hook", "/opt/etc/ndm/netfilter.d/91-n2s-port-forward.sh", "/etc/nfqws2-strategy/91-n2s-port-forward.sh";
    DnsHook, "dns_hook", "/opt/etc/ndm/netfilter.d/93-nfqws-dns.sh", "/etc/nfqws2-strategy/93-nfqws-dns.sh";
    ArpSpoofHook, "arp_spoof_hook", "/opt/etc/ndm/netfilter.d/92-n2s-arp-spoof.sh", "/etc/nfqws2-strategy/92-n2s-arp-spoof.sh";
    TcpdumpOptDir, "tcpdump_opt_dir", "/opt", "/opt";
    TcpdumpSystemDir, "tcpdump_system_dir", "/usr/sbin", "/usr/sbin";
    EtcDir, "etc_dir", "/etc", "/etc";
    AuthEtcDir, "auth_etc_dir", "/opt/etc", "/etc";
    TlsCertDir, "tls_cert_dir", "/opt/etc/ssl/certs", "/etc/ssl/certs";
    EntwareOpkg, "entware_opkg", "/opt/bin/opkg", "/opt/bin/opkg";
}

pub struct Resolver {
    platform: Platform,
    paths: [PathBuf; PATHS.len()],
}

impl Resolver {
    pub fn current() -> &'static Self {
        static LIVE: OnceLock<Resolver> = OnceLock::new();
        LIVE.get_or_init(|| Self::new_at("/"))
    }

    pub fn new_at(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        let root = if root.as_os_str().is_empty() {
            Path::new("/")
        } else {
            root
        };
        let rooted = |name: &str| clean(&root.join(name.trim_start_matches('/')));
        let openwrt = rooted("etc/openwrt_release").exists() || rooted("etc/rc.common").exists();
        let mut paths = std::array::from_fn(|index| {
            let (entware, native) = PATHS[index];
            let name = if openwrt { native } else { entware };
            if name.is_empty() {
                PathBuf::new()
            } else {
                rooted(name)
            }
        });
        if openwrt {
            for (key, marker) in [
                (Key::AwgEngineDir, Some("amneziawg-go")),
                (Key::AwgConfigDir, None),
            ] {
                let native = &paths[key as usize];
                let legacy = rooted(PATHS[key as usize].0);
                let installed = |dir: &Path| match marker {
                    Some(bin) => dir.join(bin).is_file(),
                    None => dir.is_dir(),
                };
                if !installed(native) && installed(&legacy) {
                    paths[key as usize] = legacy;
                }
            }
        }
        Self {
            platform: if openwrt {
                Platform::OpenWrt
            } else {
                Platform::Entware
            },
            paths,
        }
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }
    pub fn path(&self, key: Key) -> &Path {
        &self.paths[key as usize]
    }
    pub fn join(&self, key: Key, parts: &[&str]) -> PathBuf {
        let mut path = self.path(key).to_owned();
        if !path.as_os_str().is_empty() {
            for part in parts {
                path.push(part.trim_start_matches(std::path::is_separator));
            }
            path = clean(&path);
        }
        path
    }
}

fn clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => (),
            Component::ParentDir if out.file_name().is_some() => {
                out.pop();
            }
            Component::ParentDir if out.has_root() => (),
            _ => out.push(part.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}
