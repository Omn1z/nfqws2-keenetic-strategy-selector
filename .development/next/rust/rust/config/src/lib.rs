//! Router layout, runtime configuration and literal shell configuration parsing.
mod diagnostics;
mod https_strategy;
pub use https_strategy::validate_https_strategy;
mod paths;
pub mod service_profiles;
pub use diagnostics::{analyze_paths, Analysis, Diagnostic};
mod shell;

pub use paths::{Key, Platform, Resolver};
use serde::Serialize;
pub use shell::{
    literal_shell_config_value, managed_service_config_range, normalize_wan_interfaces,
    replace_nfqws_args, wan_interfaces_from_conf,
};
use std::io;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Config {
    pub listen_addr: String,
    pub data_dir: String,
    pub nfqws2_conf: String,
    pub nfqws_bin: String,
    pub wan_ifaces: Vec<String>,
    #[serde(skip)]
    pub awg_detect_wan: bool,
    pub base_args: Option<Vec<String>>,
    pub system_blobs_dir: String,
    pub lua_dir: String,
    pub version: String,
    pub repo: String,
    pub init_script: String,
    pub nfqws2_init: String,
    pub nfqws2_repo: String,
    pub nfqws2_pkg: String,
    pub first_queue: i32,
    pub port_base: i32,
    pub ports_per_worker: i32,
    pub main_queue: i32,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_resolver(Resolver::current())
    }
}

impl Config {
    pub fn from_resolver(resolver: &Resolver) -> Self {
        let path = |key| resolver.path(key).to_string_lossy().into_owned();
        Self {
            listen_addr: ":8090".into(),
            data_dir: path(Key::DataDir),
            nfqws2_conf: path(Key::Nfqws2Conf),
            nfqws_bin: path(Key::Nfqws2Bin),
            wan_ifaces: vec!["eth3".into()],
            awg_detect_wan: resolver.platform() == Platform::OpenWrt,
            base_args: None,
            system_blobs_dir: path(Key::Nfqws2BlobsDir),
            lua_dir: path(Key::Nfqws2LuaDir),
            version: String::new(),
            repo: String::new(),
            init_script: path(Key::StrategyInit),
            nfqws2_init: path(Key::Nfqws2Init),
            nfqws2_repo: "nfqws/nfqws2-keenetic".into(),
            nfqws2_pkg: "nfqws2-keenetic".into(),
            first_queue: 200,
            port_base: 50000,
            ports_per_worker: 200,
            main_queue: 300,
        }
    }

    pub fn load(version: &str, repo: &str) -> (Self, Option<io::Error>) {
        Self::load_at(Resolver::current(), version, repo, |key| {
            std::env::var_os(key).map(|value| value.to_string_lossy().into_owned())
        })
    }

    pub fn load_at(
        resolver: &Resolver,
        version: &str,
        repo: &str,
        getenv: impl Fn(&str) -> Option<String>,
    ) -> (Self, Option<io::Error>) {
        let mut config = Self::from_resolver(resolver);
        // The existing CLI reads the installed config before applying path overrides.
        let warning = config.load_from_nfqws2_conf().err();
        for (key, dest) in [
            ("N2S_DATA", &mut config.data_dir),
            ("N2S_LISTEN", &mut config.listen_addr),
            ("N2S_INIT", &mut config.init_script),
            ("N2S_NFQWS2_CONF", &mut config.nfqws2_conf),
            ("N2S_NFQWS_BIN", &mut config.nfqws_bin),
            ("N2S_NFQWS2_INIT", &mut config.nfqws2_init),
            ("N2S_LUA_DIR", &mut config.lua_dir),
            ("N2S_SYSTEM_BLOBS_DIR", &mut config.system_blobs_dir),
        ] {
            if let Some(value) = getenv(key).filter(|v| !v.is_empty()) {
                *dest = value;
            }
        }
        config.version = version.into();
        config.repo = repo.into();
        (config, warning)
    }

    pub fn load_from_nfqws2_conf(&mut self) -> io::Result<()> {
        let bytes = std::fs::read(&self.nfqws2_conf)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.nfqws2_conf)))?;
        self.apply_nf_config(&String::from_utf8_lossy(&bytes))
    }

    /// An empty list delegates endpoint validation to live OpenWrt netifd.
    pub fn awg_wan_ifaces(&self) -> &[String] {
        if self.awg_detect_wan {
            &[]
        } else {
            &self.wan_ifaces
        }
    }

    pub fn apply_nf_config(&mut self, source: &str) -> io::Result<()> {
        if let Some(ifaces) = wan_interfaces_from_conf(source)?.filter(|v| !v.is_empty()) {
            self.wan_ifaces = ifaces;
            self.awg_detect_wan = false;
        }
        let mut rest = source;
        while !rest.is_empty() {
            if let Some(tail) = rest
                .trim_start_matches([' ', '\t'])
                .strip_prefix("NFQWS_BASE_ARGS=\"")
            {
                if let Some((value, _)) = tail.split_once('"') {
                    let args: Vec<_> = value
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.starts_with('#'))
                        .flat_map(str::split_whitespace)
                        .map(str::to_owned)
                        .collect();
                    self.base_args = (!args.is_empty()).then_some(args);
                    break;
                }
            }
            rest = rest.split_once('\n').map_or("", |(_, next)| next);
        }
        Ok(())
    }
}

/// Builds the environment for one native KeeneticOS child. Other variables,
/// including their original order, are preserved without changing the parent.
pub fn native_env<'a>(entries: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    entries
        .into_iter()
        .filter(|entry| {
            !matches!(
                entry.split('=').next(),
                Some("LD_LIBRARY_PATH" | "LD_PRELOAD")
            )
        })
        .chain(std::iter::once("LD_LIBRARY_PATH=/lib:/usr/lib"))
        .collect()
}
