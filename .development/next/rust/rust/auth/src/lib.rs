//! Panel authentication against the router's existing account databases.
mod accounts;
mod password;
mod sessions;

use nfqws2_config::{Key, Resolver};
use nfqws2_store::Store;
use serde_json::{Map, Value};
use sessions::Sessions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const SETTINGS: &str = "settings.json";
const TTL_SECONDS: u64 = 7 * 24 * 3600;

pub struct Auth {
    store: Store,
    databases: Vec<PathBuf>,
    enabled: AtomicBool,
    forced_off: bool,
    sessions: Sessions,
}

fn settings(store: &Store) -> io::Result<Map<String, Value>> {
    match store.read(SETTINGS) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Map::new()),
        result => result,
    }
}

impl Auth {
    pub fn open(data_dir: &Path, router_root: &Path, forced_off: bool) -> io::Result<Self> {
        let store = Store::open(data_dir)?;
        let config = settings(&store)?;
        let enabled = config
            .get("auth_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let resolver = Resolver::new_at(router_root);
        let mut databases = Vec::new();
        for file in ["shadow", "passwd"] {
            for dir in [Key::AuthEtcDir, Key::EtcDir] {
                let path = resolver.path(dir).join(file);
                if !databases.contains(&path) {
                    databases.push(path);
                }
            }
        }
        Ok(Self {
            store,
            databases,
            enabled: AtomicBool::new(enabled),
            forced_off,
            sessions: Sessions::new(Duration::from_secs(TTL_SECONDS)),
        })
    }

    pub fn enabled(&self) -> bool {
        !self.forced_off && self.enabled.load(Ordering::Acquire)
    }

    pub fn forced_off(&self) -> bool {
        self.forced_off
    }

    pub fn set_enabled(&self, enabled: bool) -> io::Result<()> {
        if self.forced_off {
            return Ok(());
        }
        self.store.transaction(|tx| {
            // Reload under the store lock to preserve unrelated panel settings.
            let mut config = settings(&self.store)?;
            config.insert("auth_enabled".into(), Value::Bool(enabled));
            tx.save(SETTINGS, &config)?;
            self.enabled.store(enabled, Ordering::Release);
            Ok(())
        })
    }

    pub fn login(&self, user: &str, password: &str) -> io::Result<Option<String>> {
        if accounts::verify(&self.databases, user, password) {
            self.sessions.issue().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Call while holding the store transaction that restored settings.json.
    pub fn reload_after_restore(&self) -> io::Result<()> {
        self.sessions.clear();
        self.enabled.store(true, Ordering::Release);
        let map = settings(&self.store)?;
        self.enabled.store(
            map.get("auth_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            Ordering::Release,
        );
        Ok(())
    }

    pub fn valid_session(&self, token: &str) -> bool {
        self.sessions.valid(token)
    }

    pub fn logout(&self, token: &str) {
        self.sessions.remove(token)
    }

    /// The caller supplies the routed path without the query string.
    pub fn allows(&self, path: &str, token: &str) -> bool {
        !path.starts_with("/api/")
            || matches!(path, "/api/auth/status" | "/api/auth/login")
            || !self.enabled()
            || self.valid_session(token)
    }
}

pub fn session_token(cookie_header: &str) -> &str {
    cookie_header
        .split(';')
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == "n2s_sess").then(|| {
                value
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(value)
            })
        })
        .unwrap_or("")
}

pub fn login_cookie(token: &str) -> String {
    format!("n2s_sess={token}; Path=/; Max-Age={TTL_SECONDS}; HttpOnly; SameSite=Lax")
}

pub const LOGOUT_COOKIE: &str = "n2s_sess=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax";

#[cfg(test)]
mod tests;
