use serde::{Deserialize, Serialize};
pub mod fallback;
use std::{collections::BTreeMap, io, net::IpAddr};

/// Largest target accepted by the first Rust helper protocol.
pub const OLD_POOL_LIMIT: i64 = 16;
pub const UPSTREAM_VERSION: &str = "1.11.2";

/// Format the byte counter as exposed by Go's Telegram status API.
pub fn human_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if value < 1024.0 {
            return format!("{value:.1}{unit}");
        }
        value /= 1024.0;
    }
    format!("{value:.1}TB")
}

pub fn local_link_host() -> String {
    // Connecting a UDP socket lets the kernel choose the route without
    // sending a packet, as in Go's localIPGuess.
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| {
            socket.connect((std::net::Ipv4Addr::new(8, 8, 8, 8), 80))?;
            socket.local_addr()
        })
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub transport: String,
    pub enabled: bool,
    pub port: u16,
    pub secret: String,
    pub dc_redirects: Option<BTreeMap<i32, IpAddr>>,
    pub buffer_size: i64,
    pub pool_size: i64,
    pub proxy_protocol: bool,
    pub force_test_dc: bool,
    pub sni_fronting: bool,
    pub disable_secure: bool,
    pub cfproxy: bool,
    pub cfproxy_h2_media: bool,
    pub cfproxy_user_domain: String,
    pub cfproxy_worker_domain: String,
    pub cfproxy_user_domains: Option<Vec<String>>,
    pub cfproxy_worker_domains: Option<Vec<String>>,
    pub fake_tls_domain: String,
    pub link_host: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            transport: String::new(),
            enabled: false,
            port: 1433,
            secret: String::new(),
            dc_redirects: Some(BTreeMap::from([
                (2, IpAddr::from([149, 154, 167, 220])),
                (4, IpAddr::from([149, 154, 167, 220])),
            ])),
            buffer_size: 262144,
            pool_size: 4,
            proxy_protocol: false,
            force_test_dc: false,
            sni_fronting: false,
            disable_secure: false,
            cfproxy: true,
            cfproxy_h2_media: true,
            cfproxy_user_domain: String::new(),
            cfproxy_worker_domain: String::new(),
            cfproxy_user_domains: None,
            cfproxy_worker_domains: None,
            fake_tls_domain: String::new(),
            link_host: String::new(),
        }
    }
}
pub fn secret() -> io::Result<String> {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
fn domains(list: &mut Option<Vec<String>>, legacy: &mut String) -> io::Result<()> {
    let mut output = Vec::new();
    let entries = list.take().unwrap_or_else(|| vec![legacy.clone()]);
    for domain in entries
        .iter()
        .flat_map(|s| s.split([',', ';', ' ', '\t', '\r', '\n']))
        .filter(|s| !s.is_empty())
    {
        // These are the only non-ASCII characters whose Go simple lowercase
        // is ASCII and can pass the domain validator.
        let domain: String = domain
            .chars()
            .map(|ch| match ch {
                'İ' => 'i',
                'K' => 'k',
                _ => ch.to_ascii_lowercase(),
            })
            .collect();
        if !valid_domain(&domain) {
            return Err(invalid("неверное доменное имя TG WS"));
        }
        if !output.contains(&domain) {
            output.push(domain);
        }
    }
    *legacy = output.join(", ");
    *list = Some(output);
    Ok(())
}
pub fn valid_domain(v: &str) -> bool {
    v.len() <= 253
        && v.rsplit_once('.')
            .is_some_and(|(_, tld)| tld.len() >= 2 && tld.bytes().any(|c| c.is_ascii_alphabetic()))
        && v.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Config {
    pub fn native() -> Self {
        Self {
            transport: "direct_wss".into(),
            dc_redirects: None,
            cfproxy: false,
            cfproxy_h2_media: false,
            pool_size: 0,
            ..Default::default()
        }
    }
    pub fn normalize(&mut self) -> io::Result<()> {
        if self.port == 0 {
            self.port = 1433;
        }
        if self.buffer_size < 4096 {
            self.buffer_size = 262144;
        }
        self.pool_size = self.pool_size.max(0);
        if self.secret.is_empty() {
            self.secret = secret()?;
        }
        self.key()?;
        let redirects = self.dc_redirects.get_or_insert_with(Default::default);
        if redirects.keys().any(|dc| !matches!(dc, 1..=5 | 203)) {
            return Err(invalid("неизвестный DC"));
        }
        domains(
            &mut self.cfproxy_user_domains,
            &mut self.cfproxy_user_domain,
        )?;
        domains(
            &mut self.cfproxy_worker_domains,
            &mut self.cfproxy_worker_domain,
        )?;
        self.fake_tls_domain = self.fake_tls_domain.trim().into();
        if !self.fake_tls_domain.is_empty() && !valid_domain(&self.fake_tls_domain) {
            return Err(invalid("неверный домен Fake TLS"));
        }
        Ok(())
    }
    pub fn key(&self) -> io::Result<[u8; 16]> {
        if self.secret.len() != 32 || !self.secret.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid("secret должен содержать 32 hex-символа"));
        }
        let mut out = [0; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.secret[2 * i..2 * i + 2], 16).unwrap();
        }
        Ok(out)
    }
    fn worker_domains(&self) -> bool {
        self.cfproxy_worker_domains.as_ref().map_or_else(
            || !self.cfproxy_worker_domain.trim().is_empty(),
            |d| !d.is_empty(),
        )
    }
    fn configured_cf(&self) -> bool {
        self.cfproxy
            && self.cfproxy_user_domains.as_ref().map_or_else(
                || !self.cfproxy_user_domain.trim().is_empty(),
                |d| !d.is_empty(),
            )
    }
    pub fn configured_tls_relays(&self) -> bool {
        self.worker_domains() || self.cfproxy
    }
    pub fn uses_upstream_catalog(&self) -> bool {
        self.cfproxy && !self.configured_cf()
    }
    pub fn h2_media(&self) -> bool {
        self.cfproxy && self.cfproxy_h2_media && !self.disable_secure && !self.force_test_dc
    }
    pub fn uses_alternate_sni(&self) -> bool {
        self.sni_fronting && (self.pool_size > 0 || !self.transport.is_empty())
    }
    pub fn requires_go(&self) -> Vec<&'static str> {
        if self.transport.is_empty() || self.transport == "direct_wss" {
            Vec::new()
        } else {
            vec!["неизвестный транспорт"]
        }
    }
    pub fn link(&self, host: &str) -> String {
        let guessed;
        let host = if host.is_empty() {
            if self.link_host.is_empty() {
                guessed = local_link_host();
                &guessed
            } else {
                &self.link_host
            }
        } else {
            host
        };
        let secret = if self.fake_tls_domain.is_empty() {
            format!("dd{}", self.secret)
        } else {
            format!(
                "ee{}{}",
                self.secret,
                self.fake_tls_domain
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        let host = host
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"._-".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>();
        format!(
            "tg://proxy?server={host}&port={}&secret={secret}",
            self.port
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_inert_options_and_domain_validation_follow_saved_go_configuration() {
        let mut cfg = Config {
            pool_size: -4,
            cfproxy: false,
            sni_fronting: true,
            disable_secure: true,
            ..Config::default()
        };
        cfg.normalize().unwrap();
        assert_eq!(cfg.pool_size, 0);
        assert!(cfg.requires_go().is_empty());
        cfg.pool_size = 1;
        assert!(cfg.uses_alternate_sni() && cfg.requires_go().is_empty());
        cfg.cfproxy_worker_domains = Some(vec!["worker.example".into()]);
        assert!(cfg.requires_go().is_empty());
        cfg.cfproxy = true;
        assert!(cfg.uses_upstream_catalog() && cfg.requires_go().is_empty() && !cfg.h2_media());
        for domain in [
            "localhost",
            "192.0.2.1",
            "bad.example.",
            "x.c",
            "https://x.example",
            "bad.test:443",
            "bad..example",
        ] {
            cfg.cfproxy_worker_domains = Some(vec![domain.to_owned()]);
            assert!(cfg.normalize().is_err(), "{domain}");
        }
        for domain in ["one.example", "xn--p1ai.example", "A-1.Example"] {
            cfg.cfproxy_worker_domains = Some(vec![domain.to_owned()]);
            cfg.normalize().unwrap();
        }
    }

    #[test]
    fn legacy_cf_domain_lists_use_go_separators_and_simple_lowercase() {
        let mut cfg = Config {
            cfproxy_user_domain:
                "One.example,İ-K.example;Two.example\t THREE.example\r\nONE.example".into(),
            cfproxy_worker_domains: Some(vec!["K.worker.example\r\nİ.worker.example".into()]),
            ..Config::default()
        };
        cfg.normalize().unwrap();
        assert_eq!(
            cfg.cfproxy_user_domains.unwrap(),
            ["one.example", "i-k.example", "two.example", "three.example"]
        );
        assert_eq!(
            cfg.cfproxy_worker_domains.unwrap(),
            ["k.worker.example", "i.worker.example"]
        );

        for domain in [
            "one.example\u{a0}two.example",
            "one.example\u{b}two.example",
            "one.example\u{c}two.example",
            "one.example\u{2028}two.example",
            "ſ.example",
        ] {
            let mut cfg = Config {
                cfproxy_worker_domains: Some(vec![domain.into()]),
                ..Config::default()
            };
            assert!(cfg.normalize().is_err(), "{domain:?}");
        }
    }
    #[test]
    fn distinguishes_active_worker_overrides_from_inactive_cf_options() {
        let mut cfg = Config {
            cfproxy: false,
            cfproxy_user_domain: "public.example".into(),
            ..Default::default()
        };
        cfg.normalize().unwrap();
        assert!(cfg.requires_go().is_empty());
        cfg.cfproxy_worker_domains = None;
        cfg.cfproxy_worker_domain = "worker.example".into();
        cfg.normalize().unwrap();
        assert!(cfg.configured_tls_relays() && cfg.requires_go().is_empty());
        cfg.cfproxy_worker_domains = Some(vec![]);
        cfg.normalize().unwrap();
        assert!(cfg.requires_go().is_empty());
        cfg.transport = "custom".into();
        assert!(!cfg.requires_go().is_empty());
    }
    #[test]
    fn preserves_legacy_routes_and_keeps_native_off_by_default() {
        let mut legacy = Config {
            cfproxy_user_domain: "Example.test; a.example.test".into(),
            ..Default::default()
        };
        legacy.normalize().unwrap();
        assert!(
            legacy.configured_tls_relays() && legacy.h2_media() && legacy.requires_go().is_empty()
        );
        legacy.pool_size = i64::MAX;
        assert!(legacy.requires_go().is_empty());
        assert_eq!(
            legacy.cfproxy_user_domains.unwrap(),
            ["example.test", "a.example.test"]
        );
        let mut n = Config::native();
        n.normalize().unwrap();
        assert!(!n.enabled);
        assert!(n.requires_go().is_empty());
        for size in [1, 16, 17, i64::MAX] {
            n.pool_size = size;
            assert!(n.requires_go().is_empty());
        }
        assert_eq!(n.key().unwrap().len(), 16);
        assert!(n.link("::1").contains("%3A%3A1"));
    }
}
