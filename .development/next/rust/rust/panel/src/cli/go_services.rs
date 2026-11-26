use super::go_handoff::api;
use nfqws2_awg_rules::kernel::handoff::PanelEndpoint;
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::SocketAddr,
    num::NonZeroU16,
    time::{Duration, Instant},
};

const FILE: &str = "upgrade-go-services.json";
const LIMIT: u64 = 64 * 1024;

#[derive(Default, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct Services {
    tgws: Option<NonZeroU16>,
    socks5: Option<NonZeroU16>,
    #[serde(default)]
    dns: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) clients: Option<super::go_handoff::Clients>,
}

#[derive(Deserialize)]
struct Settings {
    #[serde(default)]
    enabled: bool,
    port: Option<u16>,
}
#[derive(Deserialize)]
struct Status {
    running: bool,
    config: Settings,
}
#[derive(Deserialize)]
struct DnsSettings {
    #[serde(default)]
    enabled: bool,
    dns_port: Option<u16>,
}
#[derive(Deserialize)]
struct DnsStatus {
    running: bool,
    config: DnsSettings,
    #[serde(default)]
    config_error: String,
    endpoints: DnsEndpoints,
}
#[derive(Deserialize)]
struct DnsEndpoints {
    dns: String,
}

fn dns_endpoint(raw: &[u8]) -> io::Result<Option<SocketAddr>> {
    let dns: DnsStatus = serde_json::from_slice(raw)
        .map_err(|_| io::Error::other("не удалось прочитать состояние DNS-сервера панели"))?;
    if !dns.running || !dns.config.enabled || !dns.config_error.is_empty() {
        return Ok(None);
    }
    let addr: SocketAddr = dns
        .endpoints
        .dns
        .parse()
        .map_err(|_| io::Error::other("некорректный активный адрес DNS-сервера панели"))?;
    if addr.port() == 0 || dns.config.dns_port != Some(addr.port()) {
        return Err(io::Error::other(
            "порт DNS-сервера не совпадает с его настройками",
        ));
    }
    Ok(Some(SocketAddr::new(addr.ip().to_canonical(), addr.port())))
}
fn dns_status(port: PanelEndpoint) -> io::Result<Option<SocketAddr>> {
    dns_endpoint(&api(port, "GET", "dnsserver")?)
}

fn status(port: PanelEndpoint, name: &str) -> io::Result<Option<NonZeroU16>> {
    let state: Status = serde_json::from_slice(&api(port, "GET", name)?)
        .map_err(|_| io::Error::other(format!("не удалось прочитать состояние {name}")))?;
    Ok(if state.running && state.config.enabled {
        state.config.port.and_then(NonZeroU16::new)
    } else {
        None
    })
}
fn settings<T: serde::de::DeserializeOwned>(db: &Store, file: &str) -> io::Result<Option<T>> {
    match db.read_limited(file, 1 << 20) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(io::Error::other(format!(
            "не удалось прочитать настройки {file}"
        ))),
    }
}

pub(super) fn capture(db: &Store, port: PanelEndpoint) -> io::Result<Services> {
    let tg = settings::<nfqws2_tgws_config::Config>(db, "tgws.json")?;
    let mut services = Services::default();
    if let Some(mut tg) = tg.filter(|c| c.enabled) {
        tg.normalize()?;
        let requires = tg.requires_go();
        if !requires.is_empty() {
            return Err(io::Error::other(format!(
                "Для работающего MTProto требуется Go: {}",
                requires.join(", ")
            )));
        }
        services.tgws = Some(
            status(port, "tgws")?
                .ok_or_else(|| io::Error::other("Go не подтвердил порт MTProto"))?,
        );
    }
    if settings::<Settings>(db, "socks5.json")?.is_some_and(|c| c.enabled) {
        services.socks5 = Some(
            status(port, "socks5")?
                .ok_or_else(|| io::Error::other("Go не подтвердил порт SOCKS5"))?,
        );
    }
    if let Some(dns) = settings::<DnsSettings>(db, "dnsserver.json")?.filter(|c| c.enabled) {
        let active = dns_status(port)?
            .ok_or_else(|| io::Error::other("Go не подтвердил работающий DNS-сервер панели"))?;
        if dns
            .dns_port
            .is_some_and(|saved| saved != 0 && saved != active.port())
        {
            return Err(io::Error::other(
                "записанный порт DNS-сервера не совпадает с работающим",
            ));
        }
        services.dns = Some(active);
    }
    Ok(services)
}
pub(super) fn stage(db: &Store, services: &Services) -> io::Result<()> {
    db.transaction(|tx| tx.save_runtime_bounded(FILE, services, LIMIT))
}
pub(super) fn finish(db: &Store, port: PanelEndpoint) -> io::Result<()> {
    let expected: Services = db.read_runtime(FILE, LIMIT)?;
    for (name, expect) in [("tgws", expected.tgws), ("socks5", expected.socks5)] {
        let Some(expect) = expect else { continue };
        resume(name, expect, || status(port, name))?;
    }
    if let Some(expect) = expected.dns {
        resume("DNS-сервер панели", expect, || dns_status(port))?;
    }
    if let Some(clients) = expected.clients.as_ref() {
        super::go_handoff::finish_clients_only(db, port, clients)?;
    }
    db.transaction(|tx| tx.delete_runtime(FILE))
}
fn resume<T: PartialEq + std::fmt::Display>(
    service: &str,
    expected: T,
    read: impl Fn() -> io::Result<Option<T>>,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if read().ok().flatten().as_ref() == Some(&expected) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "{service} не возобновил работу на прежнем адресе или порту {expected}"
            )));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_witness_requires_an_active_listener_and_preserves_effective_lan_address() {
        let mut view = serde_json::json!({
            "config":{"enabled":true,"dns_port":5355}, "running":true,
            "endpoints":{"dns":"[::ffff:192.168.1.1]:5355"}
        });
        let read = |val: &serde_json::Value| dns_endpoint(&serde_json::to_vec(val).unwrap());
        assert_eq!(
            read(&view).unwrap(),
            Some("192.168.1.1:5355".parse().unwrap())
        );
        view["config"]["dns_port"] = 5399.into();
        assert!(read(&view).is_err());
        view["running"] = false.into();
        assert_eq!(read(&view).unwrap(), None);
        view["running"] = true.into();
        view["config_error"] = "bad saved config".into();
        assert_eq!(read(&view).unwrap(), None);
        let previous: Services = serde_json::from_str(r#"{"tgws":1433,"socks5":1080}"#).unwrap();
        assert!(previous.dns.is_none());
    }
    #[test]
    fn unsupported_active_proxy_blocks_the_switch_and_disabled_proxy_needs_no_listener() {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(temp.path()).unwrap();
        let port = NonZeroU16::new(1).unwrap().into();
        let mut cfg = nfqws2_tgws_config::Config::native();
        cfg.fake_tls_domain = "mask.example.test".into();
        assert!(cfg.requires_go().is_empty());
        cfg.transport = "unknown-future-transport".into();
        cfg.enabled = true;
        db.transaction(|tx| tx.save("tgws.json", &cfg)).unwrap();
        assert!(capture(&db, port)
            .err()
            .unwrap()
            .to_string()
            .contains("неизвестный транспорт"));
        cfg.enabled = false;
        db.transaction(|tx| tx.save("tgws.json", &cfg)).unwrap();
        let services = capture(&db, port).unwrap();
        assert!(services.tgws.is_none());
        stage(&db, &services).unwrap();
        finish(&db, port).unwrap();
        assert!(db.read_runtime::<Services>(FILE, 4096).is_err());
    }
}
