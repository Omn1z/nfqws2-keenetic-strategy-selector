//! Transactional deployment of WireGuard and AmneziaWG profiles.
//! Only public status is returned. The private configuration travels on SSH stdin.
use super::{active, conf, edit_document, invalid, now, peers, runtime::Runtime, s};
use crate::{client::RefreshTransport, TransportBypassProof};
use base64ct::{Base64, Encoding};
use curve25519_dalek::montgomery::MontgomeryPoint;
use nfqws2_store::Store;
use serde_json::{json, Value};
use std::{collections::HashSet, fmt::Write, io, net::IpAddr, sync::MutexGuard};

const MARKER: &str = "# Managed by nfqws2-strategy (WireGuard)";
#[cfg(any(target_os = "linux", test))]
mod bootstrap;
pub(crate) mod history;
mod peer_sync;
mod report;
#[cfg(test)]
mod tests;
mod userspace;
use report::{Deployment, Remote};
pub(crate) use userspace::status_tool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    WireGuard,
    Kernel,
    Userspace,
}

impl Backend {
    fn requested(cfg: &Value) -> Self {
        if !userspace::selected(cfg) {
            Self::WireGuard
        } else if cfg["install"] == "userspace" || conf::requires_awg31(cfg) {
            Self::Userspace
        } else {
            Self::Kernel
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::Kernel => "apt",
            Self::Userspace => "userspace",
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Self::WireGuard => "wg",
            Self::Kernel => "awg-kernel",
            Self::Userspace => "awg",
        }
    }
}

fn interface(value: &str) -> bool {
    value.len() < 16
        && value
            .strip_prefix("awg")
            .or_else(|| value.strip_prefix("wg"))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}
fn eligible(cfg: &Value) -> io::Result<()> {
    if cfg["enabled"] == false {
        return Err(invalid("сервер выключен"));
    }
    if cfg["install"] == "imported" {
        return Err(invalid("импортированный профиль не управляет VPS"));
    }
    if !matches!(s(cfg, "protocol"), "awg" | "wireguard" | "") {
        return Err(invalid("неподдерживаемый VPN-протокол"));
    }
    if !interface(s(cfg, "interface")) {
        return Err(invalid("нужен VPN-интерфейс wgN или awgN"));
    }
    if s(&cfg["conn"], "known_key").trim().is_empty() {
        return Err(invalid(
            "сначала подтвердите ключ SSH-хоста в карточке сервера",
        ));
    }
    Ok(())
}
fn server_key(cfg: &Value) -> io::Result<()> {
    let raw = conf::key(s(cfg, "private_key"), false)?;
    if Base64::encode_string(MontgomeryPoint::mul_base_clamped(raw).as_bytes())
        != s(cfg, "public_key")
    {
        return Err(invalid("ключи VPN-сервера не соответствуют друг другу"));
    }
    Ok(())
}
fn unicast(raw: &str) -> io::Result<IpAddr> {
    let ip: IpAddr = raw
        .parse()
        .map_err(|_| invalid("неверный IP-адрес WireGuard"))?;
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip,IpAddr::V4(v) if v.is_broadcast() || v.is_link_local())
        || matches!(ip,IpAddr::V6(v) if v.is_unicast_link_local())
    {
        return Err(invalid("WireGuard требует unicast-адрес"));
    }
    Ok(ip)
}
fn render(cfg: &Value) -> io::Result<String> {
    server_key(cfg)?;
    let addr = s(cfg, "address");
    conf::cidrs(addr, true)?;
    let (host, prefix) = addr
        .trim()
        .split_once('/')
        .ok_or_else(|| invalid("нужна маска интерфейса WireGuard"))?;
    let server_ip = unicast(host)?;
    let prefix = prefix
        .parse::<u8>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| invalid("неверная маска интерфейса WireGuard"))?;
    let port = cfg["listen_port"]
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid("некорректный UDP-порт WireGuard"))?;
    let mtu = cfg["mtu"].as_u64().unwrap_or(0);
    if mtu != 0 && !(576..=9000).contains(&mtu) {
        return Err(invalid("некорректный MTU WireGuard"));
    }
    let mut text = if userspace::selected(cfg) {
        String::new()
    } else {
        format!("{MARKER}\n")
    };
    write!(
        text,
        "[Interface]\nPrivateKey = {}\nAddress = {server_ip}/{prefix}\nListenPort = {port}\n",
        s(cfg, "private_key")
    )
    .unwrap();
    if mtu != 0 {
        writeln!(text, "MTU = {mtu}").unwrap();
    }
    if userspace::selected(cfg) {
        userspace::server_lines(cfg, &mut text)?;
    }
    let mut used = HashSet::from([server_ip]);
    let mut keys = HashSet::from([s(cfg, "public_key")]);
    let rows = cfg["peers"]
        .as_array()
        .ok_or_else(|| invalid("нет списка пиров WireGuard"))?;
    if rows.len() > 512 {
        return Err(invalid("слишком много пиров WireGuard"));
    }
    for peer in rows {
        let key = s(peer, "public_key");
        conf::key(key, false)?;
        if !keys.insert(key) {
            return Err(invalid("повторяющийся публичный ключ VPN"));
        }
        writeln!(text, "\n[Peer]\nPublicKey = {key}").unwrap();
        let psk = s(peer, "psk");
        if !psk.is_empty() && conf::key(psk, true)? != [0; 32] {
            writeln!(text, "PresharedKey = {psk}").unwrap();
        }
        text.push_str("AllowedIPs = ");
        let addresses = s(peer, "address");
        conf::cidrs(addresses, false)?;
        for (i, part) in addresses.split(',').map(str::trim).enumerate() {
            let ip = unicast(part.split_once('/').map_or(part, |(ip, _)| ip))?;
            if !used.insert(ip) {
                return Err(invalid("повторяющийся VPN-адрес пира"));
            }
            if i > 0 {
                text.push_str(", ");
            }
            write!(text, "{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }).unwrap();
        }
        text.push('\n');
        if text.len() > 256 * 1024 {
            return Err(invalid("конфигурация WireGuard превышает 256 КиБ"));
        }
    }
    Ok(text)
}

fn prepare(row: &mut Value) -> io::Result<()> {
    let deployed =
        row["applied_config"].is_object() || row["config"]["deployed_at"].as_u64().unwrap_or(0) > 0;
    let cfg = &mut row["config"];
    eligible(cfg)?;
    if s(cfg, "private_key").is_empty() {
        if deployed || !s(cfg, "public_key").is_empty() {
            return Err(invalid(
                "сохранённый серверный ключ утрачен, восстановите конфигурацию",
            ));
        }
        let (private, public) = peers::pair()?;
        cfg["private_key"] = json!(private);
        cfg["public_key"] = json!(public);
    }
    server_key(cfg)?;
    if !cfg["peers"]
        .as_array()
        .is_some_and(|p| p.iter().any(|r| r["is_router"] == true))
    {
        peers::append(
            cfg,
            super::PeerInput {
                name: "Keenetic".into(),
                ..Default::default()
            },
            true,
        )?;
    }
    if s(cfg, "endpoint").is_empty() {
        let host = s(&cfg["conn"], "host");
        let port = &cfg["listen_port"];
        cfg["endpoint"] = json!(if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        });
    }
    conf::endpoint(s(cfg, "endpoint"))?;
    Ok(())
}
fn run(
    db: &Store,
    id: Option<&str>,
    apply: impl FnOnce(&str, &Value, &str, Option<[u8; 32]>) -> io::Result<Backend>,
) -> io::Result<String> {
    // Commit the generated keys before any remote action. A disconnect or a full
    // disk on the router can then be recovered by retrying the same identity.
    let (id, cfg, text, previous) = edit_document(db, |doc| {
        let id = match id {
            Some(id) => id.trim().to_owned(),
            None => s(active(doc)?, "id").to_owned(),
        };
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == id)
            .ok_or_else(|| invalid("AWG2-сервер не найден"))?;
        let deployed = row["applied_config"].is_object()
            || row["config"]["deployed_at"].as_u64().unwrap_or(0) > 0;
        let old = super::wire(row);
        let previous = if deployed && userspace::selected(old) {
            use sha2::{Digest, Sha256};
            Some(Sha256::digest(render(old)?).into())
        } else {
            None
        };
        prepare(row)?;
        let cfg = &row["config"];
        Ok((id, cfg.clone(), render(cfg)?, previous))
    })?;
    let backend = apply(&id, &cfg, &text, previous)?;
    let stamp = |value: &mut Value, time: u64| {
        value["deployed_at"] = json!(time);
        value["native_vpn_tool"] = json!(userspace::tool(&cfg));
        value["native_vpn_method"] = json!(backend.method());
    };
    edit_document(db, |doc| {
        let row = doc["servers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == id)
            .ok_or_else(|| invalid("после применения профиль удалён"))?;
        let time = now();
        // An edit to a peer or a setting can have arrived while SSH was busy.
        // Preserve that as desired state and publish what is actually running.
        if row["config"] == cfg {
            row.as_object_mut().unwrap().remove("applied_config");
            row.as_object_mut().unwrap().remove("native_peer_change");
        } else {
            let mut applied = cfg.clone();
            stamp(&mut applied, time);
            row["applied_config"] = applied;
        }
        stamp(&mut row["config"], time);
        Ok(id)
    })
    .map_err(|_| {
        io::Error::other(
            "VPN применён на сервере, но локальное подтверждение не записано; повторите операцию",
        )
    })
}

impl Runtime {
    pub fn deploy_profiles(&self, db: &Store, ids: &[String], wan: &[String]) -> io::Result<Value> {
        self.deploy_profiles_inner(db, ids, wan, None)
    }

    pub fn deploy_profiles_with_transport(
        &self,
        db: &Store,
        ids: &[String],
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> io::Result<Value> {
        self.deploy_profiles_inner(db, ids, wan, Some(&refresh))
    }

    fn deploy_profiles_inner(
        &self,
        db: &Store,
        ids: &[String],
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> io::Result<Value> {
        let guard = self.deployment_guard()?;
        let labels = {
            let doc = super::read(db)?;
            doc["servers"]
                .as_array()
                .ok_or_else(|| invalid("нет списка серверов"))?
                .iter()
                .map(|r| {
                    (
                        s(r, "id").to_owned(),
                        (
                            super::view::server_label(r, &r["config"]),
                            Backend::requested(&r["config"]),
                        ),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>()
        };
        let mut results = Vec::new();
        for id in ids.iter().map(|v| v.trim()).filter(|v| !v.is_empty()) {
            let Some((label, backend)) = labels.get(id) else {
                results.push(json!({
                    "id":id,"label":"","ok":false,"error":"AWG2-сервер не найден",
                    "result":{"ok":false,"method":"","wan_iface":"","listening":false,"handshake":false,"steps":null}
                }));
                continue;
            };
            let mut result = self
                .deploy_locked(&guard, db, Some(id), wan, *backend, refresh)
                .response();
            result["id"] = json!(id);
            result["label"] = json!(label);
            results.push(result);
        }
        Ok(json!({"results":results}))
    }
    /// Serializes a change to an SSH-managed identity with restore or removal
    /// of its local configuration. Never overwrite the identity mid-transaction.
    pub fn deployment_guard(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.deployment
            .try_lock()
            .map_err(|_| invalid("уже выполняется операция с VPN-профилем"))
    }
    pub fn deploy_profile(&self, db: &Store, id: Option<&str>, wan: &[String]) -> Value {
        self.deploy_profile_inner(db, id, wan, None)
    }

    pub fn deploy_profile_with_transport(
        &self,
        db: &Store,
        id: Option<&str>,
        wan: &[String],
        refresh: impl Fn(TransportBypassProof<'_>) -> io::Result<()>,
    ) -> Value {
        self.deploy_profile_inner(db, id, wan, Some(&refresh))
    }

    fn deploy_profile_inner(
        &self,
        db: &Store,
        id: Option<&str>,
        wan: &[String],
        refresh: Option<&RefreshTransport<'_>>,
    ) -> Value {
        let backend = crate::read(db)
            .ok()
            .and_then(|doc| {
                id.map_or_else(|| active(&doc), |id| crate::client::find(&doc, id))
                    .ok()
                    .map(|row| Backend::requested(&row["config"]))
            })
            .unwrap_or(Backend::WireGuard);
        match self.deployment_guard() {
            Ok(guard) => self.deploy_locked(&guard, db, id, wan, backend, refresh).response(),
            Err(_) => {
                let mut report = Deployment::new(backend);
                report.fail("prepare", "Уже выполняется операция с VPN-профилем");
                report.response()
            }
        }
    }
    fn deploy_locked(
        &self,
        _guard: &MutexGuard<'_, ()>,
        db: &Store,
        id: Option<&str>,
        wan: &[String],
        backend: Backend,
        refresh: Option<&RefreshTransport<'_>>,
    ) -> Deployment {
        let mut report = Deployment::new(backend);
        let mut target = crate::read(db).ok().and_then(|doc| {
            let row = id
                .map_or_else(|| active(&doc), |id| crate::client::find(&doc, id))
                .ok()?;
            Some(history::Target::new(s(row, "id"), &row["config"]))
        });
        let outcome = (|| {
            userspace::prepare_wan(self, db, id)?;
            let id = run(db, id, |id, cfg, text, previous| {
                target = Some(history::Target::new(id, cfg));
                let backend = Backend::requested(cfg);
                report = Deployment::new(backend);
                report.wan(cfg);
                report.step("prepare", "Проверены параметры и ключи профиля");
                if self.root != std::path::Path::new("/") {
                    report.fail("SSH", "SSH доступен только из рабочей системы роутера");
                    return Err(invalid("SSH доступен только из рабочей системы роутера"));
                }
                #[cfg(target_os = "linux")]
                let backend = bootstrap::prepare(cfg, backend, &mut report)?;
                match remote_apply(cfg, text, previous.as_ref(), backend.tool(), false) {
                    Ok(result) => report.apply(result, cfg).map(|()| backend),
                    Err(e) => {
                        report.fail("SSH", "SSH не подтвердил результат применения VPN");
                        Err(e)
                    }
                }
            })?;
            let local = self.reconcile_deployed(db, &id, wan, refresh);
            if super::read(db).is_ok_and(|d| d["active_id"] == id) {
                let _ = self.refresh_status(db);
            }
            Ok(local.err())
        })();
        report.finish(outcome);
        if let Some(target) = target {
            self.deploy_history.record(target, &report);
        }
        report
    }
}
#[cfg(not(target_os = "linux"))]
fn remote_apply(_: &Value, _: &str, _: Option<&[u8; 32]>, _: &str, _: bool) -> io::Result<Remote> {
    Err(invalid("деплой VPN доступен на Linux"))
}
#[cfg(target_os = "linux")]
fn remote_apply(
    cfg: &Value,
    text: &str,
    previous: Option<&[u8; 32]>,
    tool: &str,
    peer_sync: bool,
) -> io::Result<Remote> {
    use sha2::{Digest, Sha256};
    use std::{
        io::{Seek, Write},
        time::{Duration, Instant},
    };
    let (_secrets, mut ssh) = super::remote::pinned_command(cfg)?;
    let mut input = tempfile::tempfile()?;
    input.write_all(text.as_bytes())?;
    input.rewind()?;
    let hex = |bytes: &[u8]| {
        let mut digest = String::with_capacity(64);
        for byte in bytes {
            write!(digest, "{byte:02x}").unwrap();
        }
        digest
    };
    let digest = hex(&Sha256::digest(text.as_bytes()));
    let previous = previous.map_or_else(|| "-".into(), |hash| hex(hash));
    // All runtime arguments are constrained by interface(), server_key(), or
    // SHA256. The remaining shell program is fixed at build time.
    let script = include_str!("deploy/apply.sh")
        .replace("\r\n", "\n")
        .replace('\'', "'\\''");
    ssh.arg(format!(
        "PATH=/usr/bin:/usr/sbin:/bin:/sbin sh -c '{script}' n2s {} {} {digest} {previous} {tool} {}",
        s(cfg, "interface"),
        s(cfg, "public_key"),
        if peer_sync { "sync" } else { "deploy" }
    ));
    let response = nfqws2_router_command::output_with_file(
        &mut ssh,
        input,
        Instant::now() + Duration::from_secs(90),
        512,
    )
    .map_err(|_| {
        io::Error::other(
            "SSH не подтвердил результат, проверьте состояние VPN и повторите операцию",
        )
    })?;
    Remote::parse(&response)
}
