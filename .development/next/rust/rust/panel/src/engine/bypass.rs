mod domain;
use super::files;
mod hooks;
#[cfg(test)]
mod tests;

use super::lifecycle::{manual_off, pause_acceleration, OPERATIONS};
use crate::http::{ApiError, Shared};
use axum::{extract::State, http::StatusCode, Json};
use nfqws2_awg_profile::TransportBypassProof;
use nfqws2_config::{Config, Platform, Resolver};
use nfqws2_router_command::{Runner, System};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const DOMAIN_FILE: &str = "lists/nfqueue_bypass_domains.list";
const CACHE: &str = "lists/nfqueue_bypass_resolved.list";
const HELPER: &str = "nfqws-strategy-bypass.sh";
const TRANSPORTS: &str = "nfqws-transport-endpoints";
const TRANSPORT_MANIFEST_LIMIT: u64 = 1 << 20;
const SAVED_HEAD: &str = "# nfqws2-strategy Rust: saved AWG endpoints";
const SAVED_TAIL: &str = "# nfqws2-strategy Rust: end saved AWG endpoints";
const INHERITED_HEAD: &str = "# nfqws2-strategy Rust: inherited AWG endpoints";
const INHERITED_TAIL: &str = "# nfqws2-strategy Rust: end inherited AWG endpoints";

fn canonical_transport(endpoint: SocketAddr) -> io::Result<SocketAddr> {
    let ip = endpoint.ip().to_canonical();
    if endpoint.port() == 0
        || matches!(endpoint, SocketAddr::V6(v) if v.scope_id() != 0)
        || ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(v) => v.is_link_local() || v.is_broadcast(),
            IpAddr::V6(v) => v.is_unicast_link_local(),
        }
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "неверный UDP endpoint AWG",
        ));
    }
    Ok(SocketAddr::new(ip, endpoint.port()))
}

fn refresh_manifest(
    old: &str,
    saved: &[SocketAddr],
    proof: TransportBypassProof<'_>,
) -> io::Result<String> {
    let saved: BTreeSet<_> = saved
        .iter()
        .copied()
        .chain(std::iter::once(proof.endpoint))
        .map(canonical_transport)
        .collect::<io::Result<_>>()?;
    let inherited: BTreeSet<_> = proof
        .inherited
        .iter()
        .copied()
        .map(canonical_transport)
        .collect::<io::Result<_>>()?;
    let next = transport(old, &saved.iter().copied().collect::<Vec<_>>())?;
    let next = transport_block(
        &next,
        &inherited.difference(&saved).copied().collect::<Vec<_>>(),
        INHERITED_HEAD,
        INHERITED_TAIL,
    )?;
    if next.len() as u64 > TRANSPORT_MANIFEST_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "слишком большой список endpoint NFQWS2",
        ));
    }
    Ok(next)
}

pub(crate) fn refresh_transport_bypass(
    s: &Shared,
    proof: TransportBypassProof<'_>,
) -> io::Result<()> {
    refresh_transport(s, proof, Path::new("/"), &System)
}

fn refresh_transport(
    s: &Shared,
    proof: TransportBypassProof<'_>,
    root: &Path,
    runner: &impl Runner,
) -> io::Result<()> {
    if s.config.nfqws2_conf.trim().is_empty() {
        return Ok(());
    }
    let dir = conf_dir(&s.config)?;
    let helper = dir.join(HELPER);
    if !helper.try_exists()? {
        return Ok(());
    }
    // AWG recovery already holds its operation lock. The engine can be
    // applying lists while it waits for a snapshot from that same manager.
    let _engine = OPERATIONS
        .try_lock()
        .map_err(|_| io::ErrorKind::WouldBlock)?;
    if Instant::now() >= proof.deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let off = manual_off(&s.store)?;
    let profiles = nfqws2_awg_profile::read(&s.store)?;
    let saved = nfqws2_awg_profile::transport_endpoints(&s.store)?;
    let manifest = dir.join(TRANSPORTS);
    let old = files::read(&manifest, TRANSPORT_MANIFEST_LIMIT)?;
    let next = refresh_manifest(old.as_deref().unwrap_or_default(), &saved, proof)?;
    hooks::refresh_transport(
        hooks::TransportRefresh {
            root,
            helper: &helper,
            old: old.as_deref().unwrap_or_default(),
            new: &next,
            live: !off,
            deadline: proof.deadline,
        },
        runner,
        || {
            s.store.try_transaction(|_| {
                if Instant::now() >= proof.deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                if manual_off(&s.store)? != off
                    || nfqws2_awg_profile::read(&s.store)? != profiles
                    || files::read(&manifest, TRANSPORT_MANIFEST_LIMIT)? != old
                {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                if old.as_deref().unwrap_or_default() != next {
                    files::write(&manifest, &next, 0o600, old.as_deref())?;
                }
                Ok(())
            })
        },
    )
}

pub(super) struct TimedCommand;
impl Runner for TimedCommand {
    fn run(&self, name: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        #[cfg(target_os = "linux")]
        {
            let mut cmd = std::process::Command::new(name);
            cmd.args(args);
            nfqws2_router_command::output(&mut cmd, deadline, 128 << 10)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, args, deadline);
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

fn conf_dir(cfg: &Config) -> io::Result<PathBuf> {
    Path::new(&cfg.nfqws2_conf)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_owned)
        .ok_or_else(|| io::Error::other("нет каталога конфигурации NFQWS2"))
}
pub(super) fn configured(cfg: &Config) -> io::Result<bool> {
    let dir = conf_dir(cfg)?;
    for name in [
        HELPER,
        DOMAIN_FILE,
        "lists/nfqueue_bypass_ips.list",
        TRANSPORTS,
    ] {
        if dir.join(name).try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Keep addresses supplied by other controllers, including live/dynamically
/// resolved VPN peers. The Go controller can replace the whole manifest.
fn transport(old: &str, saved: &[SocketAddr]) -> io::Result<String> {
    transport_block(old, saved, SAVED_HEAD, SAVED_TAIL)
}

fn transport_block(old: &str, saved: &[SocketAddr], head: &str, tail: &str) -> io::Result<String> {
    let mut outside = String::new();
    let mut active = false;
    let mut found = false;
    for line in old.split_inclusive('\n') {
        match line.trim_end() {
            value if value == head && !active && !found => {
                active = true;
                found = true;
            }
            value if value == tail && active => active = false,
            value
                if value == head
                    || value == tail
                    || active
                        && matches!(
                            value,
                            SAVED_HEAD | SAVED_TAIL | INHERITED_HEAD | INHERITED_TAIL
                        ) =>
            {
                return Err(io::Error::other("некорректный блок endpoint NFQWS2"));
            }
            _ if !active => outside.push_str(line),
            _ => (),
        }
    }
    if active {
        return Err(io::Error::other("незавершённый блок endpoint NFQWS2"));
    }
    if !saved.is_empty() {
        if !outside.is_empty() && !outside.ends_with('\n') {
            outside.push('\n');
        }
        outside.push_str(head);
        outside.push('\n');
        for ep in saved {
            outside.push_str(&format!("{} {}\n", ep.ip(), ep.port()));
        }
        outside.push_str(tail);
        outside.push('\n');
    }
    Ok(outside)
}

fn install_files(
    s: &Shared,
    dir: &Path,
    domains: &str,
    cache: &str,
    inherited: &[SocketAddr],
) -> io::Result<()> {
    let domain = files::read(&dir.join(DOMAIN_FILE), 1 << 20)?.unwrap_or_default();
    if domain != domains {
        return Err(io::Error::other(
            "Список доменов изменился во время DNS-запросов. Повторите применение.",
        ));
    }
    let saved = nfqws2_awg_profile::transport_endpoints(&s.store)?;
    let manifest = dir.join(TRANSPORTS);
    let old = files::read(&manifest, 1 << 20)?;
    let saved = transport(old.as_deref().unwrap_or_default(), &saved)?;
    let next = transport_block(&saved, inherited, INHERITED_HEAD, INHERITED_TAIL)?;
    crate::editor::normalize_wan(&s.config)?;
    hooks::helper(&dir.join(HELPER))?;
    if old.as_deref().unwrap_or_default() != next {
        files::write(&manifest, &next, 0o600, old.as_deref())?;
    }
    let cache_file = dir.join(CACHE);
    let old = files::read(&cache_file, 4 << 20)?;
    files::write(&cache_file, cache, 0o644, old.as_deref())
}

fn firewall(
    dir: &Path,
    init: &str,
    platform: Platform,
    runner: &impl Runner,
    live: bool,
) -> io::Result<()> {
    let helper = dir.join(HELPER);
    let deadline = Instant::now() + Duration::from_secs(60);
    hooks::persist(dir, Path::new(init), &helper, platform, runner, deadline)?;
    if !live {
        return Ok(());
    }
    let helper = helper
        .to_str()
        .ok_or_else(|| io::Error::other("некорректный путь NFQUEUE helper"))?;
    for (program, action) in [
        (init, "firewall_iptables"),
        (init, "firewall_ip6tables"),
        (helper, "iptables"),
        (helper, "ip6tables"),
    ] {
        runner.run(program, &[action], deadline)?;
    }
    Ok(())
}

/// Caller holds the engine operation lock across DNS, preparation and both families.
pub(super) async fn apply_locked(s: Shared, live: bool) -> io::Result<()> {
    let prep = s.clone();
    let (dir, source) = tokio::task::spawn_blocking(move || {
        let dir = conf_dir(&prep.config)?;
        let source = files::read(&dir.join(DOMAIN_FILE), 1 << 20)?.unwrap_or_default();
        // Refuse unknown init formats before creating any managed files.
        let init = files::read(Path::new(&prep.config.nfqws2_init), 2 << 20)?
            .ok_or(io::ErrorKind::NotFound)?;
        hooks::patched(&init, &dir.join(HELPER))?;
        Ok::<_, io::Error>((dir, source))
    })
    .await
    .map_err(io::Error::other)??;
    let (hosts, invalid) = domain::hosts(&source)?;
    let (cache, failed) = domain::resolve(hosts, domain::system_lookup).await?;
    if failed + invalid > 0 {
        s.logs.append(
            "nfqws2",
            "warn",
            &format!("NFQUEUE bypass: {failed} DNS failures, {invalid} invalid domains"),
        );
    }
    let count = cache.lines().count();
    let work = s.clone();
    tokio::task::spawn_blocking(move || {
        // Gather the UAPI proof before entering the store transaction. AWG
        // client operations take a client lock before consulting the store.
        let expires = Instant::now() + Duration::from_secs(5);
        let (inherited, profiles) = if live {
            let profiles = nfqws2_awg_profile::read(&work.store)?;
            let addresses = work
                .awg_runtime
                .inherited_transport_endpoints(&work.store, work.config.awg_wan_ifaces())?;
            (addresses, Some(profiles))
        } else {
            (Vec::new(), None)
        };
        work.store.transaction(|_| {
            if !inherited.is_empty()
                && (Instant::now() >= expires
                    || profiles.as_ref() != Some(&nfqws2_awg_profile::read(&work.store)?))
            {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            install_files(&work, &dir, &source, &cache, &inherited)
        })?;
        firewall(
            &dir,
            &work.config.nfqws2_init,
            Resolver::current().platform(),
            &TimedCommand,
            live,
        )
    })
    .await
    .map_err(io::Error::other)??;
    s.logs.append(
        "nfqws2",
        "info",
        &format!(
            "NFQUEUE bypass {} ({count} resolved IPs)",
            if live {
                "applied"
            } else {
                "prepared for next engine start"
            }
        ),
    );
    Ok(())
}

pub(super) async fn apply(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    tokio::spawn(async move {
        let _lock = OPERATIONS.lock().await;
        if manual_off(&s.store)? {
            return Err(io::Error::other(
                "NFQWS2 выключен вручную. Включите сервис перед применением исключений.",
            ));
        }
        let prep = s.clone();
        let _acceleration =
            tokio::task::spawn_blocking(move || pause_acceleration(&prep.store, &prep.config))
                .await
                .map_err(io::Error::other)??;
        apply_locked(s, true).await
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(json!({"status":"applied"})))
}
