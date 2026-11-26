use super::{io, kernel, DnsApplyProof, DnsSnapshot, Operation, Path, Shared, System};

fn keenetic(root: &Path) -> bool {
    !root.join("etc/openwrt_release").exists()
        && !root.join("etc/rc.common").exists()
        && (root.join("opt/etc/ndm").is_dir() || root.join("bin/ndmc").is_file())
}

fn bridges(root: &Path, expected: Option<&[String]>) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root.join("sys/class/net"))? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with("br") {
            if !kernel::valid_dns_bridge(&name) {
                return Err(io::Error::other("некорректное имя LAN-моста Keenetic"));
            }
            names.push(name);
        }
    }
    if names.len() > 128 {
        return Err(io::Error::other(
            "не удалось определить LAN-мосты для перехвата DNS",
        ));
    }
    names.sort();
    if expected.is_some_and(|expected| expected != names) {
        return Err(io::Error::other(
            "состав LAN-мостов Keenetic изменился после проверки перехвата DNS Go",
        ));
    }
    Ok(names)
}

pub(super) fn prepare_active_replacement(s: &Shared, names: &[String]) -> io::Result<()> {
    if names.is_empty() {
        return s
            .dnsserver
            .routing_nameserver()?
            .map(|_| ())
            .ok_or_else(|| io::Error::other("DNS-сервер действующих зон недоступен"));
    }
    let root = &s.route_kernel.router_root;
    if !keenetic(root) || bridges(root, None)? != names {
        return Err(io::Error::other("изменились LAN-мосты перехвата DNS"));
    }
    tokio::runtime::Handle::current().block_on(s.dnsserver.set_routing_redirect(names))
}

/// Called on the blocking routing worker, under the same lock as DNS learning.
/// Bind before installing redirects and release sockets only after the receipt
/// confirms no live or partially-installed rule can deliver queries to them.
pub(super) fn operate(
    s: &Shared,
    op: Operation,
    snapshot: Option<&DnsSnapshot>,
    proof: Option<DnsApplyProof<'_>>,
) -> io::Result<()> {
    operate_inner(s, op, snapshot, proof, None)
}

pub(super) fn operate_firmware_refresh(s: &Shared) -> io::Result<bool> {
    let unchanged = std::cell::Cell::new(false);
    operate_inner(s, Operation::Refresh, None, None, Some(&unchanged))?;
    Ok(unchanged.get())
}

fn operate_inner(
    s: &Shared,
    op: Operation,
    snapshot: Option<&DnsSnapshot>,
    proof: Option<DnsApplyProof<'_>>,
    firmware_refresh: Option<&std::cell::Cell<bool>>,
) -> io::Result<()> {
    let root = &s.route_kernel.router_root;
    let restoring = matches!(op, Operation::Recover | Operation::Refresh);
    let watchdog = op == Operation::LegacyWatchdog;
    let mut required = kernel::redirect_bridges(&s.store, restoring || watchdog)?;
    let watchdog_dns =
        watchdog && required.is_empty() && kernel::watchdog_needs_dns_listener(&s.store)?;
    let rearm_dns = restoring && kernel::disabled_replacement_rearm_needs_dns(&s.store)?;
    let dormant = if rearm_dns && snapshot.is_none() && firmware_refresh.is_none() {
        kernel::dormant_firmware_dns(&s.store)?
            .map(|request| s.dnsserver.dormant_firmware_hints(&request))
            .transpose()?
            .flatten()
    } else {
        None
    };
    let mut available = None;
    let mut candidate = None;
    if matches!(op, Operation::Apply | Operation::ReloadSources) {
        let capture = if op == Operation::Apply {
            kernel::handoff_dns_bridges(&s.store)?.filter(|names| !names.is_empty())
        } else {
            None
        };
        let dynamic = kernel::needs_dns_listener(&s.store)?;
        if capture.is_some() && !dynamic {
            return Err(io::Error::other(
                "политика DNS изменилась после проверки перехвата Go",
            ));
        }
        if keenetic(root) {
            if dynamic || !required.is_empty() || capture.is_some() {
                available = Some(bridges(root, capture.as_deref())?);
            }
            candidate = Some(available.clone().filter(|_| dynamic).unwrap_or_default());
        } else if capture.is_some() {
            return Err(io::Error::other(
                "перенос работающего перехвата DNS Go требует Keenetic",
            ));
        } else if dynamic && s.dnsserver.routing_nameserver()?.is_none() {
            return Err(io::Error::other(
                "для маршрутизации по DNS-ответам запустите DNS-сервер панели и укажите его на клиентах",
            ));
        }
    } else if (!required.is_empty() || watchdog_dns || rearm_dns)
        && (restoring || watchdog || op == Operation::Commit)
        && keenetic(root)
    {
        let live = bridges(root, None)?;
        if live.is_empty() {
            return Err(io::Error::other(
                "ожидается появление LAN-мостов для перехвата DNS",
            ));
        }
        available = Some(live);
        candidate.clone_from(&available);
    }
    let set = |names: &[String]| {
        let live;
        let names = if let Some(available) = &available {
            // An extinct interface cannot receive packets, but its rule may
            // survive in netfilter until the transaction removes it.
            live = names
                .iter()
                .filter(|n| available.binary_search(n).is_ok())
                .cloned()
                .collect::<Vec<_>>();
            &live[..]
        } else {
            names
        };
        tokio::runtime::Handle::current().block_on(s.dnsserver.set_routing_redirect(names))
    };
    let probe = if matches!(op, Operation::Refresh | Operation::Recover) {
        kernel::legacy_dual_probe_target(&s.store, &System)?
    } else {
        None
    };
    let peer = |cfg: &serde_json::Value, iface: &str| {
        let fresh = probe
            .as_ref()
            .filter(|(expected, _)| expected == iface)
            .map(|(_, endpoint)| *endpoint);
        super::routing_live_peer_with_probe(s, cfg, iface, fresh)
    };
    if !matches!(op, Operation::Teardown | Operation::Suspend) {
        if let Some(bridges) = &candidate {
            required.extend(bridges.iter().cloned());
            required.sort();
            required.dedup();
        }
        if !required.is_empty() {
            if let Err(e) = set(&required) {
                if restoring {
                    // A crashed process may have left NAT entries in the kernel.
                    // Preserve the committed plan for the next automatic retry.
                    kernel::operate(&s.store, &System, Operation::Suspend, peer)?;
                    set(&kernel::redirect_bridges(&s.store, false)?)?;
                }
                return Err(e);
            }
        }
    }
    let update = || {
        match &proof {
            Some(DnsApplyProof::Fresh(fresh)) => fresh.check_resolver(s)?,
            Some(DnsApplyProof::Static(proof)) => {
                if let Some(proposal) = proof.proposed_apply() {
                    let result = kernel::apply_managed_static_dns_proposal(
                        &s.store,
                        &System,
                        proposal,
                        peer,
                        || proof.verify_writer(s),
                    );
                    if !proof.is_fresh_proposal()
                        || !result
                            .as_ref()
                            .err()
                            .is_some_and(kernel::managed_static_dns_proposal_off_scope)
                    {
                        return result;
                    }
                    proof.verify_writer(s)?;
                } else {
                    return kernel::apply_confirmed_static_dns_retry(
                        &s.store,
                        &System,
                        proof.confirmed_ticket(),
                        peer,
                        || proof.verify_writer(s),
                    );
                }
            }
            None => {}
        }
        let prove = |change: &nfqws2_awg_profile::RoutedMtuChange, live: &kernel::LivePeer| {
            s.awg_runtime.routed_mtu_peer_at(
                &s.store,
                change,
                live.endpoint,
                s.config.awg_wan_ifaces(),
            )
        };
        let accepted = kernel::operate_with_native_ownership(
            &s.store,
            &System,
            op,
            (snapshot, candidate.as_deref(), firmware_refresh.is_some(), dormant.as_ref()),
            peer,
            prove,
            kernel::GoFullPrimaryRecovery {
                wan: s.config.awg_wan_ifaces(),
                probe: &|id| s.awg_runtime.routing_go_full_primary(&s.store, id),
            },
        )?;
        if let Some(unchanged) = firmware_refresh {
            unchanged.set(accepted);
        }
        Ok(())
    };
    let result = if watchdog {
        s.awg_runtime.with_idle_routing_clients(update)
    } else {
        update()
    };
    let cleanup = kernel::redirect_bridges(&s.store, false).and_then(|names| set(&names));
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_keenetic_bridge_devices_receive_transparent_dns() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let net = root.join("sys/class/net");
        for name in ["br2", "eth0", "br0", "awg0", "br1"] {
            std::fs::create_dir_all(net.join(name)).unwrap();
        }
        assert!(!keenetic(root));
        std::fs::create_dir_all(root.join("opt/etc/ndm")).unwrap();
        assert!(keenetic(root));
        let captured = bridges(root, None).unwrap();
        assert_eq!(captured, ["br0", "br1", "br2"]);
        assert_eq!(bridges(root, Some(&captured)).unwrap(), captured);
        std::fs::create_dir(net.join("br3")).unwrap();
        assert!(bridges(root, Some(&captured)).is_err());
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/openwrt_release"), "").unwrap();
        assert!(!keenetic(root));
    }
}
