use super::*;

pub(super) fn selected(cfg: &Value) -> bool {
    cfg["install"] == "userspace"
        || cfg["native_vpn_tool"] == "awg"
        || cfg["protocol"] != "wireguard"
            && (cfg["traffic_obfuscation"] != false
                || cfg["native_vpn_tool"].is_null() && matches!(s(cfg, "install"), "apt" | ""))
        || cfg["native_vpn_tool"].is_null() && cfg["deployed_at"].as_u64().is_some_and(|t| t != 0)
}

pub(super) fn tool(cfg: &Value) -> &'static str {
    if selected(cfg) {
        "awg"
    } else {
        "wg"
    }
}
pub(crate) fn status_tool(cfg: &Value) -> &'static str {
    match cfg["native_vpn_tool"].as_str() {
        Some("wg") => "wg",
        Some("awg") => "awg",
        _ => tool(cfg),
    }
}
pub(super) fn deployed(cfg: &Value) -> bool {
    cfg["native_vpn_tool"] == tool(cfg)
        || selected(cfg)
            && cfg["native_vpn_tool"].is_null()
            && cfg["deployed_at"].as_u64().is_some_and(|v| v != 0)
}

pub(super) fn sync_tool(cfg: &Value) -> io::Result<&'static str> {
    if !selected(cfg) {
        return Ok(Backend::WireGuard.tool());
    }
    match cfg["native_vpn_method"].as_str() {
        Some("apt") => Ok(Backend::Kernel.tool()),
        Some("userspace") => Ok(Backend::Userspace.tool()),
        // The old Go/Rust snapshot stores only the protocol. The SSH
        // transaction may inspect either stock or our exact userspace unit.
        None if cfg["native_vpn_method"].is_null() => Ok("awg-auto"),
        _ => Err(invalid("неверный способ установки управляемого AmneziaWG")),
    }
}
pub(super) fn safe_wan(v: &str) -> bool {
    !v.is_empty()
        && v.len() < 16
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
pub(super) fn wan_iface(cfg: &Value) -> &str {
    match s(cfg, "wan_iface") {
        "" => "eth0",
        name => name,
    }
}
pub(super) fn server_lines(cfg: &Value, text: &mut String) -> io::Result<()> {
    if cfg["protocol"] != "wireguard" && cfg["traffic_obfuscation"] != false {
        let mut normalized = json!({});
        conf::write_extensions(cfg, text, Some(&mut normalized))?;
        conf::validate_obf(&normalized)?;
    }
    let wan = wan_iface(cfg);
    let subnet = s(cfg, "subnet");
    let valid_net = subnet.split_once('/').is_some_and(|(host, len)| {
        host.parse::<std::net::Ipv4Addr>().is_ok()
            && len.parse::<u8>().is_ok_and(|n| (1..=32).contains(&n))
            && subnet
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'/'))
    });
    if !safe_wan(wan) || !valid_net {
        return Err(invalid("неверная IPv4-подсеть NAT или WAN-интерфейс"));
    }
    // Match Go ServerConf byte-for-byte for ownership checks during the
    // first peer update after migrating an already deployed Linux server.
    writeln!(text,"PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -C POSTROUTING -s {subnet} -o {wan} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -o {wan} -j MASQUERADE; iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %i -j ACCEPT; iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %i -j ACCEPT").unwrap();
    writeln!(text,"PostDown = while iptables -t nat -D POSTROUTING -s {subnet} -o {wan} -j MASQUERADE 2>/dev/null; do :; done; while iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null; do :; done").unwrap();
    Ok(())
}
pub(super) fn prepare_wan(rt: &Runtime, db: &Store, id: Option<&str>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let doc = crate::read(db)?;
        let row = if let Some(id) = id {
            crate::client::find(&doc, id)?
        } else {
            active(&doc)?
        };
        let cfg = &row["config"];
        if !selected(cfg)
            || !s(cfg, "wan_iface").is_empty()
            || cfg["deployed_at"].as_u64().unwrap_or(0) > 0
        {
            return Ok(());
        }
        eligible(cfg)?;
        if rt.root != std::path::Path::new("/") {
            return Err(invalid("SSH доступен только из рабочей системы роутера"));
        }
        let (_secrets, mut ssh) = crate::remote::pinned_command(cfg)?;
        ssh.arg("ip -4 route show default | awk '$1 == \"default\" { for(i=2;i<NF;i++) if($i==\"dev\"){print $(i+1); exit} }'");
        let wan = nfqws2_router_command::output(
            &mut ssh,
            std::time::Instant::now() + std::time::Duration::from_secs(15),
            64,
        )?;
        let wan = wan.trim();
        if !safe_wan(wan) {
            return Err(invalid("не удалось определить WAN-интерфейс VPN-сервера"));
        }
        edit_document(db, |doc| {
            let target = doc["servers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == row["id"])
                .ok_or_else(|| invalid("профиль удалён"))?;
            if target != row {
                return Err(invalid("профиль изменился во время определения WAN"));
            }
            target["config"]["wan_iface"] = json!(wan);
            Ok(())
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rt, db, id);
        Ok(())
    }
}
