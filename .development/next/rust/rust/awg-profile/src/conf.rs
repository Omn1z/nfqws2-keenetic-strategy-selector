use super::{invalid, s};
use base64ct::{Base64, Encoding};
use curve25519_dalek::montgomery::MontgomeryPoint;
use serde_json::{json, Value};
use std::{borrow::Cow, collections::BTreeMap, io, net::IpAddr};

const MAX_CONF_SIZE: usize = 256 * 1024;

pub(crate) const EXTENSIONS: &[(&str, &str)] = &[
    ("Jc", "jc"),
    ("Jmin", "jmin"),
    ("Jmax", "jmax"),
    ("S1", "s1"),
    ("S2", "s2"),
    ("S3", "s3"),
    ("S4", "s4"),
    ("H1", "h1"),
    ("H2", "h2"),
    ("H3", "h3"),
    ("H4", "h4"),
    ("I1", "i1"),
    ("I2", "i2"),
    ("I3", "i3"),
    ("I4", "i4"),
    ("I5", "i5"),
    ("HeaderProtectionKey", "header_protection_key"),
    ("ContentPaddingAddition", "content_padding_addition"),
    ("RekeyAfterTime", "rekey_after_time"),
    ("RekeyTimeout", "rekey_timeout"),
    ("RejectAfterTime", "reject_after_time"),
    ("KeepaliveTimeout", "keepalive_timeout"),
    ("MaxHandshakeAttempts", "max_handshake_attempts"),
    ("RandomTrailers", "random_trailers"),
    ("DisableCookies", "disable_cookies"),
];
type Fields<'a> = BTreeMap<&'a str, Cow<'a, str>>;
fn sections(text: &str) -> io::Result<(Fields<'_>, Fields<'_>)> {
    if text.len() > MAX_CONF_SIZE {
        return Err(invalid("профиль превышает 256 КиБ"));
    }
    let mut iface = Fields::new();
    let mut peer = Fields::new();
    let mut section = 0;
    let mut seen = [false; 2];
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.trim();
            section = if name.eq_ignore_ascii_case("Interface") {
                1
            } else if name.eq_ignore_ascii_case("Peer") {
                2
            } else {
                return Err(invalid("неизвестная секция профиля"));
            };
            if std::mem::replace(&mut seen[section - 1], true) {
                return Err(invalid("нужен один Interface и один Peer"));
            }
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| invalid("неверная строка профиля"))?;
        let (k, v) = (k.trim(), v.trim());
        if v.chars().any(char::is_control) {
            return Err(invalid("неверное значение поля"));
        }
        // The panel owns routing and profile storage. These wg-quick options
        // are informational on import and never reach the local engine.
        if section == 1 && matches!(k, "Table" | "SaveConfig" | "FwMark") {
            continue;
        }
        let map = match section {
            1 => &mut iface,
            2 => &mut peer,
            _ => return Err(invalid("нет заголовка секции")),
        };
        let allowed = if section == 1 {
            matches!(
                k,
                "PrivateKey" | "Address" | "DNS" | "MTU" | "ListenPort" | "ProtocolVersion"
            ) || EXTENSIONS.iter().any(|(name, _)| *name == k)
        } else {
            matches!(
                k,
                "PublicKey" | "PresharedKey" | "Endpoint" | "AllowedIPs" | "PersistentKeepalive"
            )
        };
        if !allowed {
            return Err(invalid("неподдерживаемая директива в профиле"));
        } // Never load wg-quick shell hooks.
        if let Some(previous) = map.get_mut(k) {
            if !matches!(k, "Address" | "AllowedIPs" | "DNS") {
                return Err(invalid("повторяющееся поле профиля"));
            }
            let previous = previous.to_mut();
            previous.push_str(", ");
            previous.push_str(v);
        } else {
            map.insert(k, Cow::Borrowed(v));
        }
    }
    if !seen.into_iter().all(|v| v) {
        return Err(invalid("нужны секции Interface и Peer"));
    }
    Ok((iface, peer))
}
pub(crate) fn key(v: &str, allow_zero: bool) -> io::Result<[u8; 32]> {
    let mut raw = [0; 32];
    if Base64::decode(v, &mut raw).map_or(true, |v| v.len() != 32)
        || (!allow_zero && raw == [0; 32])
    {
        return Err(invalid(
            "неверный ключ WireGuard: требуется 32 байта в Base64",
        ));
    }
    Ok(raw)
}
pub(crate) fn cidrs(v: &str, require_prefix: bool) -> io::Result<()> {
    for item in v.split(',').map(str::trim) {
        let (ip, prefix) = item
            .split_once('/')
            .map_or((item, None), |(ip, p)| (ip, Some(p)));
        let ip: IpAddr = ip.parse().map_err(|_| invalid("неверный IP-адрес"))?;
        if let Some(p) = prefix {
            if p.parse::<u8>()
                .ok()
                .is_none_or(|n| n > if ip.is_ipv4() { 32 } else { 128 })
            {
                return Err(invalid("неверная маска адреса"));
            }
        } else if require_prefix {
            return Err(invalid("для AllowedIPs требуется префикс"));
        }
    }
    Ok(())
}
pub(crate) fn hostname(s: &str) -> bool {
    s.len() <= 253
        && !s.is_empty()
        && s.trim_end_matches('.').split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub(crate) fn endpoint(s: &str) -> io::Result<(&str, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| invalid("Endpoint без порта"))?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|v| *v != 0)
        .ok_or_else(|| invalid("неверный порт Endpoint"))?;
    if let Some(host) = host.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok((host, port));
        }
    } else if hostname(host) {
        return Ok((host, port));
    }
    Err(invalid("неверный адрес Endpoint"))
}
pub(crate) fn range(v: &str, max: u32) -> io::Result<String> {
    let num = |s: &str| {
        s.trim()
            .strip_prefix("0x")
            .map(|n| u32::from_str_radix(n, 16))
            .unwrap_or_else(|| s.trim().parse())
            .ok()
            .filter(|v| *v <= max)
            .ok_or_else(|| invalid("неверное число в параметрах AWG"))
    };
    if let Some((lo, hi)) = v.split_once('-') {
        let (lo, hi) = (num(lo)?, num(hi)?);
        if lo > hi {
            return Err(invalid("неверный диапазон AWG"));
        }
        Ok(format!("{lo}-{hi}"))
    } else {
        Ok(num(v)?.to_string())
    }
}
pub(crate) fn extension(k: &str, v: &str) -> io::Result<Value> {
    match k {
        "Jc" | "Jmin" | "Jmax" | "S1" | "S2" | "S3" | "S4" => v
            .parse::<u16>()
            .ok()
            .filter(|n| *n <= if k == "Jc" { 128 } else { 1280 })
            .map(|v| json!(v))
            .ok_or_else(|| invalid("размеры AWG вне диапазона")),
        "H1" | "H2" | "H3" | "H4" => Ok(json!(range(v, u32::MAX)?)),
        "HeaderProtectionKey" => {
            key(v, true)?;
            Ok(json!(v))
        }
        "DisableCookies" | "RandomTrailers" => match v.to_ascii_lowercase().as_str() {
            "on" | "true" | "1" => Ok(json!(true)),
            "off" | "false" | "0" => Ok(json!(false)),
            _ => Err(invalid("ожидается on/off")),
        },
        "I1" | "I2" | "I3" | "I4" | "I5" => {
            let mut rest = v.trim();
            while !rest.is_empty() {
                let (tag, tail) = rest
                    .strip_prefix('<')
                    .and_then(|s| s.split_once('>'))
                    .ok_or_else(|| invalid("неверный тег AWG"))?;
                let words: Vec<_> = tag.split_ascii_whitespace().collect();
                if !match words.as_slice() {
                    ["t"] => true,
                    ["b", hex] => hex.strip_prefix("0x").is_some_and(|v| {
                        !v.is_empty()
                            && v.len() % 2 == 0
                            && v.bytes().all(|b| b.is_ascii_hexdigit())
                    }),
                    ["r" | "rc" | "rd", n] => n.parse::<u16>().is_ok(),
                    _ => false,
                } {
                    return Err(invalid("неверный тег AWG"));
                }
                rest = tail.trim_start();
            }
            Ok(json!(v))
        }
        _ => Ok(json!(range(v, u16::MAX.into())?)),
    }
}
pub(crate) fn validate_obf(obf: &Value) -> io::Result<()> {
    if obf["jmin"].as_u64() > obf["jmax"].as_u64() {
        return Err(invalid("Jmin больше Jmax"));
    }
    if !s(obf, "header_protection_key").is_empty()
        && ["s1", "s2", "s3", "s4"]
            .iter()
            .any(|k| obf[*k].as_u64().unwrap_or(0) < 12)
    {
        return Err(invalid("HeaderProtectionKey требует S1–S4 не меньше 12"));
    }
    let mut headers = Vec::new();
    for k in ["h1", "h2", "h3", "h4"] {
        let v = s(obf, k);
        let (lo, hi) = v.split_once('-').unwrap_or((v, v));
        let lo = lo
            .parse::<u32>()
            .map_err(|_| invalid("неверный заголовок AWG"))?;
        let hi = hi
            .parse::<u32>()
            .map_err(|_| invalid("неверный заголовок AWG"))?;
        if headers.iter().any(|(a, b)| lo <= *b && *a <= hi) {
            return Err(invalid("диапазоны заголовков AWG пересекаются"));
        }
        headers.push((lo, hi));
    }
    Ok(())
}
fn has_awg31_obfuscation(obf: &Value) -> bool {
    obf["has_header_protection_key"] == true
        || obf["random_trailers"] == true
        || obf["disable_cookies"] == true
        || [
            "header_protection_key",
            "content_padding_addition",
            "rekey_after_time",
            "rekey_timeout",
            "reject_after_time",
            "keepalive_timeout",
            "max_handshake_attempts",
        ]
        .iter()
        .any(|field| obf[*field].is_number() || !s(obf, field).trim().is_empty())
}

pub(crate) fn requires_awg31(cfg: &Value) -> bool {
    cfg["protocol"] != "wireguard"
        && cfg["traffic_obfuscation"] != false
        && (cfg["protocol_version"] == "3.1"
            || has_awg31_obfuscation(&cfg["obf"])
            || cfg["peers"].as_array().into_iter().flatten().any(|peer| {
                let range = s(peer, "keepalive_range").trim();
                range.contains('-')
                    || range.is_empty() && peer["keepalive"].as_i64().is_some_and(|n| n < 0)
            }))
}

/// AWG wire version of the effective configuration, including legacy metadata.
pub fn effective_protocol_version(cfg: &Value) -> &str {
    if cfg["protocol"] == "wireguard" {
        return "";
    }
    if requires_awg31(cfg) {
        return "3.1";
    }
    let explicit = s(cfg, "protocol_version");
    if !explicit.is_empty() {
        return explicit;
    }
    let obf = &cfg["obf"];
    if has_awg31_obfuscation(obf) {
        "3.1"
    } else if ["s3", "s4"]
        .iter()
        .any(|k| obf[*k].as_u64().unwrap_or_default() > 0)
        || ["h1", "h2", "h3", "h4"]
            .iter()
            .any(|k| s(obf, k).contains('-'))
    {
        "2"
    } else if ["i1", "i2", "i3", "i4", "i5"]
        .iter()
        .any(|k| !s(obf, k).trim().is_empty())
    {
        "1.5"
    } else {
        "1.0"
    }
}

pub(crate) fn base() -> Value {
    json!({"enabled":true,"protocol":"awg","protocol_version":"3.1","traffic_obfuscation":true,"conn":{"host":"","port":22,"user":"root","auth_kind":"password","known_key":""},
        "install":"apt","private_key":"","public_key":"","listen_port":51820,"address":"10.13.13.1/24","subnet":"10.13.13.0/24","mtu":1420,"dns":"1.1.1.1, 1.0.0.1","wan_iface":"","endpoint":"",
        "obf":{"jc":4,"jmin":8,"jmax":80,"s1":0,"s2":0,"s3":0,"s4":0,"h1":"1","h2":"2","h3":"3","h4":"4","i1":"","i2":"","i3":"","i4":"","i5":""},
        "peers":[],"client":{"enabled":false,"peer_id":"","standby":false},"routing":{"mode":"off","zones":[],"mtu":1420,"domain_source":"resolve","active":false},
        "interface":"awg0","client_iface":"awg0","deployed_at":0})
}
pub fn parse(text: &str, now: u64) -> io::Result<Value> {
    parse_with_overrides(text, now, ImportOverrides::default())
}

fn expand_vpn_dns(dns: &str, replacements: [&str; 2]) -> io::Result<String> {
    let addresses = dns
        .split(',')
        .flat_map(|part| {
            let value = match part.trim() {
                "$PRIMARY_DNS" => replacements[0],
                "$SECONDARY_DNS" => replacements[1],
                value => value,
            };
            value.split(',')
        })
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut expanded = String::new();
    for address in addresses {
        let separator = if expanded.is_empty() { "" } else { ", " };
        if expanded.len() + separator.len() + address.len() > MAX_CONF_SIZE {
            return Err(invalid("слишком длинный список DNS в .vpn"));
        }
        expanded.push_str(separator);
        expanded.push_str(address);
    }
    Ok(expanded)
}

#[derive(Default)]
pub(crate) struct ImportOverrides<'a> {
    pub dns: Option<[&'a str; 2]>,
    pub mtu: Option<u16>,
    pub protocol_version: Option<&'a str>,
}

pub(crate) fn parse_with_overrides(
    text: &str,
    now: u64,
    overrides: ImportOverrides<'_>,
) -> io::Result<Value> {
    let (iface, peer) = sections(text)?;
    let get = |map: &Fields<'_>, k: &str| map.get(k).map(|s| s.to_string()).unwrap_or_default();
    let privkey = get(&iface, "PrivateKey");
    let pubkey = get(&peer, "PublicKey");
    let psk = get(&peer, "PresharedKey");
    let raw = key(&privkey, false)?;
    key(&pubkey, false)?;
    if !psk.is_empty() {
        key(&psk, true)?;
    }
    let public = Base64::encode_string(MontgomeryPoint::mul_base_clamped(raw).as_bytes());
    let remote = get(&peer, "Endpoint");
    let (_, port) = endpoint(&remote)?;
    let address = get(&iface, "Address");
    cidrs(&address, false)?;
    let allowed = peer
        .get("AllowedIPs")
        .map(|s| s.as_ref())
        .unwrap_or("0.0.0.0/0, ::/0");
    cidrs(allowed, true)?;
    let keep = range(
        peer.get("PersistentKeepalive")
            .map(|s| s.as_ref())
            .unwrap_or("25"),
        65535,
    )?;
    let mut cfg = base();
    if let Some(v) = iface.get("ListenPort") {
        cfg["client"]["listen_port"] = json!(v
            .parse::<u16>()
            .map_err(|_| invalid("неверный ListenPort"))?);
    }
    cfg["install"] = json!("imported");
    cfg["conn"] = json!({"host":"","port":0,"user":"","auth_kind":"","known_key":""});
    cfg["endpoint"] = json!(remote);
    cfg["listen_port"] = json!(port);
    cfg["public_key"] = json!(pubkey);
    cfg["deployed_at"] = json!(now);
    cfg.as_object_mut().unwrap().remove("traffic_obfuscation");
    if let Some(mtu) = overrides.mtu {
        cfg["mtu"] = json!(mtu);
    } else if let Some(mtu) = iface.get("MTU") {
        cfg["mtu"] = json!(mtu
            .parse::<u16>()
            .ok()
            .filter(|v| *v >= 576)
            .ok_or_else(|| invalid("неверный MTU"))?);
    }
    if let Some(dns) = iface.get("DNS") {
        let dns = match overrides.dns {
            Some(replacements) => Cow::Owned(expand_vpn_dns(dns, replacements)?),
            None => Cow::Borrowed(dns.as_ref()),
        };
        if !dns.is_empty() {
            if !dns
                .split(',')
                .map(str::trim)
                .all(|v| v.parse::<IpAddr>().is_ok() || hostname(v))
            {
                return Err(invalid("неверный DNS"));
            }
            cfg["dns"] = json!(dns);
        }
    }
    if let Some(ip) = address
        .split(',')
        .next()
        .and_then(|v| v.split('/').next())
        .and_then(|v| v.trim().parse::<std::net::Ipv4Addr>().ok())
    {
        let [a, b, c, _] = ip.octets();
        cfg["address"] = json!(format!("{a}.{b}.{c}.1/24"));
        cfg["subnet"] = json!(format!("{a}.{b}.{c}.0/24"));
    }
    let mut v31 = keep.contains('-');
    let mut v2 = false;
    let mut v15 = false;
    for (i, &(k, field)) in EXTENSIONS.iter().enumerate() {
        if let Some(v) = iface.get(k) {
            cfg["obf"][field] = extension(k, v)?;
            v31 |= i >= 16;
            v2 |= matches!(k, "S3" | "S4") || (k.starts_with('H') && v.contains('-'));
            v15 |= k.starts_with('I');
        } else if i < 7 {
            cfg["obf"][field] = json!(0);
        }
    }
    validate_obf(&cfg["obf"])?;
    let explicit_version = overrides
        .protocol_version
        .or_else(|| iface.get("ProtocolVersion").map(Cow::as_ref));
    let awg =
        v31 || explicit_version.is_some() || EXTENSIONS.iter().any(|(k, _)| iface.contains_key(k));
    cfg["protocol"] = json!(if awg { "awg" } else { "wireguard" });
    let version = explicit_version.unwrap_or(if v31 {
        "3.1"
    } else if v2 {
        "2"
    } else if v15 {
        "1.5"
    } else {
        "1.0"
    });
    if awg && !matches!(version, "1.0" | "1.5" | "2" | "2.0" | "3.1") {
        return Err(invalid("неизвестная версия AWG"));
    }
    cfg["protocol_version"] = json!(if awg { version } else { "" });
    cfg["peers"] = json!([{"id":"router","name":"Router (imported)","private_key":privkey,"public_key":public,"psk":psk,"address":address,"allowed_ips":allowed,
        "keepalive":keep.parse::<u16>().ok().filter(|n|*n!=0).unwrap_or(25),"is_router":true,"has_private":true,"created_at":now}]);
    if keep == "0" || keep.contains('-') {
        cfg["peers"][0]["keepalive_range"] = json!(keep);
    }
    cfg["client"]["peer_id"] = json!("router");
    Ok(cfg)
}
fn line(out: &mut String, k: &str, v: &str) -> io::Result<()> {
    if v.chars().any(char::is_control) {
        return Err(invalid("неверное поле сохранённой конфигурации"));
    }
    out.push_str(k);
    out.push_str(" = ");
    out.push_str(v);
    out.push('\n');
    Ok(())
}
pub fn export(cfg: &Value, p: &Value) -> io::Result<String> {
    render_client(cfg, p, cfg["mtu"].as_u64().filter(|v| *v > 0), None)
}
pub(super) fn export_with_mtu(cfg: &Value, p: &Value, mtu: Option<u64>) -> io::Result<String> {
    render_client(cfg, p, mtu, cfg["client"]["listen_port"].as_u64())
}
fn render_client(
    cfg: &Value,
    p: &Value,
    mtu: Option<u64>,
    listen_port: Option<u64>,
) -> io::Result<String> {
    let mut out = String::from("[Interface]\n");
    let privkey = s(p, "private_key");
    if privkey.is_empty() {
        return Err(invalid("для этого пира нет приватного ключа"));
    }
    key(privkey, false)?;
    key(s(cfg, "public_key"), false)?;
    cidrs(s(p, "address"), false)?;
    endpoint(s(cfg, "endpoint"))?;
    line(&mut out, "PrivateKey", privkey)?;
    if let Some(port) = listen_port {
        let port = u16::try_from(port).map_err(|_| invalid("неверный ListenPort"))?;
        line(&mut out, "ListenPort", &port.to_string())?;
    }
    line(&mut out, "Address", s(p, "address"))?;
    if !s(cfg, "dns").is_empty() {
        line(&mut out, "DNS", s(cfg, "dns"))?;
    }
    if let Some(mtu) = mtu {
        line(&mut out, "MTU", &mtu.to_string())?;
    }
    let awg = s(cfg, "protocol") != "wireguard" && cfg["traffic_obfuscation"] != false;
    if awg {
        write_extensions(cfg, &mut out, None)?;
    }
    out.push_str("\n[Peer]\n");
    line(&mut out, "PublicKey", s(cfg, "public_key"))?;
    if !s(p, "psk").is_empty() {
        key(s(p, "psk"), true)?;
        line(&mut out, "PresharedKey", s(p, "psk"))?;
    }
    line(&mut out, "Endpoint", s(cfg, "endpoint"))?;
    let allowed = p["allowed_ips"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("0.0.0.0/0, ::/0");
    cidrs(allowed, true)?;
    line(&mut out, "AllowedIPs", allowed)?;
    let mut keep = s(p, "keepalive_range").to_owned();
    if keep.is_empty() || (!awg && keep.contains('-')) {
        keep = p["keepalive"]
            .as_u64()
            .filter(|v| *v > 0)
            .unwrap_or(25)
            .to_string();
    }
    line(&mut out, "PersistentKeepalive", &range(&keep, 65535)?)?;
    Ok(out)
}

pub(crate) fn write_extensions(
    cfg: &Value,
    out: &mut String,
    mut normalized: Option<&mut Value>,
) -> io::Result<()> {
    for (i, &(k, f)) in EXTENSIONS.iter().enumerate() {
        let v = &cfg["obf"][f];
        let value = if i < 7 {
            let n = v.as_u64().unwrap_or(0);
            if i > 4 && n == 0 {
                continue;
            }
            n.to_string()
        } else if (7..11).contains(&i) {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map_or_else(|| (i - 6).to_string(), str::to_owned)
        } else if v == true {
            "on".into()
        } else {
            v.as_str().unwrap_or_default().into()
        };
        if !value.is_empty() {
            let field = extension(k, &value)?;
            if let Some(obf) = normalized.as_deref_mut() {
                obf[f] = field;
            }
            line(out, k, &value)?;
        }
    }
    Ok(())
}
