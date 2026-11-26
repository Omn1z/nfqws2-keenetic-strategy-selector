use super::{conf, invalid, s};
use base64ct::{Base64UrlUnpadded, Encoding};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

const MAX_PROFILE_SIZE: usize = 4 * 1024 * 1024;

pub fn parse(text: &str, now: u64) -> io::Result<Value> {
    if text.len() > MAX_PROFILE_SIZE {
        return Err(invalid("слишком большой файл профиля"));
    }
    let Some(token) = text
        .split_whitespace()
        .find(|t| t.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("vpn://")))
    else {
        return conf::parse(text, now);
    };
    let raw = Base64UrlUnpadded::decode_vec(token[6..].trim_end_matches('='))
        .map_err(|_| invalid("неверный Base64 в .vpn"))?;
    // Like Go, treat the qCompress length as metadata and bound the actual output.
    let payload = raw
        .get(4..)
        .filter(|payload| !payload.is_empty())
        .ok_or_else(|| invalid("неверная длина .vpn"))?;
    let mut doc = Vec::new();
    ZlibDecoder::new(payload)
        .take(MAX_PROFILE_SIZE as u64 + 1)
        .read_to_end(&mut doc)
        .map_err(|_| invalid("неверное сжатие .vpn"))?;
    if doc.len() > MAX_PROFILE_SIZE {
        return Err(invalid("неверный размер .vpn"));
    }
    let root: Value =
        serde_json::from_slice(&doc).map_err(|_| invalid("неверный документ .vpn"))?;
    let (kind, proto) = root["containers"]
        .as_array()
        .into_iter()
        .flatten()
        .rev()
        .flat_map(|c| [("awg", &c["awg"]), ("wireguard", &c["wireguard"])])
        .find(|(_, p)| !p["last_config"].is_null())
        .ok_or_else(|| invalid("контейнер профиля отсутствует"))?;
    let last = match &proto["last_config"] {
        Value::String(v) => serde_json::from_str(v).map_err(|_| invalid("неверный last_config"))?,
        v => v.clone(),
    };
    let mtu = match &last["mtu"] {
        Value::Null => None,
        Value::String(value) if value.trim().is_empty() => None,
        value => Some(
            value
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .or_else(|| value.as_str()?.trim().parse().ok())
                .filter(|v| *v >= 576)
                .ok_or_else(|| invalid("неверный MTU в .vpn"))?,
        ),
    };
    let protocol_version = (kind == "awg")
        .then(|| s(proto, "protocol_version"))
        .filter(|version| !version.is_empty())
        .or_else(|| {
            last["protocol_version"]
                .as_str()
                .filter(|version| !version.is_empty())
        });
    if protocol_version.is_some_and(|version| !matches!(version, "1.0" | "1.5" | "2" | "3.1")) {
        return Err(invalid("неизвестная версия .vpn"));
    }
    conf::parse_with_overrides(
        s(&last, "config"),
        now,
        conf::ImportOverrides {
            dns: Some([s(&root, "dns1"), s(&root, "dns2")]),
            mtu,
            protocol_version,
        },
    )
}
pub fn encode(cfg: &Value, peer: &Value, text: String, name: &str, mtu: u64) -> io::Result<String> {
    let endpoint = s(cfg, "endpoint").trim();
    let host = endpoint
        .rsplit_once(':')
        .filter(|(host, _)| !host.is_empty())
        .map_or(endpoint, |(host, _)| host);
    let mut dns = s(cfg, "dns")
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty());
    let (dns1, dns2) = match dns.next() {
        Some(first) => (first, dns.next().unwrap_or(first)),
        None => ("1.1.1.1", "1.0.0.1"),
    };
    let awg = s(cfg, "protocol") != "wireguard" && cfg["traffic_obfuscation"] != false;
    let port = cfg["listen_port"].as_u64().unwrap_or(51820);
    let mut last = json!({"config":text,"hostName":host,"port":port,"client_ip":s(peer,"address"),"client_priv_key":s(peer,"private_key"),
        "client_pub_key":s(peer,"public_key"),"server_pub_key":s(cfg,"public_key"),"mtu":mtu.to_string()});
    let mut in_iface = true;
    for l in text.lines() {
        if l == "[Peer]" {
            in_iface = false;
            continue;
        }
        let Some((k, v)) = l.split_once(" = ") else {
            continue;
        };
        match k {
            "PrivateKey" | "Address" | "DNS" | "MTU" | "PublicKey" | "Endpoint" => (),
            "AllowedIPs" => {
                last["allowed_ips"] = json!(v.split(',').map(str::trim).collect::<Vec<_>>())
            }
            "PersistentKeepalive" => last["persistent_keep_alive"] = json!(v),
            "PresharedKey" => last["psk_key"] = json!(v),
            _ if in_iface && awg => last[k] = json!(v),
            _ => (),
        }
    }
    let protocol = if awg { "awg" } else { "wireguard" };
    let container = format!("amnezia-{protocol}");
    if awg {
        last["isObfuscationEnabled"] = json!(true);
    }
    let mut p = json!({"last_config":last.to_string(),"isThirdPartyConfig":true,"port":port.to_string(),"transport_proto":"udp"});
    if awg {
        let ver = conf::effective_protocol_version(cfg);
        if !matches!(ver, "" | "1.0") {
            p["protocol_version"] = json!(ver);
        }
    }
    let root = json!({"description":name,"dns1":dns1,"dns2":dns2,"hostName":host,"defaultContainer":container,
        "containers":[{"container":container,(protocol):p}]});
    let plain = serde_json::to_vec(&root)?;
    let mut compressed = ZlibEncoder::new(
        (plain.len() as u32).to_be_bytes().to_vec(),
        Compression::default(),
    );
    compressed.write_all(&plain)?;
    Ok(format!(
        "vpn://{}",
        Base64UrlUnpadded::encode_string(&compressed.finish()?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(plain: &[u8], declared_len: u32) -> String {
        let mut compressed =
            ZlibEncoder::new(declared_len.to_be_bytes().to_vec(), Compression::default());
        compressed.write_all(plain).unwrap();
        format!(
            "vpn://{}",
            Base64UrlUnpadded::encode_string(&compressed.finish().unwrap())
        )
    }

    #[test]
    fn vpn_export_keeps_applied_mtu_and_uses_current_routing_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::Store::open(dir.path()).unwrap();
        let mut active = conf::parse(&crate::tests::input(), 0).unwrap();
        active["routing"]["mtu"] = json!(1400);
        active["dns"] = json!("192.0.2.60");
        let mut applied = active.clone();
        applied["routing"]["mtu"] = json!(1300);
        applied["dns"] = json!("192.0.2.61");
        for (wire_mtu, expected) in [(0, "1400"), (1370, "1370")] {
            applied["mtu"] = json!(wire_mtu);
            crate::edit_document(&store, |doc| {
                doc["servers"][0]["config"] = active.clone();
                doc["servers"][0]["applied_config"] = applied.clone();
                Ok(())
            })
            .unwrap();
            let (uri, _) = crate::peer_export(&store, "router", "vpn").unwrap();
            let raw = Base64UrlUnpadded::decode_vec(uri.strip_prefix("vpn://").unwrap()).unwrap();
            let root: Value = serde_json::from_reader(ZlibDecoder::new(&raw[4..])).unwrap();
            let last: Value = serde_json::from_str(
                root["containers"][0]["wireguard"]["last_config"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(root["dns1"], "192.0.2.61");
            assert_eq!(last["mtu"], expected);
            assert_eq!(
                last["config"].as_str().unwrap().contains("MTU = "),
                wire_mtu != 0
            );
        }
    }

    #[test]
    fn export_and_status_agree_on_inferred_awg_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::Store::open(dir.path()).unwrap();
        let runtime = crate::runtime::Runtime::new(dir.path(), dir.path().join("absent"));
        let base = conf::parse(&crate::tests::input(), 0).unwrap();
        for (metadata, field, value, expected) in [
            ("", "s3", json!(0), "1.0"),
            ("", "i1", json!("<r 2>"), "1.5"),
            ("", "s3", json!(12), "2"),
            ("1.5", "rekey_after_time", json!("100-120"), "3.1"),
        ] {
            let mut cfg = base.clone();
            cfg["protocol"] = json!("awg");
            cfg["traffic_obfuscation"] = json!(true);
            cfg["protocol_version"] = json!(metadata);
            cfg["obf"][field] = value;
            crate::edit_document(&store, |doc| {
                doc["servers"][0]["config"] = cfg;
                Ok(())
            })
            .unwrap();
            let view = crate::status(&store, &runtime).unwrap();
            assert_eq!(view["servers"][0]["protocol_version"], expected);
            assert_eq!(view["config"]["protocol_version"], metadata);
            let (uri, _) = crate::peer_export(&store, "router", "vpn").unwrap();
            let raw = Base64UrlUnpadded::decode_vec(uri.strip_prefix("vpn://").unwrap()).unwrap();
            let root: Value = serde_json::from_reader(ZlibDecoder::new(&raw[4..])).unwrap();
            let version = root["containers"][0]["awg"]["protocol_version"].as_str();
            assert_eq!(version, (expected != "1.0").then_some(expected));
        }
    }

    #[test]
    fn exported_amnezia_metadata_matches_go_dns_defaults_and_ipv6_authority() {
        let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
        let peer = cfg["peers"][0].clone();
        for (saved, expected) in [
            ("", ["1.1.1.1", "1.0.0.1"]),
            (" , 192.0.2.60 ,", ["192.0.2.60", "192.0.2.60"]),
            (" , 192.0.2.61, , 2001:db8::52, 192.0.2.63", ["192.0.2.61", "2001:db8::52"]),
        ] {
            cfg["dns"] = json!(saved);
            let conf = conf::export(&cfg, &peer).unwrap();
            let mtu = crate::tunnel_mtu(&cfg, &cfg["routing"]);
            let uri = encode(&cfg, &peer, conf, "fixture", mtu).unwrap();
            let raw = Base64UrlUnpadded::decode_vec(uri.strip_prefix("vpn://").unwrap()).unwrap();
            let root: Value = serde_json::from_reader(ZlibDecoder::new(&raw[4..])).unwrap();
            assert_eq!(root["dns1"], expected[0]);
            assert_eq!(root["dns2"], expected[1]);
            assert_eq!(root["hostName"], "[2001:db8::1]");
            let protocol = if root["defaultContainer"] == "amnezia-awg" { "awg" } else { "wireguard" };
            let wire: Value = serde_json::from_str(
                root["containers"][0][protocol]["last_config"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(wire["hostName"], "[2001:db8::1]");
            assert!(wire["config"].as_str().unwrap().contains("Endpoint = [2001:db8::1]:51820"));
        }
    }

    #[test]
    fn amnezia_metadata_overrides_only_its_wire_fields_before_validation() {
        struct Case<'a> {
            container: &'a str,
            embedded: &'a str,
            envelope_version: &'a str,
            last_version: &'a str,
            metadata_mtu: Value,
            expected: (&'a str, &'a str, u16),
        }
        let cases = [
            Case {
                container: "awg",
                embedded: "MTU = old\nProtocolVersion = old",
                envelope_version: "3.1",
                last_version: "2",
                metadata_mtu: json!(1320),
                expected: ("awg", "3.1", 1320),
            },
            Case {
                container: "wireguard",
                embedded: "MTU = 1372",
                envelope_version: "3.1",
                last_version: "",
                metadata_mtu: json!(""),
                expected: ("wireguard", "", 1372),
            },
            Case {
                container: "awg",
                embedded: "MTU = 1412",
                envelope_version: "",
                last_version: "2",
                metadata_mtu: json!("1340"),
                expected: ("awg", "2", 1340),
            },
            Case {
                container: "wireguard",
                embedded: "MTU = 1412",
                envelope_version: "3.1",
                last_version: "2",
                metadata_mtu: Value::Null,
                expected: ("awg", "2", 1412),
            },
        ];
        for case in cases {
            let config =
                crate::tests::input().replace("[Peer]", &format!("{}\n[Peer]", case.embedded));
            let last = json!({
                "config":config,"mtu":case.metadata_mtu,"protocol_version":case.last_version
            });
            let root = json!({"containers":[{
                (case.container):{"last_config":last.to_string(),"protocol_version":case.envelope_version}
            }]});
            let profile = link(&serde_json::to_vec(&root).unwrap(), 0);
            let state = tempfile::tempdir().unwrap();
            let store = nfqws2_store::Store::open(state.path()).unwrap();
            crate::import(&store, &profile, "Amnezia profile").unwrap();
            let document = crate::read(&store).unwrap();
            let cfg = &crate::active(&document).unwrap()["config"];
            let (protocol, version, mtu) = case.expected;
            assert_eq!(cfg["protocol"], protocol);
            assert_eq!(cfg["protocol_version"], version);
            assert_eq!(cfg["mtu"], mtu);
            assert_eq!(cfg["client"]["enabled"], false);
            let (conf, _) = crate::peer_export(&store, "router", "conf").unwrap();
            assert!(conf.contains(&format!("\nMTU = {mtu}\n")));
            assert!(!conf.contains("ProtocolVersion"));
        }
    }

    #[test]
    fn imports_go_vpn_with_zero_length_and_only_one_dns_without_starting_the_client() {
        let config = crate::tests::input().replace(
            "DNS = 192.0.2.1",
            "DNS = $PRIMARY_DNS, $SECONDARY_DNS\nRandomTrailers = off",
        );
        let last = json!({"config":config,"mtu":1320,"port":51820});
        let mut root = json!({"dns1":"9.9.9.9","containers":[{"awg":{
            "last_config":last.to_string(),"protocol_version":"3.1"
        }}]});
        let plain = serde_json::to_vec(&root).unwrap();
        let legacy = link(&plain, 0);
        let state = tempfile::tempdir().unwrap();
        let store = nfqws2_store::Store::open(state.path()).unwrap();
        crate::import(&store, &legacy, "saved Go profile").unwrap();
        let document = crate::read(&store).unwrap();
        let cfg = &crate::active(&document).unwrap()["config"];
        assert_eq!(cfg["dns"], "9.9.9.9");
        assert_eq!(cfg["mtu"], 1320);
        assert_eq!(cfg["protocol_version"], "3.1");
        assert_eq!(cfg["obf"]["random_trailers"], false);
        assert_eq!(cfg["client"]["enabled"], false);
        assert_eq!(cfg["peers"][0]["keepalive_range"], "0");

        let canonical = link(&plain, plain.len() as u32);
        let cfg = parse(&canonical, 5).unwrap();
        assert_eq!(parse(&legacy, 5).unwrap(), cfg);
        assert_eq!(parse(&link(&plain, u32::MAX), 5).unwrap(), cfg);

        root["dns1"] = json!("9.9.9.9\nListenPort = 1234");
        assert!(parse(&link(&serde_json::to_vec(&root).unwrap(), 0), 5).is_err());
    }

    #[test]
    fn legacy_vpn_without_a_declared_length_still_has_a_decompression_limit() {
        let oversized = link(&vec![b' '; MAX_PROFILE_SIZE + 1], 0);
        let error = parse(&oversized, 5).unwrap_err();
        assert_eq!(error.to_string(), "неверный размер .vpn");
    }
}
