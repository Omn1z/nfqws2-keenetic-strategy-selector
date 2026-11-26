//! Compile operator-supplied, scoped NFQWS2 profiles into configuration data.
//! The compiler does no I/O and never invokes a shell or a traffic generator.
mod cli;
pub use cli::cli;
mod profiles;
mod zones;
pub use nfqws2_config::service_profiles::{Compiled, Request};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io,
};

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}
fn name_and_id(name: &mut String, id: &str, seen: &mut HashSet<String>) -> io::Result<()> {
    *name = name.trim().into();
    if name.is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
        return Err(bad(
            "имя сервиса или группы должно содержать от 1 до 120 символов",
        ));
    }
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || i > 0 && matches!(b, b'-' | b'_'))
        || !seen.insert(id.to_ascii_lowercase())
    {
        return Err(bad("неверный или повторяющийся ID сервиса или группы"));
    }
    Ok(())
}
pub fn compile(req: Request) -> io::Result<Compiled> {
    let Request {
        mut services,
        source,
        lists_dir,
    } = req;
    if services.len() > 64 || source.len() > 16 << 20 {
        return Err(bad("превышен размер конфигурации сервисов"));
    }
    let mut ids = HashSet::new();
    let mut lists = BTreeMap::new();
    let mut zones = zones::Zones::default();
    let (mut total_entries, mut strategy_bytes, mut group_index, mut profiles) = (0, 0, 0, 0);
    let mut output = Vec::new();
    let mut ports: [profiles::Ports; 2] = Default::default();
    let mut kinds = [false; 2];
    let mut remaining = 16 << 20;
    for service in &mut services {
        name_and_id(&mut service.name, &service.id, &mut ids)?;
        if service.groups.len() > 32 {
            return Err(bad("допустимо до 32 групп в сервисе"));
        }
        let mut groups = HashSet::new();
        for group in &mut service.groups {
            group_index += 1;
            name_and_id(&mut group.name, &group.id, &mut groups)?;
            let domains = match group.kind.as_str() {
                "domains" => true,
                "ips" => false,
                _ => return Err(bad("неверный тип группы")),
            };
            total_entries += group.entries.len();
            strategy_bytes += group.strategy.len();
            if group.entries.len() > 2048
                || total_entries > 32768
                || group.strategy.len() > 32768
                || strategy_bytes > 1 << 20
            {
                return Err(bad("превышен размер стратегии или списка группы"));
            }
            let mut seen = HashSet::new();
            let mut entries = vec![];
            for raw in std::mem::take(&mut group.entries) {
                if raw.len() > 512 {
                    return Err(bad("слишком длинная запись списка"));
                }
                let entry = raw.trim();
                if entry.is_empty() || entry.starts_with('#') {
                    continue;
                }
                let normalized = if domains {
                    zones::domain(entry)?
                } else {
                    zones::ip(entry)?
                };
                if seen.insert(normalized.clone()) {
                    if service.enabled {
                        zones.record(domains, &normalized, group_index)?;
                    }
                    entries.push(normalized);
                }
            }
            group.entries = entries;
            group.strategy = group.strategy.trim().into();
            profiles::valid_text(&group.strategy)?;
            if !service.enabled || group.entries.is_empty() && group.strategy.is_empty() {
                continue;
            }
            if group.entries.is_empty() || group.strategy.is_empty() {
                return Err(bad("укажите список и стратегию для включённой группы"));
            }
            if lists_dir.is_empty()
                || lists_dir.len() > 4096
                || lists_dir.contains(|c: char| c.is_whitespace() || c.is_control())
            {
                return Err(bad("недопустимый путь к спискам"));
            }
            let content = group.entries.join("\n") + "\n";
            let digest = Sha256::digest(content.as_bytes());
            let prefix = u64::from_be_bytes(digest[..8].try_into().unwrap());
            let filename = format!(
                "n2s_service_{}_{}_{}_{prefix:016x}.list",
                service.id, group.id, group.kind
            );
            if lists.insert(filename.clone(), content).is_some() {
                return Err(bad("совпали имена списков двух сервисов"));
            }
            kinds[usize::from(domains)] = true;
            let flag = if domains { "--hostlist" } else { "--ipset" };
            let path = format!("{flag}={}/{filename}", lists_dir.trim_end_matches('/'));
            profiles += profiles::append(
                &group.strategy,
                &path,
                &mut output,
                &mut ports,
                &mut remaining,
            )?;
        }
    }
    zones.check()?;
    let mut config = source;
    if let Some(range) = nfqws2_config::managed_service_config_range(&config)? {
        config.replace_range(range, "");
    }
    let mut merged = [String::new(), String::new()];
    let mut adds = [false; 2];
    for (i, key) in ["TCP_PORTS", "UDP_PORTS"].into_iter().enumerate() {
        let extra = ports[i].formatted(false)?;
        let original = nfqws2_config::literal_shell_config_value(&config, key);
        if extra.is_empty() {
            merged[i] = original.ok().flatten().unwrap_or_default();
            continue;
        }
        let base = original?.unwrap_or_default();
        if !base.trim().is_empty() {
            ports[i].add(&base, true)?;
        }
        merged[i] = ports[i].formatted(true)?;
        adds[i] = true;
    }
    let args = output.join(" ");
    if profiles > 0 {
        if config.is_empty() {
            return Err(bad("не найден конфиг NFQWS2"));
        }
        if !config.ends_with('\n') {
            config.push('\n');
        }
        config.push_str("# BEGIN N2S SERVICE STRATEGIES\nNFQWS_ARGS_CUSTOM=\"");
        for ch in args.chars() {
            if matches!(ch, '\\' | '"' | '$' | '\x60') {
                config.push('\\');
            }
            config.push(ch);
        }
        config.push_str("${NFQWS_ARGS_CUSTOM:+ --new }${NFQWS_ARGS_CUSTOM}\"\n");
        for (i, key) in ["TCP_PORTS", "UDP_PORTS"].into_iter().enumerate() {
            if adds[i] {
                config.push_str(&format!("{key}='{}'\n", merged[i]));
            }
        }
        config.push_str("# END N2S SERVICE STRATEGIES\n");
        nfqws2_config::managed_service_config_range(&config)?;
        if config.len() > 16 << 20 {
            return Err(bad("слишком большой конфиг NFQWS2"));
        }
    }
    let [tcp_ports, udp_ports] = merged;
    let warnings = if kinds == [true, true] {
        vec!["Доменные и IP-зоны могут пересекаться после DNS-разрешения; при пересечении применяется первый подходящий профиль в порядке сервисов и групп.".into()]
    } else {
        vec![]
    };
    Ok(Compiled {
        services,
        lists,
        config,
        args,
        tcp_ports,
        udp_ports,
        profiles,
        warnings,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn example() -> Value {
        json!({"source":"TCP_PORTS='80'\nUDP_PORTS='443'\n","lists_dir":"/opt/etc/nfqws2/lists","services":[{"id":"svc","name":"  Test  ","enabled":true,"groups":[{"id":"g","name":"Group","kind":"domains","entries":["# note","*.Example.test.","example.test"],"strategy":"--filter-tcp=443 --new --filter-udp=443"}]}]})
    }
    #[test]
    fn scoped_files_are_deterministic_and_recompilation_is_idempotent() {
        let mut req = example();
        let out = compile(serde_json::from_value(req.clone()).unwrap()).unwrap();
        assert_eq!(out.profiles, 2);
        assert_eq!(out.tcp_ports, "80,443");
        assert_eq!(out.services[0].name, "Test");
        assert_eq!(out.lists.values().next().unwrap(), "example.test\n");
        assert!(out
            .args
            .starts_with("--hostlist=/opt/etc/nfqws2/lists/n2s_service_svc_g_domains_"));
        req["source"] = json!(out.config);
        assert_eq!(
            compile(serde_json::from_value(req.clone()).unwrap())
                .unwrap()
                .config,
            out.config
        );
        req["services"][0]["enabled"] = json!(false);
        let off = compile(serde_json::from_value(req).unwrap()).unwrap();
        assert_eq!(off.profiles, 0);
        assert_eq!(off.config, example()["source"]);
        assert!(off.lists.is_empty());
    }
}
