//! ICMP replies are only an ordering hint for a real AWG retry.
use super::{conf, usable_endpoint_ip};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    thread,
    time::Instant,
};

#[cfg(target_os = "linux")]
pub(super) fn collect(pool: &[String], wan: &[String]) -> Vec<bool> {
    use nfqws2_router_command::{Runner, System};
    const IP_FULL: &str = "/opt/libexec/ip-full";
    let tool = if std::path::Path::new(IP_FULL).is_file() {
        IP_FULL
    } else {
        "ip"
    };
    collect_with(
        pool,
        wan,
        tool,
        Instant::now() + std::time::Duration::from_secs(2),
        crate::endpoint::cached_endpoint_address,
        |program, args, deadline| System.run_bounded(program, args, deadline, 128 << 10),
    )
}

fn collect_with(
    pool: &[String],
    wan: &[String],
    ip_tool: &str,
    deadline: Instant,
    cached: impl Fn(&str) -> Option<SocketAddr>,
    run: impl Fn(&str, &[&str], Instant) -> io::Result<String> + Sync,
) -> Vec<bool> {
    let ips: Vec<_> = pool
        .iter()
        .take(super::MAX_BACKUPS + 1)
        .map(|candidate| {
            let (host, port) = conf::endpoint(candidate).ok()?;
            let ip = host
                .parse::<IpAddr>()
                .ok()
                .or_else(|| {
                    cached(candidate)
                        .filter(|addr| addr.port() == port)
                        .map(|addr| addr.ip())
                })?
                .to_canonical();
            usable_endpoint_ip(ip).then_some(ip)
        })
        .collect();
    if ips.iter().all(Option::is_none) {
        return Vec::new();
    }
    let netifd = if wan.is_empty() {
        let Ok(dump) = run("ubus", &["call", "network.interface", "dump"], deadline) else {
            return Vec::new();
        };
        Some(dump)
    } else {
        None
    };
    let probe = |ip| probe_wan(ip, wan, netifd.as_deref(), ip_tool, deadline, &run);
    thread::scope(|scope| {
        let probe = &probe;
        let workers: Vec<_> = ips
            .into_iter()
            .map(|ip| {
                ip.and_then(|ip| {
                    thread::Builder::new()
                        .spawn_scoped(scope, move || probe(ip))
                        .ok()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.is_some_and(|handle| handle.join().unwrap_or(false)))
            .collect()
    })
}

fn probe_wan(
    ip: IpAddr,
    wan: &[String],
    netifd: Option<&str>,
    ip_tool: &str,
    deadline: Instant,
    run: &impl Fn(&str, &[&str], Instant) -> io::Result<String>,
) -> bool {
    let family = if ip.is_ipv4() { "-4" } else { "-6" };
    let target = ip.to_string();
    let Ok(route) = run(ip_tool, &[family, "route", "get", &target], deadline) else {
        return false;
    };
    let Some(dev) = super::super::physical_wan(&route, ip, wan, netifd) else {
        return false;
    };
    // Bind to the verified interface and never modify the FIB for this hint.
    // An endpoint that requires a marked VPN socket stays in the retry pool.
    let args = ["-I", dev, "-c", "1", "-W", "1", target.as_str()];
    if ip.is_ipv4() {
        return run("ping", &args, deadline).is_ok();
    }
    match run("ping6", &args, deadline) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => run(
            "ping",
            &["-6", "-I", dev, "-c", "1", "-W", "1", &target],
            deadline,
        )
        .is_ok(),
        result => result.is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn uses_only_numeric_cache_and_wan_and_falls_back_from_missing_ping6() {
        let pool = [
            "cached.test:2408",
            "[2001:db8::3]:2408",
            "192.0.2.4:2408",
            "uncached.test:2408",
            "127.0.0.1:2408",
            "wrong-port.test:2408",
            "192.0.2.7:2408",
        ]
        .map(str::to_owned);
        let calls = Mutex::new(Vec::new());
        let deadline = Instant::now();
        let hints = collect_with(
            &pool,
            &["wan.2".into()],
            "ip",
            deadline,
            |candidate| match candidate {
                "cached.test:2408" => Some("[::ffff:192.0.2.1]:2408".parse().unwrap()),
                "wrong-port.test:2408" => Some("192.0.2.6:2409".parse().unwrap()),
                _ => None,
            },
            |prog, args, until| {
                assert_eq!(until, deadline);
                calls
                    .lock()
                    .unwrap()
                    .push((prog.to_owned(), args.join(" ")));
                match (prog, args) {
                    ("ip", ["-4", "route", "get", "192.0.2.4"]) => Ok("192.0.2.4 dev awg1".into()),
                    ("ip", ["-4" | "-6", "route", "get", ip]) => {
                        Ok(format!("{ip} via gateway dev wan.2"))
                    }
                    ("ping6", _) => Err(io::ErrorKind::NotFound.into()),
                    ("ping", ["-I", "wan.2", "-c", "1", "-W", "1", "192.0.2.7"]) => {
                        Err(io::ErrorKind::TimedOut.into())
                    }
                    (
                        "ping",
                        ["-6", "-I", "wan.2", "-c", "1", "-W", "1", "2001:db8::3"]
                        | ["-I", "wan.2", "-c", "1", "-W", "1", "192.0.2.1"],
                    ) => Ok(String::new()),
                    _ => panic!("unexpected call {prog} {args:?}"),
                }
            },
        );
        assert_eq!(hints, [true, true, false, false, false, false, false]);
        let calls = calls.into_inner().unwrap();
        assert_eq!(calls.len(), 8);
        assert!(!calls
            .iter()
            .any(|(_, args)| args.contains("127.0.0.1") || args.contains("192.0.2.6")));
    }

    #[test]
    fn netifd_must_confirm_the_wan_default_for_the_probed_family() {
        let pool = ["192.0.2.1:2408", "[2001:db8::3]:2408"].map(str::to_owned);
        let hints = collect_with(
            &pool,
            &[],
            "ip",
            Instant::now(),
            |_| None,
            |prog, args, _| {
                match (prog, args) {
                ("ubus", ["call", "network.interface", "dump"]) => Ok(
                    r#"{"interface":[{"up":true,"l3_device":"wan0","route":[{"target":"0.0.0.0","mask":0}]}]}"#.into(),
                ),
                ("ip", ["-4" | "-6", "route", "get", ip]) => Ok(format!("{ip} dev wan0")),
                ("ping", ["-I", "wan0", "-c", "1", "-W", "1", "192.0.2.1"]) => Ok(String::new()),
                _ => panic!("unexpected call {prog} {args:?}"),
            }
            },
        );
        assert_eq!(hints, [true, false]);
    }
}
