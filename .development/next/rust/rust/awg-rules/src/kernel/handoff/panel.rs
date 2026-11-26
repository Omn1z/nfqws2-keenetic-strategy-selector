use super::call;
use crate::model::err;
use nfqws2_router_command::Runner;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    path::Path,
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub struct PanelEndpoint(SocketAddr);

impl From<NonZeroU16> for PanelEndpoint {
    fn from(port: NonZeroU16) -> Self {
        Self(SocketAddr::from((Ipv4Addr::LOCALHOST, port.get())))
    }
}

impl FromStr for PanelEndpoint {
    type Err = io::Error;
    fn from_str(raw: &str) -> io::Result<Self> {
        if let Ok(port) = raw.parse::<NonZeroU16>() {
            return Ok(port.into());
        }
        let addr: SocketAddr = raw
            .parse()
            .map_err(|_| err("ожидался локальный адрес панели"))?;
        let ip = match addr.ip().to_canonical() {
            IpAddr::V4(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(ip) if ip.is_unspecified() => Ipv6Addr::LOCALHOST.into(),
            ip => ip,
        };
        if addr.port() == 0
            || ip.is_multicast()
            || ip == IpAddr::V4(Ipv4Addr::BROADCAST)
            || matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local())
            || matches!(addr, SocketAddr::V6(v) if v.scope_id() != 0)
        {
            return Err(err("неоднозначный локальный адрес панели"));
        }
        Ok(Self(SocketAddr::new(ip, addr.port())))
    }
}

impl PanelEndpoint {
    pub fn api(self, run: &dyn Runner, method: &str, path: &str) -> io::Result<String> {
        let ip = self.0.ip();
        let mut args = vec!["-q", "--noproxy", "*", "-fsS"];
        if !ip.is_loopback() {
            let family = if ip.is_ipv4() { "-4" } else { "-6" };
            let route = call(run, "ip", &[family, "route", "get", &ip.to_string()])?;
            let mut fields = route.lines().next().unwrap_or("").split_whitespace();
            if fields.next() != Some("local")
                || fields.next().and_then(|s| s.parse::<IpAddr>().ok()) != Some(ip)
                || !fields
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|w| w == ["dev", "lo"])
            {
                return Err(err("адрес панели не принадлежит этому маршрутизатору"));
            }
            // Keep the connection on loopback even if the address disappears
            // between the kernel route lookup and connect(2).
            args.extend(["--interface", "lo"]);
        }
        let seconds = if method == "POST" { 35 } else { 6 };
        let timeout = seconds.to_string();
        let url = format!("http://{}/api/{path}", self.0);
        args.extend([
            "--max-filesize",
            "4194304",
            "--max-time",
            &timeout,
            "-X",
            method,
            &url,
        ]);
        run.run_bounded(
            "curl",
            &args,
            Instant::now() + Duration::from_secs(seconds + 2),
            4 << 20,
        )
    }
}

/// Match the confirmed process to the kernel's listening socket, including
/// IPv4/IPv6 wildcards and hostnames already resolved by the running panel.
pub fn listen_address(procfs: &Path, token: &str, port: NonZeroU16) -> io::Result<SocketAddr> {
    let invalid = || err("не удалось подтвердить локальный сокет панели");
    let (pid, start) = token.split_once('/').ok_or_else(invalid)?;
    let pid: u32 = pid.parse().map_err(|_| invalid())?;
    let start: u64 = start.parse().map_err(|_| invalid())?;
    if pid <= 1 || start == 0 {
        return Err(invalid());
    }
    let dir = procfs.join(pid.to_string());
    let check_process = || -> io::Result<()> {
        let stat = fs::read_to_string(dir.join("stat"))?;
        let ticks = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19));
        if ticks.and_then(|t| t.parse().ok()) == Some(start) {
            Ok(())
        } else {
            Err(invalid())
        }
    };
    check_process()?;
    let mut sockets = BTreeMap::new();
    for (table, width) in [("tcp", 8), ("tcp6", 32)] {
        let file = match fs::File::open(dir.join("net").join(table)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            other => other?,
        };
        for line in io::BufReader::new(file).lines() {
            let line = line?;
            let mut cols = line.split_whitespace();
            let Some((address, raw_port)) = cols.nth(1).and_then(|s| s.split_once(':')) else {
                continue;
            };
            if cols.nth(1) != Some("0A")
                || u16::from_str_radix(raw_port, 16).ok() != Some(port.get())
            {
                continue;
            }
            let inode = cols
                .nth(5)
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(invalid)?;
            if address.len() != width || !address.is_ascii() || inode == 0 {
                return Err(invalid());
            }
            let mut bytes = [0; 16];
            for (word, chunk) in address.as_bytes().chunks_exact(8).zip(bytes.chunks_mut(4)) {
                let val =
                    u32::from_str_radix(std::str::from_utf8(word).map_err(|_| invalid())?, 16)
                        .map_err(|_| invalid())?;
                chunk.copy_from_slice(&val.to_ne_bytes());
            }
            let ip = if width == 8 {
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            } else {
                IpAddr::V6(Ipv6Addr::from(bytes))
            };
            sockets.insert(inode, ip);
        }
    }
    let mut owned = BTreeSet::new();
    for fd in fs::read_dir(dir.join("fd"))? {
        let link = match fs::read_link(fd?.path()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            value => value?,
        };
        if let Some(inode) = link
            .to_str()
            .and_then(|l| l.strip_prefix("socket:["))
            .and_then(|l| l.strip_suffix(']'))
            .and_then(|n| n.parse::<u64>().ok())
            .filter(|i| sockets.contains_key(i))
        {
            owned.insert(inode);
        }
    }
    check_process()?;
    if owned.len() != 1 {
        return Err(invalid());
    }
    let inode = *owned.first().unwrap();
    let address = SocketAddr::new(sockets[&inode], port.get());
    let probe = address.to_string().parse::<PanelEndpoint>()?.0.ip();
    if sockets.iter().any(|(&other, ip)| {
        let ip = ip.to_canonical();
        other != inode && (ip == probe || ip.is_unspecified() && (ip.is_ipv6() || probe.is_ipv4()))
    }) {
        return Err(invalid());
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn probe_only_contacts_the_local_listener_on_its_family() {
        struct Router<'a> {
            route: &'a str,
            curl: Mutex<Vec<String>>,
        }
        impl Runner for Router<'_> {
            fn run(&self, cmd: &str, args: &[&str], _: Instant) -> io::Result<String> {
                match cmd {
                    "ip" => Ok(self.route.into()),
                    "curl" => {
                        *self.curl.lock().unwrap() = args.iter().map(|s| s.to_string()).collect();
                        Ok("ok".into())
                    }
                    _ => Err(io::ErrorKind::Unsupported.into()),
                }
            }
        }
        for (input, addr) in [
            ("9080", "127.0.0.1:9080"),
            ("0.0.0.0:9080", "127.0.0.1:9080"),
            ("[::]:9080", "[::1]:9080"),
            ("127.0.0.2:9080", "127.0.0.2:9080"),
        ] {
            let run = Router {
                route: "",
                curl: Default::default(),
            };
            let endpoint: PanelEndpoint = input.parse().unwrap();
            endpoint.api(&run, "GET", "socks5").unwrap();
            assert_eq!(
                run.curl.lock().unwrap().last().unwrap(),
                &format!("http://{addr}/api/socks5")
            );
        }
        let ep: PanelEndpoint = "192.0.2.17:8090".parse().unwrap();
        for route in [
            "192.0.2.17 via 192.0.2.1 dev eth0",
            "local 192.0.2.10 dev lo",
            "local 192.0.2.17 dev eth0",
            "",
        ] {
            let run = Router {
                route,
                curl: Default::default(),
            };
            assert!(ep.api(&run, "GET", "awg2").is_err());
            assert!(run.curl.lock().unwrap().is_empty());
        }
        let run = Router {
            route: "local 192.0.2.17 dev lo src 192.0.2.17",
            curl: Default::default(),
        };
        ep.api(&run, "GET", "awg2").unwrap();
        assert!(run
            .curl
            .lock()
            .unwrap()
            .windows(2)
            .any(|w| w == ["--interface", "lo"]));
        for bad in [
            "example.org:443",
            "127.0.0.1:0",
            "[ff02::1]:443",
            "[fe80::1]:443",
            "255.255.255.255:443",
            "https://example.org",
        ] {
            assert!(bad.parse::<PanelEndpoint>().is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_socket_owner_and_start_time_select_a_unique_listener() {
        use std::net::TcpListener;
        let own = TcpListener::bind("127.0.0.2:0").unwrap();
        let addr = own.local_addr().unwrap();
        let pid = std::process::id();
        let stat = fs::read_to_string("/proc/self/stat").unwrap();
        let start = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        let token = format!("{pid}/{start}");
        let port = NonZeroU16::new(addr.port()).unwrap();
        assert_eq!(
            listen_address(Path::new("/proc"), &token, port).unwrap(),
            addr
        );
        assert!(listen_address(Path::new("/proc"), &format!("{pid}/1"), port).is_err());
        let other = TcpListener::bind((Ipv4Addr::LOCALHOST, addr.port())).unwrap();
        assert!(listen_address(Path::new("/proc"), &token, port).is_err());
        drop((other, own));
        assert!(listen_address(Path::new("/proc"), &token, port).is_err());
        let v6 = TcpListener::bind("[::1]:0").unwrap();
        let addr = v6.local_addr().unwrap();
        assert_eq!(
            listen_address(
                Path::new("/proc"),
                &token,
                NonZeroU16::new(addr.port()).unwrap()
            )
            .unwrap(),
            addr
        );
    }
}
