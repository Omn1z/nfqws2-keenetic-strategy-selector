//! Read-only notifications for OpenWrt. A firewall event can only request a
//! fresh check of the journal; it never supplies a rule body or handle.
#[cfg(any(target_os = "linux", test))]
fn affected(mut bytes: &[u8], forward_chain: &str) -> Option<bool> {
    fn aligned(n: usize) -> Option<usize> {
        n.checked_add(3).map(|v| v & !3)
    }
    fn attrs(mut data: &[u8], chain_attr: Option<u16>, forward: &[u8]) -> Option<bool> {
        let mut fw4 = false;
        let mut owned_chain = chain_attr.is_none();
        while !data.is_empty() {
            let header = data.get(..4)?;
            let size = usize::from(u16::from_ne_bytes(header[..2].try_into().ok()?));
            let kind = u16::from_ne_bytes(header[2..4].try_into().ok()?) & 0x3fff;
            let value = data.get(4..size)?;
            if kind == 1 {
                fw4 = value == b"fw4\0";
            } else if Some(kind) == chain_attr {
                owned_chain = matches!(value, b"srcnat\0" | b"mangle_forward\0")
                    || value.strip_suffix(&[0]) == Some(forward);
            }
            data = data.get(aligned(size)?..)?;
        }
        Some(fw4 && owned_chain)
    }
    let mut result = false;
    while !bytes.is_empty() {
        let header = bytes.get(..16)?;
        let size = usize::try_from(u32::from_ne_bytes(header[..4].try_into().ok()?)).ok()?;
        let kind = u16::from_ne_bytes(header[4..6].try_into().ok()?);
        let body = bytes.get(16..size)?;
        if kind == 4 {
            // NLMSG_OVERRUN: a notification may have been lost.
            result = true;
        } else if kind >> 8 == 10 && body.first() == Some(&1) {
            // NFNL_SUBSYS_NFTABLES, NFPROTO_INET
            let selector = match kind & 0xff {
                0 | 2 | 26 => Some(None),    // NEW/DEL/DESTROYTABLE
                3 | 5 | 27 => Some(Some(3)), // CHAIN_NAME
                8 | 28 => Some(Some(2)),     // DEL/DESTROYRULE: RULE_CHAIN
                _ => None,
            };
            if let Some(chain) = selector {
                result |= attrs(body.get(4..)?, chain, forward_chain.as_bytes())?;
            }
        }
        bytes = bytes.get(aligned(size)?..)?;
    }
    Some(result)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::affected;
    use std::io;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};
    use tokio::io::unix::AsyncFd;

    struct Socket {
        fd: AsyncFd<OwnedFd>,
        buffer: Box<[u8]>,
        dirty: bool,
    }
    impl Socket {
        fn subscribe() -> io::Result<Self> {
            // Fresh descriptor, initialized sockaddr_nl; no requests are sent.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    libc::NETLINK_NETFILTER,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as _;
            addr.nl_groups = 1 << (7 - 1); // NFNLGRP_NFTABLES, not packet tracing.
            if unsafe {
                libc::bind(
                    raw,
                    (&addr as *const libc::sockaddr_nl).cast(),
                    mem::size_of_val(&addr) as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                // OwnedFd holds the same open file description until AsyncFd
                // unregisters it. Nothing else closes or replaces the fd.
                fd: unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE) }?,
                buffer: vec![0u8; 16 * 1024].into_boxed_slice(),
                dirty: true,
            })
        }
        fn receive(fd: &OwnedFd, bytes: &mut [u8], chain: &str) -> io::Result<bool> {
            let mut from: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut addr_len = mem::size_of_val(&from) as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_TRUNC,
                    (&mut from as *mut libc::sockaddr_nl).cast(),
                    &mut addr_len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(libc::ENOBUFS) {
                    Ok(true)
                } else {
                    Err(e)
                };
            }
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if addr_len as usize != mem::size_of_val(&from)
                || from.nl_family as i32 != libc::AF_NETLINK
                || from.nl_pid != 0
            {
                return Ok(false);
            }
            // Truncation, malformed input or packet loss only trigger a
            // read-back of the current kernel state, never a blind mutation.
            Ok(bytes.get(..n as usize).and_then(|s| affected(s, chain)).unwrap_or(true))
        }
        async fn changed(&mut self, chain: &str) -> io::Result<()> {
            while !self.dirty {
                let mut ready = self.fd.readable().await?;
                if let Ok(event) = ready.try_io(|fd| Self::receive(fd.get_ref(), &mut self.buffer, chain))
                {
                    self.dirty = event?;
                }
            }
            // Changes from one committed nft transaction can span datagrams.
            // Bound work and keep the ordinary audit/expiry timer independent.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let started = Instant::now();
            'drain: loop {
                for _ in 0..32 {
                    match Self::receive(self.fd.get_ref(), &mut self.buffer, chain) {
                        Ok(_) => (),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break 'drain,
                        Err(e) => return Err(e),
                    }
                }
                if started.elapsed() >= Duration::from_millis(100) { break; }
                tokio::task::yield_now().await;
            }
            self.dirty = false;
            Ok(())
        }
    }
    #[derive(Default)]
    pub(crate) struct Watch {
        socket: Option<Socket>,
        retry: Option<Instant>,
        chain: String,
    }
    impl Watch {
        pub(crate) fn enable(&mut self, chain: Option<&str>) {
            let Some(chain) = chain else {
                *self = Self::default();
                return;
            };
            if chain != self.chain {
                chain.clone_into(&mut self.chain);
            }
            if self.socket.is_none() && self.retry.is_none_or(|t| t <= Instant::now()) {
                self.socket = Socket::subscribe().ok();
                self.retry = Some(Instant::now() + Duration::from_secs(30));
            }
        }
        pub(crate) async fn changed(&mut self) {
            if let Some(socket) = &mut self.socket {
                if socket.changed(&self.chain).await.is_err() {
                    self.socket = None;
                    self.retry = Some(Instant::now() + Duration::from_secs(30));
                }
            } else {
                std::future::pending::<()>().await;
            }
        }
    }
}
#[cfg(target_os = "linux")]
pub(super) use linux::Watch;
#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub(super) struct Watch {
    _private: (),
}
#[cfg(not(target_os = "linux"))]
impl Watch {
    pub(super) fn enable(&mut self, _: Option<&str>) {}
    pub(super) async fn changed(&mut self) {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(kind: u16, family: u8, table: &str, chain: &str) -> Vec<u8> {
        let mut data = vec![0u8; 20];
        data[4..6].copy_from_slice(&(0xa00 | kind).to_ne_bytes());
        data[16] = family;
        let attr = if matches!(kind, 3 | 5 | 27) { 3 } else { 2 };
        for (id, name) in [(1u16, table), (attr, chain)] {
            if name.is_empty() {
                continue;
            }
            data.extend_from_slice(&((name.len() + 5) as u16).to_ne_bytes());
            data.extend_from_slice(&id.to_ne_bytes());
            data.extend_from_slice(name.as_bytes());
            data.push(0);
            data.resize(data.len().next_multiple_of(4), 0);
        }
        let len = data.len() as u32;
        data[..4].copy_from_slice(&len.to_ne_bytes());
        data
    }
    #[test]
    fn netfilter_notifications_scope_families_tables_chains_and_ignore_own_additions() {
        let ignored = notice(8, 1, "admin", "forward_lan");
        for record in [
            &ignored,
            &notice(8, 2, "fw4", "forward_lan"),
            &notice(6, 1, "fw4", "srcnat"),
            &notice(8, 1, "fw4", "input"),
        ] {
            assert_eq!(affected(record, "forward_lan"), Some(false));
        }
        for record in [
            notice(0, 1, "fw4", ""),
            notice(3, 1, "fw4", "srcnat"),
            notice(8, 1, "fw4", "forward_lan"),
            notice(28, 1, "fw4", "mangle_forward"),
        ] {
            assert_eq!(
                affected(&[ignored.clone(), record.clone()].concat(), "forward_lan"),
                Some(true)
            );
            assert_eq!(affected(&record[..record.len() - 1], "forward_lan"), None);
        }
        let renamed = notice(8, 1, "fw4", "forward_home");
        assert_eq!(affected(&renamed, "forward_lan"), Some(false));
        assert_eq!(affected(&renamed, "forward_home"), Some(true));
    }

    // A separate network/mount namespace and test-only rootfs are prepared by
    // the launcher. Run actual fw4, nft, kernel RPDB and the normal Rust
    // installation/reassertion entry points with a synthetic verified peer.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires an isolated OpenWrt rootfs, nftables, ip-full and CAP_NET_ADMIN"]
    async fn fw4_reload_signal_repairs_only_owned_rules_in_isolated_netns() {
        use nfqws2_awg_rules::kernel::{self, LivePeer, Operation};
        use nfqws2_router_command::System;
        use serde_json::json;
        use std::{fs, process::Command, time::Duration};
        assert_eq!(
            fs::read_to_string("/synthetic-guest").unwrap().trim(),
            "ea1-qemu-airgap"
        );
        for (kind, var) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
            let parent = std::env::var(var).unwrap();
            assert!(parent.starts_with(&format!("{kind}:[")));
            let current = fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
            assert_ne!(current.to_str().unwrap(), parent);
        }
        let run = |prog: &str, args: &[&str]| {
            let out = Command::new(prog).args(args).output().unwrap();
            assert!(
                out.status.success(),
                "{prog} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(run("fw4", &["-q", "network", "lan"]).trim(), "lan");
        for (dev, addr) in [("awg57", "192.0.2.57/32"), ("n2s_wan57", "192.0.2.157/32")] {
            run("ip", &["link", "add", dev, "type", "dummy"]);
            run("ip", &["link", "set", dev, "up"]);
            run("ip", &["addr", "add", addr, "dev", dev]);
        }
        run(
            "ip",
            &["route", "add", "198.51.100.231/32", "dev", "n2s_wan57"],
        );
        let dir = tempfile::tempdir().unwrap();
        let db = nfqws2_store::Store::open(dir.path()).unwrap();
        nfqws2_awg_profile::edit_document(&db,|doc|{
            doc["routing_revision"]=json!(1);
            doc["routing"]=json!({"mode":"zones"});
            let c=&mut doc["servers"][0]["config"];
            c["enabled"]=json!(true);c["client"]["enabled"]=json!(true);
            c["public_key"]=json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=");
            c["client_iface"]=json!("awg57");
            c["endpoint"]=json!("198.51.100.231:51820");
            c["routing"]=json!({"mode":"zones","zones":[{"name":"demo","enabled":true,"ips":["203.0.113.173"]}]});
            Ok(())
        }).unwrap();
        let op = |op| {
            kernel::operate(&db, &System, op, |_, ifname| {
                assert_eq!(ifname, "awg57");
                LivePeer::from_uapi(
                    std::path::Path::new("/"),
                    ifname,
                    "198.51.100.231:51820".parse().unwrap(),
                    vec!["0.0.0.0/0".into()],
                    0,
                    false,
                )
            })
            .unwrap()
        };
        let own = || {
            run("nft", &["list", "table", "inet", "fw4"])
                .lines()
                .filter(|l| l.contains("n2s-awg-cidr"))
                .count()
        };
        let mut watch = Watch::default();
        op(Operation::Apply);
        op(Operation::Commit);
        assert!(kernel::scheduled_with_fw4(&db).unwrap().1);
        watch.enable(Some("forward_lan"));
        tokio::time::timeout(Duration::from_secs(3), watch.changed())
            .await
            .unwrap();
        assert_eq!(own(), 3);
        run("fw4", &["reload"]);
        assert_eq!(own(), 0);
        tokio::time::timeout(Duration::from_secs(3), watch.changed())
            .await
            .expect("no fw4 event");
        run("nft",&["add rule inet fw4 forward_lan oifname \"n2s_wan57\" counter drop comment \"qa-foreign\""]);
        let foreign = || {
            run(
                "nft",
                &["-a", "list", "chain", "inet", "fw4", "forward_lan"],
            )
            .lines()
            .find(|l| l.contains("qa-foreign"))
            .unwrap()
            .trim()
            .to_owned()
        };
        let before = foreign();
        op(Operation::FirewallReload);
        assert_eq!(own(), 3);
        assert_eq!(foreign(), before);
        assert!(kernel::inspect(&db, &System).unwrap().ready);
        assert!(
            tokio::time::timeout(Duration::from_millis(350), watch.changed())
                .await
                .is_err(),
            "own add triggered another repair"
        );
        drop(watch);
        // Repeat through the running panel worker. The synthetic UAPI socket
        // supplies a known key/handshake; the actual subscriber, RPDB, fw4
        // and application scheduling are left in place.
        let root = dir.path().join("router");
        let sys = root.join("sys/class/net/awg57");
        let sockets = root.join("var/run/amneziawg");
        fs::create_dir_all(&sys).unwrap();
        fs::create_dir_all(&sockets).unwrap();
        fs::write(sys.join("tun_flags"),"0x0001\n").unwrap();
        let socket=tokio::net::UnixListener::bind(sockets.join("awg57.sock")).unwrap();
        let checked=std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let seen=checked.clone();
        let engine=tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut stream,_)=socket.accept().await.unwrap();
                let mut request=[0u8;7];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request,b"get=1\n\n");
                let reply=format!("public_key={}\nendpoint=198.51.100.231:51820\nallowed_ip=0.0.0.0/0\nlast_handshake_time_sec={}\nerrno=0\n\n",
                    "01".repeat(32),nfqws2_awg_profile::now());
                stream.write_all(reply.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                seen.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
            }
        });
        let state=crate::http::AppState::open(
            nfqws2_config::Config{data_dir:dir.path().display().to_string(),..Default::default()},
            &root,true).unwrap();
        drop(super::super::worker(&state).await);
        for _ in 0..2 {
            let count = checked.load(std::sync::atomic::Ordering::Relaxed);
            run("fw4",&["reload"]);
            assert_eq!(own(),0);
            run("nft",&["add rule inet fw4 forward_lan oifname \"n2s_wan57\" counter drop comment \"qa-foreign\""]);
            let keep=foreign();
            tokio::time::timeout(Duration::from_secs(8),async {
                while own()!=3 { tokio::time::sleep(Duration::from_millis(30)).await; }
            }).await.expect("running panel did not restore fw4 on notification");
            assert!(checked.load(std::sync::atomic::Ordering::Relaxed)>count);
            assert_eq!(foreign(),keep);
        }
        let keep=foreign();
        super::super::shutdown(&state).await;
        engine.abort();
        assert_eq!(own(), 0);
        assert_eq!(foreign(), keep);
    }
}
