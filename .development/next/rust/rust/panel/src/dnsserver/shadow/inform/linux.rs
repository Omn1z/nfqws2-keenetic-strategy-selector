use super::{capture, elapsed, exchange, Ack, Identity, Socket, Target, Trace};
use std::{
    ffi::{CStr, CString},
    io,
    mem::{size_of, size_of_val},
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
};
use tokio::{
    io::{unix::AsyncFd, Interest},
    time::Instant,
};

pub(super) async fn probe(target: Target<'_>, deadline: Instant, trace: &Trace) -> io::Result<Ack> {
    let name = CString::new(target.device).map_err(|_| io::ErrorKind::InvalidInput)?;
    verify_link(&name, target)?;
    let [a, b] = nfqws2_dns::transaction_id()?.to_be_bytes();
    let [c, d] = nfqws2_dns::transaction_id()?.to_be_bytes();
    let identity = Identity {
        client: target.client,
        server: target.server,
        mac: target.mac,
        xid: [a, b, c, d],
    };
    if Instant::now() >= deadline {
        return Err(elapsed(None));
    }
    let socket = RawSocket::open(&name, target)?;
    verify_link(&name, target)?;
    let work = exchange(&socket, identity, deadline, trace);
    let scope = trace
        .wire_scope()
        .filter(|scope| scope.has_changed().is_ok() && Instant::now() < deadline);
    let ack = if let Some(scope) = scope {
        match capture::linux::Capture::open(&name, target, identity) {
            Ok(observer) => {
                trace.step("wire.start", &format!("Захват на {}: IPv4 UDP 67↔68, только текущий DHCPINFORM; без promiscuous mode", target.device));
                capture::during(work, observer, scope, |observer, scope| {
                    observer.finish(trace, scope)
                })
                .await
            }
            Err(_) => {
                trace.step(
                    "wire.error",
                    "Не удалось включить захват DHCP на текущем WAN",
                );
                work.await
            }
        }
    } else {
        work.await
    }?;
    verify_link(&name, target)?;
    if Instant::now() >= deadline {
        return Err(elapsed(None));
    }
    Ok(ack)
}

// Confirm that this name still denotes the same up Ethernet link, with the
// same scoped local address and six-byte MAC. The caller proves WAN role.
fn verify_link(name: &CStr, target: Target<'_>) -> io::Result<()> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // This pointer comes from successful getifaddrs and has one owner.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut first = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = Addresses(first);
    let mut next = addresses.0;
    let mut hardware = false;
    let mut address = false;
    // The list and per-family sockaddr pointers remain owned by Addresses.
    unsafe {
        while let Some(entry) = next.as_ref() {
            next = entry.ifa_next;
            if entry.ifa_name.is_null()
                || CStr::from_ptr(entry.ifa_name) != name
                || entry.ifa_flags & libc::IFF_UP as u32 == 0
                || entry.ifa_flags & libc::IFF_LOOPBACK as u32 != 0
            {
                continue;
            }
            let Some(sockaddr) = entry.ifa_addr.as_ref() else {
                continue;
            };
            match i32::from(sockaddr.sa_family) {
                libc::AF_PACKET => {
                    let link = &*entry.ifa_addr.cast::<libc::sockaddr_ll>();
                    hardware |= link.sll_ifindex as u32 == target.index
                        && link.sll_hatype == libc::ARPHRD_ETHER
                        && link.sll_halen == 6
                        && link.sll_addr[..6] == target.mac;
                }
                libc::AF_INET => {
                    let ip = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                    address |= ip.sin_addr.s_addr.to_ne_bytes() == target.client.octets();
                }
                _ => (),
            }
        }
        if hardware && address && libc::if_nametoindex(name.as_ptr()) == target.index {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "DHCPINFORM WAN no longer owns the expected link and address",
    ))
}

struct RawSocket {
    fd: AsyncFd<OwnedFd>,
    destination: libc::sockaddr_in,
}

fn ipv4(ip: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_port: 0,
        sin_zero: [0; 8],
    }
}

fn set_option<T: ?Sized>(fd: &impl AsRawFd, name: libc::c_int, value: &T) -> io::Result<()> {
    let status = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (value as *const T).cast(),
            size_of_val(value) as _,
        )
    };
    cvt(status as isize).map(|_| ())
}

fn cvt(result: isize) -> io::Result<usize> {
    usize::try_from(result).map_err(|_| io::Error::last_os_error())
}

impl RawSocket {
    fn open(name: &CStr, target: Target<'_>) -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::IPPROTO_UDP,
            )
        };
        cvt(raw as isize)?;
        // The new descriptor has a single owner, including on setup failure.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        attach_filter(&fd)?;
        set_option(&fd, libc::SO_RCVBUF, &(16 * 1024i32))?;
        set_option(&fd, libc::SO_BINDTODEVICE, name.to_bytes_with_nul())?;
        let source = ipv4(target.client);
        cvt(unsafe {
            libc::bind(
                raw,
                (&source as *const libc::sockaddr_in).cast(),
                size_of_val(&source) as _,
            ) as isize
        })?;
        if target.server.is_none() {
            set_option(&fd, libc::SO_BROADCAST, &1i32)?;
        }
        // The socket remains unconnected to admit a verified ACK whose UDP
        // source differs from the server identifier, as RFC 2131 permits.
        let destination = ipv4(target.server.unwrap_or(Ipv4Addr::BROADCAST));
        // The owned descriptor remains open and nonblocking until AsyncFd
        // deregisters it. No other code can change the descriptor or its mode.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(Self { fd, destination })
    }
}

impl Socket for RawSocket {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        let written = self
            .fd
            .async_io(Interest::WRITABLE, |fd| {
                cvt(unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&self.destination as *const libc::sockaddr_in).cast(),
                        size_of::<libc::sockaddr_in>() as _,
                    )
                })
            })
            .await?;
        if written != packet.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }

    async fn receive(&self, packet: &mut [u8]) -> io::Result<usize> {
        self.fd
            .async_io(Interest::READABLE, |fd| {
                cvt(unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        packet.as_mut_ptr().cast(),
                        packet.len(),
                        libc::MSG_TRUNC,
                    )
                })
            })
            .await
    }
}

pub(super) fn attach_filter(fd: &impl AsRawFd) -> io::Result<()> {
    use libc::{
        BPF_ABS, BPF_ALU, BPF_AND, BPF_B, BPF_H, BPF_IND, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_JSET,
        BPF_K, BPF_LD, BPF_LDX, BPF_MSH, BPF_RET,
    };
    let ins = |code, k, jt, jf| libc::sock_filter {
        code: code as u16,
        k,
        jt,
        jf,
    };
    let mut filter = [
        // IPv4 with at least 20 byte header, UDP, no fragments.
        ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
        ins(BPF_ALU | BPF_AND | BPF_K, 0xf0, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 0, 13),
        ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
        ins(BPF_ALU | BPF_AND | BPF_K, 0x0f, 0, 0),
        ins(BPF_JMP | BPF_JGE | BPF_K, 5, 0, 10),
        ins(BPF_LD | BPF_B | BPF_ABS, 9, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 8),
        ins(BPF_LD | BPF_H | BPF_ABS, 6, 0, 0),
        ins(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 6, 0),
        // X is IP header length including options. Admit only 67 to 68.
        ins(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0),
        ins(BPF_LD | BPF_H | BPF_IND, 0, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 67, 0, 3),
        ins(BPF_LD | BPF_H | BPF_IND, 2, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 68, 0, 1),
        ins(BPF_RET | BPF_K, u32::MAX, 0, 0),
        ins(BPF_RET | BPF_K, 0, 0, 0),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    set_option(fd, libc::SO_ATTACH_FILTER, &program)
}
