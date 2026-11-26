use super::{parse::Tracker, Receipt};
use std::{
    ffi::{CStr, CString},
    io,
    mem::{offset_of, size_of_val},
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use time::OffsetDateTime;
use tokio::{
    io::{unix::AsyncFd, Interest},
    time::Instant,
};

pub(crate) struct Capture {
    fd: AsyncFd<OwnedFd>,
    index: i32,
    tracker: Tracker,
}

impl Capture {
    pub(crate) fn open(
        device: &str,
        ifindex: u32,
        client: Ipv4Addr,
        mac: [u8; 6],
    ) -> io::Result<Self> {
        let tracker = Tracker::new(client, mac)?;
        let index = i32::try_from(ifindex).map_err(|_| io::ErrorKind::InvalidInput)?;
        let name = CString::new(device).map_err(|_| io::ErrorKind::InvalidInput)?;
        let fd = open_packet_receiver(&name, ifindex, mac, None)?;
        // AsyncFd owns the open description through deregistration.
        let fd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }?;
        Ok(Self { fd, index, tracker })
    }

    pub(in crate::dnsserver::shadow) async fn next(
        &mut self,
        mut progress: impl FnMut(u64),
    ) -> io::Result<Receipt> {
        let mut bytes = [0; super::parse::BUFFER];
        loop {
            for _ in 0..32 {
                let mut ready = self.fd.readable().await?;
                let received =
                    ready.try_io(|sock| read_packet(sock.get_ref(), self.index, &mut bytes));
                match received {
                    Ok(Ok(Some((len, outgoing)))) => {
                        let requests = self.tracker.requests;
                        let observation =
                            self.tracker.packet(&bytes[..len], outgoing, Instant::now());
                        if self.tracker.requests != requests {
                            progress(self.tracker.requests);
                        }
                        if let Some(observation) = observation {
                            return Ok(Receipt {
                                observation,
                                observed_at: OffsetDateTime::now_utc(),
                            });
                        }
                    }
                    Ok(Err(error)) if error.kind() != io::ErrorKind::Interrupted => {
                        return Err(error)
                    }
                    _ => (),
                }
            }
            // A stream of irrelevant frames cannot starve a firmware command
            // or cancellation running on the same executor thread.
            tokio::task::yield_now().await;
        }
    }
}

pub(in crate::dnsserver::shadow) fn open_packet_receiver(
    name: &CStr,
    ifindex: u32,
    mac: [u8; 6],
    xid: Option<[u8; 4]>,
) -> io::Result<OwnedFd> {
    let index = i32::try_from(ifindex).map_err(|_| io::ErrorKind::InvalidInput)?;
    if index == 0 || name.to_bytes().is_empty() || name.to_bytes().len() >= libc::IFNAMSIZ {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    check_index(name, ifindex)?;
    // Protocol zero prevents traffic reaching the socket before both the
    // DHCP filter and the interface binding are installed.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // This new descriptor has no other owner, including on setup error.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    socket_option(&fd, libc::SO_RCVBUF, &(16 * 1024i32))?;
    attach_filter(&fd, mac, xid)?;

    let mut link: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    link.sll_family = libc::AF_PACKET as _;
    link.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    link.sll_ifindex = index;
    if unsafe {
        libc::bind(
            raw,
            (&link as *const libc::sockaddr_ll).cast(),
            size_of_val(&link) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    check_index(name, ifindex)?;
    Ok(fd)
}

fn check_index(name: &CStr, index: u32) -> io::Result<()> {
    // The library reads a NUL-terminated string only for this call.
    let live = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if live != index {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DHCP capture interface changed",
        ));
    }
    Ok(())
}

pub(in crate::dnsserver::shadow) fn read_packet(
    fd: &OwnedFd,
    index: i32,
    bytes: &mut [u8],
) -> io::Result<Option<(usize, bool)>> {
    let mut peer: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    let mut peer_len = size_of_val(&peer) as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            (&mut peer as *mut libc::sockaddr_ll).cast(),
            &mut peer_len,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize > bytes.len()
        || peer_len as usize <= offset_of!(libc::sockaddr_ll, sll_pkttype)
        || peer.sll_family as i32 != libc::AF_PACKET
        || peer.sll_ifindex != index
    {
        return Ok(None);
    }
    let outgoing = match peer.sll_pkttype {
        libc::PACKET_OUTGOING => true,
        libc::PACKET_HOST | libc::PACKET_BROADCAST => false,
        _ => return Ok(None),
    };
    Ok(Some((n as usize, outgoing)))
}

fn socket_option<T>(fd: &impl AsRawFd, name: i32, value: &T) -> io::Result<()> {
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (value as *const T).cast(),
            size_of_val(value) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn attach_filter(fd: &impl AsRawFd, mac: [u8; 6], xid: Option<[u8; 4]>) -> io::Result<()> {
    use libc::{
        BPF_ABS, BPF_ALU, BPF_AND, BPF_B, BPF_H, BPF_IND, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JMP,
        BPF_JSET, BPF_K, BPF_LD, BPF_LDX, BPF_MSH, BPF_RET, BPF_W,
    };
    let ins = |code, k, jt, jf| libc::sock_filter {
        code: code as u16,
        k,
        jt,
        jf,
    };
    let mut filter = vec![
        // IPv4, IHL >= 20, UDP, no reserved or fragmentation bits.
        ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
        ins(BPF_ALU | BPF_AND | BPF_K, 0xf0, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 0, 17),
        ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
        ins(BPF_ALU | BPF_AND | BPF_K, 0x0f, 0, 0),
        ins(BPF_JMP | BPF_JGE | BPF_K, 5, 0, 14),
        ins(BPF_LD | BPF_B | BPF_ABS, 9, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 12),
        ins(BPF_LD | BPF_H | BPF_ABS, 6, 0, 0),
        ins(BPF_JMP | BPF_JSET | BPF_K, 0xbfff, 10, 0),
        // X holds IHL. Accept only the two DHCP port directions.
        ins(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0),
        ins(BPF_LD | BPF_H | BPF_IND, 0, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 67, 1, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 68, 3, 6),
        ins(BPF_LD | BPF_H | BPF_IND, 2, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 68, 3, 4),
        ins(BPF_RET | BPF_K, 0, 0, 0),
        ins(BPF_LD | BPF_H | BPF_IND, 2, 0, 0),
        ins(BPF_JMP | BPF_JEQ | BPF_K, 67, 0, 1),
        ins(BPF_JMP | BPF_JA, 1, 0, 0),
        ins(BPF_RET | BPF_K, 0, 0, 0),
        // BOOTP chaddr begins after 8 UDP and 28 BOOTP bytes.
        ins(BPF_LD | BPF_W | BPF_IND, 36, 0, 0),
        ins(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]),
            0,
            3,
        ),
        ins(BPF_LD | BPF_H | BPF_IND, 40, 0, 0),
        ins(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::from(u16::from_be_bytes([mac[4], mac[5]])),
            0,
            1,
        ),
        ins(BPF_RET | BPF_K, super::parse::BUFFER as u32, 0, 0),
        ins(BPF_RET | BPF_K, 0, 0, 0),
    ];
    if let Some(xid) = xid {
        // Keep the common reject branch at index 26. The original accept
        // instruction jumps past it into the exact DHCP transaction check.
        filter[25] = ins(BPF_JMP | BPF_JA, 1, 0, 0);
        filter.extend([
            ins(BPF_LD | BPF_W | BPF_IND, 12, 0, 0),
            ins(BPF_JMP | BPF_JEQ | BPF_K, u32::from_be_bytes(xid), 0, 1),
            ins(BPF_RET | BPF_K, super::parse::BUFFER as u32, 0, 0),
            ins(BPF_RET | BPF_K, 0, 0, 0),
        ]);
    }
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    socket_option(fd, libc::SO_ATTACH_FILTER, &program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_filter_keeps_only_dhcp_ports_and_known_client_mac_on_unix_pair() {
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let fixture = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let filter = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let mac = [2, 1, 2, 3, 4, 5];
        attach_filter(&filter, mac, None).unwrap();
        let mut frame = [0u8; 80];
        frame[0] = 0x46;
        frame[9] = 17;
        frame[24..28].copy_from_slice(&[0, 68, 0, 67]);
        frame[60..66].copy_from_slice(&mac);
        let transfer = |data: &[u8], accepted| {
            let mut received = [0; 80];
            assert_eq!(
                unsafe { libc::write(fixture.as_raw_fd(), data.as_ptr().cast(), data.len()) },
                data.len() as isize
            );
            let n = unsafe {
                libc::read(
                    filter.as_raw_fd(),
                    received.as_mut_ptr().cast(),
                    received.len(),
                )
            };
            if accepted {
                assert_eq!(n as usize, data.len());
                assert_eq!(received.as_slice(), data);
            } else {
                assert_eq!(n, -1);
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
            }
        };
        transfer(&frame, true);
        frame[24..28].copy_from_slice(&[0, 67, 0, 68]);
        transfer(&frame, true);
        for (offset, value) in [(0, 0x65), (6, 0x20), (9, 6), (27, 53), (60, 6), (65, 9)] {
            let mut rejected = frame;
            rejected[offset] = value;
            transfer(&rejected, false);
        }
        transfer(&frame[..64], false);
    }

    #[test]
    fn shadow_wire_kernel_filter_restricts_this_xid_and_mac_in_both_directions() {
        use std::os::unix::net::UnixDatagram;

        let (fixture, filter) = UnixDatagram::pair().unwrap();
        filter.set_nonblocking(true).unwrap();
        let mac = [2, 1, 2, 3, 4, 5];
        let xid = [9, 8, 7, 6];
        attach_filter(&filter, mac, Some(xid)).unwrap();
        let mut frame = [0; 80];
        frame[0] = 0x46;
        frame[9] = 17;
        frame[36..40].copy_from_slice(&xid);
        frame[60..66].copy_from_slice(&mac);
        let mut received = [0; 80];
        for ports in [[0, 68, 0, 67], [0, 67, 0, 68]] {
            frame[24..28].copy_from_slice(&ports);
            for offset in [36, 39, 60, 65] {
                let mut unrelated = frame;
                unrelated[offset] ^= 1;
                fixture.send(&unrelated).unwrap();
                assert_eq!(
                    filter.recv(&mut received).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
            fixture.send(&frame).unwrap();
            assert_eq!(filter.recv(&mut received).unwrap(), frame.len());
            assert_eq!(received, frame);
        }
    }
}
