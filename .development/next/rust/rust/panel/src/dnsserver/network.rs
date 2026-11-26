use std::io;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};
#[cfg(target_os = "linux")]
pub(super) fn bind_device(
    socket: &impl std::os::fd::AsRawFd,
    binding: (&str, u32),
) -> io::Result<()> {
    #[cfg(test)]
    if binding.0.is_empty() && binding.1 == 0 {
        return Ok(());
    }
    let dev = std::ffi::CString::new(binding.0)?;
    // Apply the WAN constraint to this socket before it emits any datagram or SYN.
    let res = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            dev.as_ptr().cast(),
            dev.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if res == 0 && binding.1 != 0 && unsafe { libc::if_nametoindex(dev.as_ptr()) } != binding.1 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "выбранный VPN-интерфейс изменился",
        ));
    }
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(not(target_os = "linux"))]
pub(super) fn bind_device<T>(_: &T, _binding: (&str, u32)) -> io::Result<()> {
    #[cfg(test)]
    if _binding.0.is_empty() && _binding.1 == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "привязка DNS к сетевому интерфейсу доступна только на Linux",
    ))
}
pub async fn tcp(
    addr: SocketAddr,
    device: Option<(&str, u32)>,
) -> io::Result<tokio::net::TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(dev) = device {
        bind_device(&socket, dev)?;
    }
    socket.connect(addr).await
}
const UDP_CAPACITY: usize = 4097;

async fn udp_exchange(
    addr: SocketAddr,
    device: Option<(&str, u32)>,
    original: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    if !(12..=65535).contains(&original.len()) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut q = original.to_owned();
    q[..2].copy_from_slice(&nfqws2_dns::transaction_id()?.to_be_bytes());
    let udp = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    if let Some(dev) = device {
        bind_device(&udp, dev)?;
    }
    udp.connect(addr).await?;
    udp.send(&q).await?;
    let mut reply = vec![0u8; UDP_CAPACITY];
    loop {
        let n = udp.recv(&mut reply).await?;
        if n < 12 || reply[..2] != q[..2] {
            continue;
        }
        reply.truncate(n);
        return Ok((q, reply));
    }
}

pub async fn exchange(
    addr: SocketAddr,
    device: Option<(&str, u32)>,
    original: &[u8],
) -> io::Result<Vec<u8>> {
    let (q, mut reply) = udp_exchange(addr, device, original).await?;
    if reply[2] & 2 == 0 && reply.len() < UDP_CAPACITY {
        nfqws2_dns::validate_answer(&q, &reply)?;
        reply[..2].copy_from_slice(&original[..2]);
        return Ok(reply);
    }
    let mut tcp = tcp(addr, device).await?;
    tcp.write_u16(q.len() as u16).await?;
    tcp.write_all(&q).await?;
    let size = tcp.read_u16().await? as usize;
    reply.resize(size, 0);
    tcp.read_exact(&mut reply).await?;
    nfqws2_dns::validate_answer(&q, &reply)?;
    reply[..2].copy_from_slice(&original[..2]);
    Ok(reply)
}

pub(super) async fn exchange_redirected(addr: SocketAddr, original: &[u8]) -> io::Result<Vec<u8>> {
    let (q, mut reply) = udp_exchange(addr, None, original).await?;
    // The firmware's local resolver may listen on UDP only. Even when the
    // client uses TCP, the proxy must return its valid TC response as DNS.
    if reply.len() == UDP_CAPACITY {
        return Err(io::Error::other("слишком большой UDP-ответ DNS роутера"));
    }
    nfqws2_dns::validate_forwarded_response(&q, &reply)?;
    if reply[2] & 2 != 0 && reply[6..12] != [0; 6] {
        // An incomplete RRset cannot authorize an address. Give the client
        // a question-only TC response so no partial answer can be used.
        let mut truncated = nfqws2_dns::response_error(original, reply[3] & 15);
        truncated[2..4].copy_from_slice(&reply[2..4]);
        return Ok(truncated);
    }
    reply[..2].copy_from_slice(&original[..2]);
    Ok(reply)
}
