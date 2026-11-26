use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::net::{TcpListener, TcpSocket};

fn listen(socket: TcpSocket, address: SocketAddr) -> io::Result<TcpListener> {
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, WSAGetLastError, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        };
        let enabled = 1i32;
        // A dual-stack wildcard must fail when an IPv4-only socket owns the port.
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const enabled).cast(),
                std::mem::size_of_val(&enabled) as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    socket.bind(address)?;
    #[cfg(target_os = "linux")]
    let backlog = std::fs::read_to_string("/proc/sys/net/core/somaxconn")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .map_or(128, |n| n.min(i32::MAX as u32));
    #[cfg(not(target_os = "linux"))]
    let backlog = 128;
    socket.listen(backlog)
}

/// Go's TCP :port accepts both families on a dual-stack kernel and works on
/// IPv4-only firmware. An occupied port remains a bind failure.
pub fn bind_wildcard(port: u16) -> io::Result<TcpListener> {
    bind_available(port, TcpSocket::new_v6())
}

fn bind_available(port: u16, v6: io::Result<TcpSocket>) -> io::Result<TcpListener> {
    let dual = v6.and_then(|socket| {
        socket2::SockRef::from(&socket).set_only_v6(false)?;
        Ok(socket)
    });
    if let Ok(socket) = dual {
        match listen(socket, (Ipv6Addr::UNSPECIFIED, port).into()) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) => {}
            result => return result,
        }
    }
    listen(TcpSocket::new_v4()?, (Ipv4Addr::UNSPECIFIED, port).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn ipv4_and_available_ipv6_localhost_share_the_same_service_port() {
        let socket = bind_wildcard(0).unwrap();
        let address = socket.local_addr().unwrap();
        assert!(address.ip().is_unspecified());
        let port = address.port();
        let (v4, accepted) = tokio::join!(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
            socket.accept()
        );
        assert!(v4.is_ok() && accepted.is_ok());
        if address.is_ipv6() {
            let (v6, accepted) = tokio::join!(
                TcpStream::connect((Ipv6Addr::LOCALHOST, port)),
                socket.accept()
            );
            assert!(v6.is_ok() && accepted.is_ok());
        }
        assert!(bind_wildcard(port).is_err());
        let only_v4 = bind_available(0, Err(io::ErrorKind::Unsupported.into())).unwrap();
        let address = only_v4.local_addr().unwrap();
        assert!(address.is_ipv4() && address.ip().is_unspecified());
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, address.port()))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn ipv4_listener_blocks_a_dual_stack_wildcard() {
        let existing = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = existing.local_addr().unwrap().port();
        assert!(bind_wildcard(port).is_err());
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());
    }
}
