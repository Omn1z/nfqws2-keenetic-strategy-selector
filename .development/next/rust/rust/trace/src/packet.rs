use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub fn open(index: i32, socket_type: i32, filter: &mut [libc::sock_filter]) -> io::Result<OwnedFd> {
    // A protocol of zero receives no traffic before the filter and bind.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            socket_type | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let prog = libc::sock_fprog {
        len: filter.len().try_into().map_err(io::Error::other)?,
        filter: filter.as_mut_ptr(),
    };
    let buffer: libc::c_int = 32 * 1024;
    let set = |name, ptr, len| {
        if unsafe { libc::setsockopt(raw, libc::SOL_SOCKET, name, ptr, len) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    set(
        libc::SO_ATTACH_FILTER,
        (&prog as *const libc::sock_fprog).cast(),
        size_of_val(&prog) as _,
    )?;
    set(
        libc::SO_RCVBUF,
        (&buffer as *const libc::c_int).cast(),
        size_of_val(&buffer) as _,
    )?;
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as _;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = index;
    let result = unsafe {
        libc::bind(
            raw,
            (&addr as *const libc::sockaddr_ll).cast(),
            size_of_val(&addr) as _,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn dropped(fd: &OwnedFd) -> io::Result<bool> {
    let mut stats = [0u32; 2];
    let mut len = size_of_val(&stats) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            stats.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stats[1] != 0)
}

pub fn disappeared(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENETDOWN))
}
