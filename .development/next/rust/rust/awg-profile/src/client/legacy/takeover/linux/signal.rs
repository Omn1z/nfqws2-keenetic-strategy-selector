use std::{
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(in crate::client) enum Target {
    Pid(OwnedFd),
    Notification { _read: OwnedFd, write: File },
}

impl Target {
    pub(in crate::client) fn open(pid: i32) -> io::Result<Self> {
        if pid <= 1 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd >= 0 {
            return Ok(Self::Pid(unsafe { OwnedFd::from_raw_fd(fd as i32) }));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOSYS) {
            return Err(err);
        }
        Self::notification(pid)
    }

    // Keenetic 4.9 predates pidfd. F_SETOWN pins a kernel struct pid, so
    // asynchronous pipe notification also cannot signal a reused PID. No
    // data or events are sent until the caller rechecks the pinned owner.
    fn notification(pid: i32) -> io::Result<Self> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { File::from_raw_fd(fds[1]) };
        // Linux UAPI F_SETSIG, shared by all of the supported router ABIs.
        const F_SETSIG: libc::c_int = 10;
        for (cmd, arg) in [
            (libc::F_SETOWN, pid),
            (F_SETSIG, libc::SIGTERM),
            (libc::F_SETFL, libc::O_NONBLOCK | libc::O_ASYNC),
        ] {
            if unsafe { libc::fcntl(read.as_raw_fd(), cmd, arg) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self::Notification { _read: read, write })
    }

    pub(in crate::client) fn terminate(self) -> io::Result<()> {
        match self {
            Self::Pid(fd) => {
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGTERM,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
            Self::Notification { _read, mut write } => write.write_all(&[1]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::{
        process::Command,
        time::{Duration, Instant},
    };
    #[test]
    fn legacy_kernel_notification_terminates_only_after_revalidation() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let discarded = Target::notification(child.id() as i32).unwrap();
        drop(discarded);
        std::thread::sleep(Duration::from_millis(20));
        assert!(child.try_wait().unwrap().is_none());
        Target::notification(child.id() as i32)
            .unwrap()
            .terminate()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.signal(), Some(libc::SIGTERM));
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("no SIGTERM received");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
