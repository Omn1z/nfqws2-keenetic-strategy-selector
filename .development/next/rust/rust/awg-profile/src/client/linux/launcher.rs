//! Transfer a configured foreground AWG engine to init once its owner receipt
//! is durable. Until then the private control socket ties it to the panel.
use super::{invalid, soft_limit, terminate};
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

const START: &[u8; 4] = b"AWG1";
const COMMIT: u8 = 1;

pub(super) struct Launch {
    helper: Child,
    channel: UnixStream,
    pid: u32,
}

impl Launch {
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn running(&mut self) -> io::Result<bool> {
        self.helper.try_wait().map(|exit| exit.is_none())
    }

    pub(super) fn commit(mut self) -> io::Result<()> {
        self.channel.write_all(&[COMMIT])?;
        if self.helper.wait()?.success() {
            Ok(())
        } else {
            Err(invalid("не удалось передать настроенный процесс AWG"))
        }
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        let _ = self.channel.shutdown(Shutdown::Both);
        let _ = self.helper.wait();
    }
}

pub(super) fn spawn(engine: &Path, iface: &str) -> io::Result<Launch> {
    let (channel, child_channel) = UnixStream::pair()?;
    channel.set_read_timeout(Some(Duration::from_secs(6)))?;
    let helper = Command::new("/proc/self/exe")
        .arg("launch-awg-client")
        .arg(engine)
        .arg(iface)
        .stdin(Stdio::from(OwnedFd::from(child_channel)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut launch = Launch {
        helper,
        channel,
        pid: 0,
    };
    launch.channel.write_all(START)?;
    let mut bytes = [0; 4];
    launch.channel.read_exact(&mut bytes)?;
    launch.pid = u32::from_be_bytes(bytes);
    if launch.pid < 2 {
        return Err(invalid("неверный PID процесса AWG"));
    }
    Ok(launch)
}

pub fn run_launcher(engine: &Path, iface: &str) -> io::Result<()> {
    if ![
        Path::new("/opt/usr/bin/amneziawg-go"),
        Path::new("/usr/bin/amneziawg-go"),
    ]
    .contains(&engine)
        || iface.len() >= libc::IFNAMSIZ
        || !iface
            .strip_prefix("awg")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid("неверный движок или интерфейс AWG"));
    }
    let mut channel = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
    // SO_PEERCRED on a socketpair records its creator. Only the parent panel
    // can request startup on this inherited connection.
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            channel.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || peer.uid != unsafe { libc::geteuid() }
        || peer.pid <= 1
        || peer.pid != unsafe { libc::getppid() }
    {
        return Err(invalid("не удалось подтвердить управляющий процесс AWG"));
    }
    let parent = std::fs::metadata(format!("/proc/{}/exe", peer.pid))?;
    let own = std::fs::metadata("/proc/self/exe")?;
    if (parent.dev(), parent.ino()) != (own.dev(), own.ino()) {
        return Err(invalid("управляющий процесс AWG не принадлежит панели"));
    }
    channel.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = [0; 4];
    channel.read_exact(&mut request)?;
    if &request != START {
        return Err(invalid("неверный запрос запуска AWG"));
    }
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    let (limit, gc) = soft_limit();
    let mut command = Command::new(engine);
    command
        .args(["-f", iface])
        .env("WG_PROCESS_FOREGROUND", "1")
        .env("GOMEMLIMIT", limit)
        .env("GOGC", gc)
        .env("GODEBUG", "madvdontneed=1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    supervise(&mut command, &mut channel)
}

fn supervise(command: &mut Command, channel: &mut UnixStream) -> io::Result<()> {
    channel.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut engine = command.spawn()?;
    let transfer = (|| {
        channel.write_all(&engine.id().to_be_bytes())?;
        let mut decision = [0; 1];
        loop {
            if engine.try_wait()?.is_some() {
                return Err(invalid("движок AWG завершился до передачи управления"));
            }
            match channel.read(&mut decision) {
                Ok(1) if decision[0] == COMMIT => return Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e),
                _ => return Err(invalid("панель отменила запуск AWG")),
            }
        }
    })();
    if transfer.is_err() {
        terminate(&mut engine)?;
    }
    transfer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn losing_the_control_socket_reaps_the_child_but_a_committed_engine_survives() {
        for commit in [false, true] {
            let (mut parent, mut control) = UnixStream::pair().unwrap();
            let job = std::thread::spawn(move || {
                let mut command = Command::new("sleep");
                command.arg("60");
                supervise(&mut command, &mut control)
            });
            let mut bytes = [0; 4];
            parent.read_exact(&mut bytes).unwrap();
            let pid = u32::from_be_bytes(bytes) as libc::pid_t;
            if commit {
                parent.write_all(&[COMMIT]).unwrap();
            }
            drop(parent);
            assert_eq!(job.join().unwrap().is_ok(), commit);
            // The fixture runs in this process. For a committed transfer the
            // test is still the kernel parent and must reap its test child.
            let mut status = 0;
            let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if commit {
                assert_eq!(observed, 0);
                assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            } else {
                assert_eq!(observed, -1);
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD)
                );
            }
        }
    }
}
