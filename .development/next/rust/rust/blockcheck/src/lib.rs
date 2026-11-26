mod cli;
pub use cli::cli;
pub mod firewall;
pub mod probe;

// If the supervisor has to recover from a killed helper, none of its probes
// may continue opening sockets after the private OUTPUT rules are removed.
fn tied_to_parent(cmd: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = std::process::id();
        // Only direct Linux syscalls in the forked child; check getppid to
        // cover the fork-to-prctl race if our parent has already exited.
        unsafe {
            cmd.pre_exec(move || {
                let zero: libc::c_ulong = 0;
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    zero,
                    zero,
                    zero,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
}

use serde::Deserialize;
use std::io;

#[derive(Deserialize)]
pub struct Request {
    pub targets: Vec<String>,
    pub threads: usize,
    pub port_base: u16,
    pub ports_per_worker: u16,
    pub wan_ifaces: Vec<String>,
}

impl Request {
    pub fn ports(&self) -> io::Result<Vec<(u16, u16)>> {
        if self.wan_ifaces.is_empty()
            || self.threads == 0
            || self.threads > 8
            || self.threads > self.targets.len()
            || self.port_base == 0
            || self.ports_per_worker == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid worker count, source ports or WAN interfaces",
            ));
        }
        (0..self.threads)
            .map(|i| {
                let lo = u32::from(self.port_base) + i as u32 * u32::from(self.ports_per_worker);
                let hi = lo + u32::from(self.ports_per_worker) - 1;
                let hi = u16::try_from(hi).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "worker port range exceeds 65535",
                    )
                })?;
                Ok((lo as u16, hi))
            })
            .collect()
    }
}
