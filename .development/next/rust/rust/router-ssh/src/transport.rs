use crate::args::Connection;
use std::{
    env, io,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const ASKPASS_MODE: &str = "N2S_SSH_PASSWORD_PROMPT";

// OpenSSH invokes the same executable as its non-interactive password reader.
// The extra marker and prompt check keep normal invocations from emitting a password.
pub fn password_prompt(args: &[String]) -> Option<io::Result<()>> {
    if env::var_os(ASKPASS_MODE).as_deref() != Some("1".as_ref()) {
        return None;
    }
    if matches!(args, [prompt] if prompt.trim_end().to_ascii_lowercase().ends_with("password:")) {
        return Some(
            env::var("ROUTER_PASS")
                .map(|pw| println!("{pw}"))
                .map_err(|_| io::Error::other("password unavailable")),
        );
    }
    Some(Err(io::Error::other(
        "unexpected SSH authentication prompt",
    )))
}

impl Connection {
    pub fn run(
        &self,
        remote: &str,
        input: Stdio,
        output: Stdio,
        timeout: Duration,
    ) -> io::Result<ExitStatus> {
        let mut ssh = Command::new("ssh");
        ssh.args([
            "-F",
            "none",
            "-T",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ]);
        if let Some(path) = env::var_os("ROUTER_KNOWN_HOSTS") {
            // OpenSSH tokenizes -o values as config lines; quote a path containing spaces.
            let value = path
                .to_str()
                .ok_or_else(|| io::Error::other("invalid known_hosts path"))?;
            if value.contains(['\n', '\r', '"']) {
                return Err(io::Error::other("invalid known_hosts path"));
            }
            let value = if cfg!(windows) {
                value.replace('\\', "/")
            } else {
                value.replace('\\', "\\\\")
            };
            ssh.arg("-o").arg(format!("UserKnownHostsFile=\"{value}\""));
        }
        ssh.arg("-p")
            .arg(self.port.to_string())
            .arg("-l")
            .arg(&self.user)
            .arg("--")
            .arg(&self.host)
            .arg(remote)
            .env("SSH_ASKPASS", env::current_exe()?)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env(ASKPASS_MODE, "1")
            .env("ROUTER_PASS", &self.password)
            .stdin(input)
            .stdout(output)
            .stderr(Stdio::inherit());
        let mut child = ssh
            .spawn()
            .map_err(|err| io::Error::new(err.kind(), format!("cannot start OpenSSH: {err}")))?;
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("remote command timed out after {timeout:?}"),
                ));
            }
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }
}
