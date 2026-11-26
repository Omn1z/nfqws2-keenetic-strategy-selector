use std::{collections::VecDeque, io, time::Instant};
pub trait Runner: Send + Sync {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String>;
    /// Capture a complete bounded snapshot, rejecting truncation.
    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        deadline: Instant,
        limit: usize,
    ) -> io::Result<String> {
        let output = self.run(program, args, deadline)?;
        if output.len() > limit {
            return Err(io::Error::other("command output exceeds limit"));
        }
        Ok(output)
    }
    fn run_input(&self, _: &str, _: &[&str], _: &[u8], _: Instant) -> io::Result<String> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Return the most recent complete log lines within the byte budget.
    fn run_tail(
        &self,
        program: &str,
        args: &[&str],
        deadline: Instant,
        limit: usize,
    ) -> io::Result<String> {
        let raw = self.run(program, args, deadline)?;
        if raw.len() <= limit {
            return Ok(raw);
        }
        let mut bytes = Capture::new(limit, true);
        bytes.push(raw.as_bytes())?;
        bytes.finish()
    }
}
pub struct System;

#[derive(Debug)]
struct CommandExit {
    program: String,
    status: std::process::ExitStatus,
}

impl std::fmt::Display for CommandExit {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{} {}", self.program, self.status)
    }
}

impl std::error::Error for CommandExit {}

/// The child itself reported failure. An interrupted wait or lost output
/// is not evidence that the requested command completed.
pub fn reported_failure(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<CommandExit>())
        .is_some_and(|exit| exit.status.code().is_some())
}

#[cfg(target_os = "linux")]
fn has_keenetic_entware_shell(root: &std::path::Path) -> bool {
    root.join("bin/ndmc").is_file() && root.join("opt/bin/sh").is_file()
}

#[cfg(target_os = "linux")]
fn command(program: &str) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    // Keenetic's firmware shell drops the positional arguments to sh -c.
    // Use the Entware shell without changing how other tools are resolved.
    let executable = if program == "sh" && has_keenetic_entware_shell(std::path::Path::new("/")) {
        "/opt/bin/sh"
    } else {
        program
    };
    let mut cmd = std::process::Command::new(executable);
    if program == "/opt/libexec/ip-full" {
        // Entware's iproute2 dispatches on argv[0], even for "rule show".
        cmd.arg0("ip");
    }
    cmd
}
#[cfg(not(target_os = "linux"))]
impl Runner for System {
    fn run(&self, _: &str, _: &[&str], _: Instant) -> io::Result<String> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[cfg(target_os = "linux")]
impl Runner for System {
    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        deadline: Instant,
    ) -> io::Result<String> {
        use std::io::{Seek, Write};
        let mut file = tempfile::tempfile()?;
        file.write_all(input)?;
        file.rewind()?;
        output_with_file(command(program).args(args), file, deadline, 4 << 20)
    }
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        self.run_bounded(
            program,
            args,
            deadline.min(Instant::now() + std::time::Duration::from_secs(8)),
            4 << 20,
        )
    }
    fn run_bounded(
        &self,
        program: &str,
        args: &[&str],
        deadline: Instant,
        limit: usize,
    ) -> io::Result<String> {
        output(command(program).args(args), deadline, limit)
    }
    fn run_tail(
        &self,
        program: &str,
        args: &[&str],
        deadline: Instant,
        limit: usize,
    ) -> io::Result<String> {
        capture(
            command(program).args(args),
            deadline,
            Capture::new(limit, true),
            std::process::Stdio::null(),
        )
    }
}
struct Capture {
    bytes: VecDeque<u8>,
    limit: usize,
    tail: bool,
    discarded: bool,
}
impl Capture {
    fn new(limit: usize, tail: bool) -> Self {
        Self {
            bytes: VecDeque::new(),
            limit,
            tail,
            discarded: false,
        }
    }
    fn push(&mut self, chunk: &[u8]) -> io::Result<()> {
        let excess = chunk.len().saturating_sub(self.limit - self.bytes.len());
        if excess > 0 && !self.tail {
            return Err(io::Error::other("command output exceeds configured limit"));
        }
        self.discarded |= excess > 0;
        let removed = excess.min(self.bytes.len());
        self.bytes.drain(..removed);
        self.bytes.extend(&chunk[excess - removed..]);
        Ok(())
    }
    fn finish(mut self) -> io::Result<String> {
        if self.discarded {
            let skip = self
                .bytes
                .iter()
                .position(|b| *b == b'\n')
                .map_or(self.bytes.len(), |i| i + 1);
            self.bytes.drain(..skip);
        }
        let mut s = String::from_utf8(Vec::from(self.bytes))
            .map_err(|_| io::Error::other("invalid command output encoding"))?;
        if !self.tail {
            s.truncate(s.trim_end().len());
            let start = s.len() - s.trim_start().len();
            s.drain(..start);
        }
        Ok(s)
    }
}
/// Capture bounded stdout and discard stderr (which may include credentials).
#[cfg(target_os = "linux")]
pub fn output(
    cmd: &mut std::process::Command,
    deadline: Instant,
    limit: usize,
) -> io::Result<String> {
    capture(
        cmd,
        deadline,
        Capture::new(limit, false),
        std::process::Stdio::null(),
    )
}
/// Stream a prepared file through stdin without placing its contents in argv.
#[cfg(target_os = "linux")]
pub fn output_with_file(
    cmd: &mut std::process::Command,
    input: std::fs::File,
    deadline: Instant,
    limit: usize,
) -> io::Result<String> {
    capture(cmd, deadline, Capture::new(limit, false), input.into())
}
#[cfg(target_os = "linux")]
fn capture(
    cmd: &mut std::process::Command,
    deadline: Instant,
    mut data: Capture,
    input: std::process::Stdio,
) -> io::Result<String> {
    use std::{
        io::Read,
        os::unix::{io::AsRawFd, process::CommandExt},
        process::Stdio,
        thread,
        time::Duration,
    };
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .process_group(0)
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = child.stdout.take().expect("piped stdout");
    let fd = output.as_raw_fd();
    let mut reaped = false;
    let result = (|| {
        // The pipe belongs to this child and has no competing readers.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = [0; 8192];
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match output.read(&mut buf) {
                Ok(0) => {
                    if let Some(status) = child.try_wait()? {
                        reaped = true;
                        if !status.success() {
                            return Err(io::Error::other(CommandExit { program, status }));
                        }
                        return data.finish();
                    }
                }
                Ok(n) => {
                    data.push(&buf[..n])?;
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() && !reaped {
        // Kill only the dedicated process group, including descendants holding the pipe.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn ring_retains_only_complete_utf8_log_lines_with_bounded_memory() {
        let input = "old contents\n сетевая запись\n valid\nmore\nlatest\n";
        for limit in [0, 1, 8, 16, 32, 64] {
            for width in [1, 2, 9, 40, 128] {
                let mut cap = Capture::new(limit, true);
                for chunk in input.as_bytes().chunks(width) {
                    cap.push(chunk).unwrap();
                    assert!(cap.bytes.len() <= limit);
                }
                let expect = if input.len() <= limit {
                    input
                } else {
                    let bytes = &input.as_bytes()[input.len() - limit..];
                    bytes
                        .iter()
                        .position(|b| *b == b'\n')
                        .map(|i| std::str::from_utf8(&bytes[i + 1..]).unwrap())
                        .unwrap_or("")
                };
                assert_eq!(cap.finish().unwrap(), expect);
            }
        }
        let mut strict = Capture::new(4, false);
        strict.push(b"test").unwrap();
        assert!(strict.push(b"more").is_err());
        assert_eq!(strict.finish().unwrap(), "test");
    }
    #[test]
    fn runner_obeys_deadlines_on_supported_platforms() {
        let deadline = Instant::now() + Duration::from_secs(1);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(System.run("printf", &["test"], deadline).unwrap(), "test");
            assert_eq!(
                System
                    .run("sleep", &["5"], Instant::now() + Duration::from_millis(80))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            System.run("fixture", &[], deadline).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn private_input_is_read_from_the_file_and_stdout_is_bounded() {
        let run = |limit| {
            output_with_file(
                std::process::Command::new("head").args(["-c", "4"]),
                std::fs::File::open("/dev/zero").unwrap(),
                Instant::now() + Duration::from_secs(3),
                limit,
            )
        };
        assert_eq!(run(4).unwrap().as_bytes(), [0; 4]);
        assert!(run(3).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn entware_shell_selection_requires_keenetic_and_an_installed_shell() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path();
        std::fs::create_dir(path.join("bin")).unwrap();
        std::fs::create_dir_all(path.join("opt/bin")).unwrap();
        std::fs::write(path.join("opt/bin/sh"), "shell").unwrap();
        assert!(!has_keenetic_entware_shell(path));
        std::fs::write(path.join("bin/ndmc"), "ndmc").unwrap();
        assert!(has_keenetic_entware_shell(path));
        std::fs::remove_file(path.join("opt/bin/sh")).unwrap();
        assert!(!has_keenetic_entware_shell(path));
    }
}
