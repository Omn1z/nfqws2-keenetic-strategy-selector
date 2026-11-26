use crate::{device::Device, emit, hello, CANCEL};
use portable_atomic::AtomicU64;
use serde_json::json;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::IpAddr,
    process::{Command, Stdio},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

pub const MAX_FILE: u64 = 2 * 1024 * 1024;
#[derive(Default)]
struct Count {
    packets: AtomicU64,
    size: AtomicU64,
}
pub fn tcpdump() -> Option<std::path::PathBuf> {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&paths)
        .chain(["/opt/sbin", "/opt/bin", "/usr/sbin"].map(Into::into))
        .map(|p| p.join(format!("tcpdump{}", std::env::consts::EXE_SUFFIX)))
        .find(|p| p.is_file())
}
fn args(ip: IpAddr, dev: &Device, client_hellos: bool) -> Vec<String> {
    let snap = if client_hellos { hello::SNAP } else { 0 }.to_string();
    let mut args = [
        "-i", &dev.iface, "-n", "-p", "-U", "-B", "256", "-s", &snap, "-w", "-",
    ]
    .map(str::to_string)
    .to_vec();
    if client_hellos {
        args.extend(
            [
                "src",
                "host",
                &ip.to_string(),
                "and",
                "ether",
                "src",
                &dev.mac,
                "and",
                "tcp",
                "dst",
                "port",
                "443",
            ]
            .map(str::to_owned),
        );
    } else {
        args.extend(["host", &ip.to_string(), "and", "ether", "host", &dev.mac].map(str::to_owned));
    }
    args
}
// An interrupted tcpdump can leave a partial record in its pipe. Only commit
// complete records and enforce a hard aggregate limit, even at line rate.
enum Frame<'a> {
    Header(&'a [u8], bool, usize),
    Packet(&'a [u8], &'a [u8]),
}
fn read_records(
    mut input: impl Read,
    count: &Count,
    limit: u64,
    mut accept: impl FnMut(Frame<'_>) -> io::Result<()>,
) -> io::Result<bool> {
    let mut header = [0u8; 24];
    input.read_exact(&mut header)?;
    let le = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err(io::Error::other("tcpdump supplied an invalid pcap header")),
    };
    let word = |buf: &[u8]| {
        let bytes = buf.try_into().unwrap();
        if le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let snap = word(&header[16..20]);
    if snap == 0 || snap > 262144 {
        return Err(io::Error::other("invalid pcap snap length"));
    }
    accept(Frame::Header(
        &header,
        word(&header[20..24]) & 0xffff == 1,
        snap as usize,
    ))?;
    count.size.store(24, Ordering::Relaxed);
    let mut record = [0u8; 16];
    let mut packet = Vec::new();
    loop {
        if input.read(&mut record[..1])? == 0 {
            return Ok(false);
        }
        input.read_exact(&mut record[1..])?;
        let len = word(&record[8..12]);
        if len > snap || len > word(&record[12..16]) {
            return Err(io::Error::other("invalid pcap record length"));
        }
        let size = count.size.load(Ordering::Relaxed) + 16 + u64::from(len);
        if size > limit {
            return Ok(true);
        }
        packet.resize(len as usize, 0);
        input.read_exact(&mut packet)?;
        accept(Frame::Packet(&record, &packet))?;
        count.size.store(size, Ordering::Relaxed);
        count.packets.fetch_add(1, Ordering::Relaxed);
        if size == limit {
            return Ok(true);
        }
    }
}
fn copy_records(
    input: impl Read,
    mut output: impl Write,
    count: &Count,
    limit: u64,
) -> io::Result<bool> {
    read_records(input, count, limit, |frame| match frame {
        Frame::Header(header, _, _) => output.write_all(header),
        Frame::Packet(record, packet) => {
            output.write_all(record)?;
            output.write_all(packet)
        }
    })
}
fn interrupt(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    #[cfg(not(unix))]
    let _ = child.kill();
}
pub fn run(
    mut cmd: Command,
    ip: IpAddr,
    dev: &Device,
    seconds: u64,
    client_hellos: bool,
) -> io::Result<()> {
    cmd.args(args(ip, dev, client_hellos))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = std::process::id();
        // The capture cannot outlive its worker, including after SIGKILL.
        unsafe {
            cmd.pre_exec(move || {
                let z: libc::c_ulong = 0;
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    z,
                    z,
                    z,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn()?;
    let input = child.stdout.take().unwrap();
    let errors = child.stderr.take().unwrap();
    let count = Count::default();
    let start = Instant::now();
    thread::scope(|scope| {
        let counter = &count;
        let mut summary = client_hellos.then(|| hello::Summary::new(ip));
        let writer = scope.spawn(move || {
            let limited = if let Some(view) = summary.as_mut() {
                read_records(input, counter, MAX_FILE, |frame| match frame {
                    Frame::Header(_, ethernet, snap) => view.header(ethernet, snap),
                    Frame::Packet(_, bytes) => {
                        view.observe(bytes);
                        Ok(())
                    }
                })
            } else {
                copy_records(input, io::stdout().lock(), counter, MAX_FILE)
            };
            (limited, summary)
        });
        let diagnostics = scope.spawn(|| {
            let mut dropped = 0u64;
            let mut error = String::new();
            let mut buf = Vec::new();
            let mut reader = BufReader::new(errors);
            while {
                buf.clear();
                (&mut reader).take(2048).read_until(b'\n', &mut buf)? != 0
            } {
                let s = String::from_utf8_lossy(&buf);
                if s.contains("dropped by kernel") {
                    dropped = s
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
                if !s.contains("listening on") && !s.contains("packets ") && error.len() < 1024 {
                    error.push_str(s.trim());
                }
            }
            Ok::<_, io::Error>((dropped, error))
        });
        let mut stopping = None;
        let mut next = Duration::from_secs(1);
        let mut pipe_error = None;
        let status = loop {
            let elapsed = start.elapsed();
            if stopping.is_none()
                && (elapsed >= Duration::from_secs(seconds)
                    || CANCEL.load(Ordering::Relaxed)
                    || writer.is_finished()
                    || pipe_error.is_some())
            {
                interrupt(&mut child);
                stopping = Some(Instant::now());
            }
            if stopping.is_some_and(|t| t.elapsed() > Duration::from_secs(1)) {
                let _ = child.kill();
            }
            if let Some(code) = child.try_wait()? {
                break code;
            }
            if elapsed >= next {
                if let Err(e) = emit(
                    json!({"elapsed_ms":elapsed.as_millis(),"size_bytes":count.size.load(Ordering::Relaxed),"packets":count.packets.load(Ordering::Relaxed)}),
                ) {
                    pipe_error = Some(e);
                }
                next = elapsed + Duration::from_secs(1);
            }
            thread::sleep(Duration::from_millis(30));
        };
        let (stored, summary) = writer
            .join()
            .map_err(|_| io::Error::other("capture writer stopped"))?;
        let (dropped, error) = diagnostics
            .join()
            .map_err(|_| io::Error::other("capture diagnostics stopped"))??;
        if let Some(e) = pipe_error {
            return Err(e);
        }
        let cancelled = CANCEL.load(Ordering::Relaxed);
        let limited = match stored {
            Ok(value) => value,
            Err(_) if cancelled => false,
            Err(e)
                if stopping.is_some()
                    && e.kind() == io::ErrorKind::UnexpectedEof
                    && count.size.load(Ordering::Relaxed) >= 24 =>
            {
                false
            }
            Err(e) => return Err(io::Error::other(format!("tcpdump {status}: {error} {e}"))),
        };
        if !cancelled && !limited && start.elapsed() < Duration::from_secs(seconds) {
            return Err(io::Error::other(format!(
                "tcpdump stopped early ({status}): {error}"
            )));
        }
        let mut outcome = json!({"status":if cancelled {"cancelled"} else {"done"},"elapsed_ms":start.elapsed().as_millis(),"limited":limited,
            "size_bytes":count.size.load(Ordering::Relaxed),"packets":count.packets.load(Ordering::Relaxed),"dropped":dropped});
        if let Some(mut view) = summary {
            let candidates = view.finish();
            // stdout is a private, anonymous file owned by the panel. The
            // separate status channel contains only the public metadata.
            let mut archive = io::stdout().lock();
            for row in &candidates {
                archive.write_all(&row.bytes)?;
            }
            archive.flush()?;
            outcome["candidates"] = json!(candidates);
            outcome["observations"] = json!(view.destinations);
            outcome["limited"] = json!(limited || view.overflow);
        }
        emit(outcome)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(le: bool) -> Vec<u8> {
        let n = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let mut raw = vec![0; 24];
        raw[..4].copy_from_slice(&n(0xa1b2c3d4));
        raw[16..20].copy_from_slice(&n(65535));
        for _ in 0..4 {
            raw.extend([0; 8]);
            raw.extend(n(20));
            raw.extend(n(20));
            raw.extend([0; 20]);
        }
        raw
    }
    #[test]
    fn enforces_file_limit_at_complete_record_and_discards_cut_frames() {
        for le in [true, false] {
            let mut raw = fixture(le);
            let mut out = Vec::new();
            let count = Count::default();
            assert!(copy_records(raw.as_slice(), &mut out, &count, 24 + 3 * 36 + 1).unwrap());
            assert_eq!(out, raw[..24 + 3 * 36]);
            assert_eq!(count.packets.load(Ordering::Relaxed), 3);
            raw.pop();
            out.clear();
            assert!(copy_records(raw.as_slice(), &mut out, &Count::default(), MAX_FILE).is_err());
            assert_eq!(out.len(), 24 + 3 * 36);
        }
        assert!(copy_records(&[0u8; 24][..], Vec::new(), &Count::default(), MAX_FILE).is_err());
    }
    #[test]
    fn capture_always_has_ip_mac_and_lan_interface_filters() {
        let dev = Device {
            iface: "br2".into(),
            mac: "02:aa:00:00:00:01".into(),
        };
        let a = args("192.0.2.4".parse().unwrap(), &dev, false);
        assert_eq!(a[0..2], ["-i", "br2"]);
        assert!(a.contains(&"-p".into()));
        assert!(a.ends_with(
            &[
                "host",
                "192.0.2.4",
                "and",
                "ether",
                "host",
                "02:aa:00:00:00:01"
            ]
            .map(str::to_owned)
        ));
    }
}
