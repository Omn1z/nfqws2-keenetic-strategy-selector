use crate::{firewall, probe, Request};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    process::{Command, ExitCode},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    thread,
};

static CANCEL: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn stop(_: libc::c_int) {
    CANCEL.store(true, Ordering::Relaxed);
}
fn emit(value: Value) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, &value)?;
    out.write_all(b"\n")?;
    out.flush()
}
fn check_curl() -> io::Result<()> {
    let out = Command::new("curl")
        .args(["--disable", "--version"])
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("curl required: {e}")))?;
    let info = String::from_utf8_lossy(&out.stdout);
    let version = info
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.split_once('.'))
        .and_then(|(a, b)| {
            Some((
                a.parse::<u32>().ok()?,
                b.split('.').next()?.parse::<u32>().ok()?,
            ))
        });
    if !out.status.success()
        || version.is_none_or(|v| v < (7, 63))
        || !info
            .lines()
            .any(|l| l.starts_with("Protocols:") && l.split_whitespace().any(|v| v == "https"))
    {
        return Err(io::Error::other("curl 7.63+ with HTTPS support required"));
    }
    Ok(())
}
fn run() -> io::Result<&'static str> {
    #[cfg(unix)]
    // Only an atomic flag changes in a signal handler. The owning thread
    // stops workers and undoes the firewall transaction before exit.
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
    }
    let mut input = BufReader::new(io::stdin());
    let mut bytes = Vec::new();
    (&mut input)
        .take(8 * 1024 * 1024 + 1024)
        .read_until(b'\n', &mut bytes)?;
    if bytes.last() != Some(&b'\n') {
        return Err(io::Error::other("incomplete or oversized helper request"));
    }
    let req: Request = serde_json::from_slice(&bytes)?;
    drop(bytes);
    let ports = req.ports()?;
    thread::Builder::new()
        .stack_size(96 * 1024)
        .spawn(move || {
            let mut buf = [0u8; 1];
            let _ = input.read(&mut buf);
            // EOF also means the parent panel has exited.
            CANCEL.store(true, Ordering::Relaxed);
        })?;
    check_curl()?;
    let _lock = firewall::exclusive()?;
    if CANCEL.load(Ordering::Relaxed) {
        return Ok("cancelled");
    }
    let mut sandbox = match firewall::Sandbox::open_with(firewall::System, &ports, || {
        if CANCEL.load(Ordering::Relaxed) {
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        } else {
            Ok(())
        }
    }) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::Interrupted && CANCEL.load(Ordering::Relaxed) => {
            return Ok("cancelled")
        }
        Err(e) => return Err(e),
    };
    let next = AtomicUsize::new(0);
    let failure = Mutex::new(None);
    thread::scope(|scope| {
        for range in ports {
            let targets = &req.targets;
            let next = &next;
            let failure = &failure;
            let spawned =
                thread::Builder::new()
                    .stack_size(192 * 1024)
                    .spawn_scoped(scope, move || {
                        while !CANCEL.load(Ordering::Relaxed) {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(host) = targets.get(i) else { break };
                            let measured = if probe::valid_host(host) {
                                probe::measure(
                                    host,
                                    &format!("https://{host}/"),
                                    range,
                                    None,
                                    &CANCEL,
                                )
                            } else {
                                Ok(probe::Measurement {
                                    err: "invalid domain or IPv4 address".into(),
                                    ..Default::default()
                                })
                            };
                            if CANCEL.load(Ordering::Relaxed) {
                                break;
                            }
                            if let Err(e) =
                                measured.and_then(|r| emit(json!({"target":r.classify(host)})))
                            {
                                *failure.lock().unwrap() = Some(e);
                                CANCEL.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    });
            if let Err(e) = spawned {
                *failure.lock().unwrap() = Some(e);
                CANCEL.store(true, Ordering::Relaxed);
                break;
            }
        }
    });
    let verified = sandbox.verify();
    let closed = sandbox.close();
    if let Err(e) = closed {
        return Err(io::Error::other(format!("firewall rollback: {e}")));
    }
    verified.map_err(|e| io::Error::other(format!("block-check isolation: {e}")))?;
    if let Some(e) = failure.into_inner().unwrap() {
        return Err(e);
    }
    Ok(if CANCEL.load(Ordering::Relaxed) {
        "cancelled"
    } else {
        "done"
    })
}
pub fn cli() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--recover") {
        return match firewall::recover_owned() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("nfqws2-blockcheck {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run() {
        Ok(status) => match emit(json!({"status":status})) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Err(e) => {
            let _ = emit(json!({"status":"error","error":e.to_string()}));
            ExitCode::FAILURE
        }
    }
}
