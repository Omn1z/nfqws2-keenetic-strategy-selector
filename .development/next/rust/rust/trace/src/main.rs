mod awg;
mod awg_sni;
mod device;
mod flows;
mod hello;
#[cfg(target_os = "linux")]
mod packet;
mod pcap;
use serde_json::{json, Value};
use std::{
    io::{self, Read, Write},
    net::IpAddr,
    path::Path,
    process::{Command, ExitCode},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
static CANCEL: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn cancel(_: libc::c_int) {
    CANCEL.store(true, Ordering::Relaxed);
}
fn emit(v: Value) -> io::Result<()> {
    let mut out = io::stderr().lock();
    serde_json::to_writer(&mut out, &v)?;
    out.write_all(b"\n")?;
    out.flush()
}
fn trace(path: &Path, ip: IpAddr, seconds: u64) -> io::Result<()> {
    let start = Instant::now();
    let mut tracker = flows::Tracker::default();
    loop {
        if CANCEL.load(Ordering::Relaxed) {
            break;
        }
        let now = start.elapsed();
        let events = tracker.sample(path, ip, now.as_millis() as u64)?;
        emit(json!({"events":events,"elapsed_ms":now.as_millis()}))?;
        if now >= Duration::from_secs(seconds) {
            break;
        }
        thread::sleep(Duration::from_millis(500).saturating_sub(start.elapsed() - now));
    }
    let limited = tracker.limited;
    emit(
        json!({"status":if CANCEL.load(Ordering::Relaxed) {"cancelled"} else {"done"},
        "elapsed_ms":start.elapsed().as_millis(),"limited":limited,"conns":tracker.finish()}),
    )
}
fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    if mode == "--version" {
        println!("nfqws2-trace {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if mode == "awg" {
        return awg::run(args.collect());
    }
    if mode == "awg-sni" {
        if args.next().is_some() {
            return Err(io::Error::other("usage: nfqws2-trace awg-sni"));
        }
        return awg_sni::run();
    }
    if !matches!(mode.as_str(), "trace" | "pcap" | "hello") {
        return Err(io::Error::other(
            "usage: nfqws2-trace trace|pcap|hello IP SECONDS [WAN...]",
        ));
    }
    let ip: IpAddr = args
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("invalid IP"))?;
    let seconds = args
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| (1..=120).contains(v))
        .ok_or_else(|| io::Error::other("duration must be 1..120 seconds"))?;
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, cancel as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, cancel as *const () as libc::sighandler_t);
    }
    thread::Builder::new().stack_size(96 * 1024).spawn(|| {
        let _ = io::stdin().read(&mut [0]);
        CANCEL.store(true, Ordering::Relaxed);
    })?;
    let dev = device::interface(ip, &args.collect::<Vec<_>>())?;
    let binary = if mode != "trace" {
        let Some(bin) = pcap::tcpdump() else {
            return emit(json!({"need_install":true,"package":"tcpdump"}));
        };
        Some(bin)
    } else {
        None
    };
    emit(json!({"ready":true,"iface":dev.iface,"client_hello_records":mode == "hello"}))?;
    if let Some(bin) = binary {
        pcap::run(Command::new(bin), ip, &dev, seconds, mode == "hello")
    } else {
        trace(Path::new("/proc/net/nf_conntrack"), ip, seconds)
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = emit(json!({"status":"error","error":e.to_string()}));
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests;
