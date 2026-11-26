mod arpblock;
mod assets;
mod awg_profiles;
mod awg_rules;
mod backup;
mod blobs;
mod blockcheck;
mod bridge_mac;
mod cli;
mod data;
mod dns;
mod dnsserver;
mod editor;
mod engine;
mod geo;
mod http;
mod monitor;
mod packages;
mod portforward;
mod ports;
#[cfg(unix)]
mod process_group;
mod release_assets;
mod runs;
mod settings;
mod socks5;
#[cfg(test)]
mod tests;
mod tgws;
mod trace;
mod update;

use nfqws2_config::Config;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
};
use tokio::net::TcpListener;

const VERSION: &str = match option_env!("N2S_BUILD_VERSION") {
    Some(v) => v,
    None => "dev",
};
const REPO: &str = "Omn1z/nfqws2-keenetic-strategy-selector";

#[derive(Default)]
struct Serve {
    listen: Option<String>,
    ignore_saved: bool,
    daemon: bool,
    log: Option<PathBuf>,
    pid: Option<PathBuf>,
}
fn invalid(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s.into())
}
impl Serve {
    fn parse(mut args: impl Iterator<Item = String>) -> io::Result<Self> {
        let mut opts = Self::default();
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| invalid(format!("missing value for {flag}")))
            };
            match flag.as_str() {
                "-l" => opts.listen = Some(value()?),
                "--ignore-saved-port" => opts.ignore_saved = true,
                "-d" => opts.daemon = true,
                "-pid" => opts.pid = Some(value()?.into()),
                "-log" => opts.log = Some(value()?.into()),
                _ => return Err(invalid(format!("unknown option {flag}"))),
            }
        }
        Ok(opts)
    }
}
fn saved_panel_port(dir: &Path) -> io::Result<Option<std::num::NonZeroU16>> {
    let file = match fs::File::open(dir.join("ports.json")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        f => f?,
    };
    #[derive(serde::Deserialize)]
    struct Ports {
        panel_port: std::num::NonZeroU16,
    }
    let ports: Ports = serde_json::from_reader(file).map_err(|e| {
        invalid(format!(
            "ports.json: {e}; use --ignore-saved-port to recover"
        ))
    })?;
    Ok(Some(ports.panel_port))
}
fn saved_addr(dir: &Path, fallback: &str) -> io::Result<String> {
    let Some(port) = saved_panel_port(dir)? else {
        return Ok(fallback.into());
    };
    let (host, _) = fallback
        .rsplit_once(':')
        .ok_or_else(|| invalid("invalid listen address"))?;
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(invalid("expected a bracketed IPv6 address"));
    }
    Ok(format!("{host}:{port}"))
}
#[cfg(target_os = "linux")]
fn detach(opts: &Serve) -> io::Result<bool> {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    if env::var_os("N2S_DAEMONIZED").is_some_and(|v| v == "1") {
        if let Some(pid) = &opts.pid {
            fs::write(pid, std::process::id().to_string())?;
        }
        return Ok(false);
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(opts.log.as_deref().unwrap_or(Path::new("/dev/null")))?;
    let mut cmd = Command::new(env::current_exe()?);
    cmd.args(env::args_os().skip(1))
        .env("N2S_DAEMONIZED", "1")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // setsid is async-signal-safe. No allocation or Rust locks after fork.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    cmd.spawn()?;
    Ok(true)
}
#[cfg(not(target_os = "linux"))]
fn detach(_: &Serve) -> io::Result<bool> {
    Ok(false)
}

async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! { _ = term.recv() => (), _ = tokio::signal::ctrl_c() => () }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
async fn serve(
    config: Config,
    log_path: Option<&Path>,
    previous: Option<std::sync::Arc<TcpListener>>,
) -> io::Result<Option<std::sync::Arc<TcpListener>>> {
    let addr = config.listen_addr.clone();
    let state = http::AppState::open_with_log(
        config,
        Path::new("/"),
        env::var_os("N2S_NOAUTH").is_some_and(|v| v == "1"),
        log_path,
    )?;
    let listener = if let Some(socket) =
        previous.filter(|s| s.local_addr().is_ok_and(|a| a.to_string() == addr))
    {
        socket
    } else if let Some(port) = addr.strip_prefix(':') {
        std::sync::Arc::new(match TcpListener::bind(format!("[::]:{port}")).await {
            Ok(listener) => listener,
            Err(_) => TcpListener::bind(format!("0.0.0.0:{port}")).await?,
        })
    } else {
        std::sync::Arc::new(TcpListener::bind(addr).await?)
    };
    eprintln!(
        "nfqws2-strategy {VERSION} listening on {}",
        listener.local_addr()?
    );
    let listener = state.ports.attach(listener)?;
    if let Err(e) = portforward::restore(&state) {
        state.logs.append("port-forwarding", "warn", &e.to_string());
    }
    geo::start_auto(&state);
    bridge_mac::restore(&state).await;
    bridge_mac::start_refresh(&state);
    engine::restore_manual_off(&state).await;
    // Go keeps the tunnel daemons alive on shutdown. Inspect their UAPI before
    // legacy client reconciliation marks an active, unowned Go policy pending.
    let go_handoff = nfqws2_awg_rules::kernel::handoff::pending(&state.store)?;
    if !go_handoff {
        awg_profiles::restore(&state).await;
    }
    awg_rules::kernel::restore(&state).await;
    if !go_handoff {
        trace::awg::restore(&state).await;
    }
    dnsserver::autostart(&state).await;
    awg_rules::kernel::start_go_handoff(&state).await;
    if go_handoff {
        // Publish the candidate's packet and DNS rules before restoring trace
        // and reconciling the client owners the old panel kept alive.
        trace::awg::restore(&state).await;
        awg_profiles::restore(&state).await;
    }
    if let Err(e) = socks5::auto_start(&state).await {
        state.logs.append("socks5", "warn", &e.1);
    }
    if let Err(e) = tgws::auto_start(&state).await {
        state.logs.append("tgws", "warn", &e.1);
    }
    let mut requested = state.restart.subscribe();
    if runs::matrix_available() {
        if let Err(e) = runs::recover_matrix().await {
            state.logs.append("automation", "warn", &e.to_string());
        }
    }
    let (stop_watchdog, watchdog) = engine::automation::start(&state);
    let history_writer = awg_rules::start_history_writer(&state);
    let result = axum::serve(listener, http::router(state.clone()))
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = shutdown() => (),
                _ = requested.wait_for(|wanted| *wanted) => (),
            }
        })
        .await;
    let _ = stop_watchdog.send(());
    let _ = watchdog.await;
    state.blockcheck.shutdown().await;
    engine::automation::shutdown(&state).await;
    state.runs.shutdown().await;
    state.trace.shutdown().await;
    awg_rules::kernel::shutdown(&state).await;
    awg_profiles::shutdown(&state).await;
    state.dnsserver.shutdown().await;
    history_writer.abort();
    let _ = history_writer.await;
    awg_rules::flush_history(&state).await;
    state.socks5.shutdown().await;
    state.tgws.shutdown().await;
    result?;
    if let Some(next) = state.update.take_binary() {
        if let Err(e) = next.activate() {
            state.logs.append(
                "update",
                "error",
                &format!("не удалось запустить обновление: {e}"),
            );
        }
    }
    if *state.restart.borrow() {
        Ok(Some(state.ports.socket()?))
    } else {
        Ok(None)
    }
}
fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    if cmd == "resolve-panel-port" {
        let value = args.next().ok_or_else(|| invalid("укажите порт панели"))?;
        if args.next().is_some() {
            return Err(invalid("ожидался один порт панели"));
        }
        if value == "--supported" {
            println!("panel-port-v1");
        } else {
            let fallback = value.parse().map_err(|_| invalid("неверный порт панели"))?;
            let (config, _) = Config::load(VERSION, REPO);
            println!(
                "{}",
                saved_panel_port(Path::new(&config.data_dir))?.unwrap_or(fallback)
            );
        }
        return Ok(());
    }
    if cmd == "port-forward-wan" {
        return portforward::print_wan(args);
    }
    #[cfg(target_os = "linux")]
    if cmd == "launch-awg-client" {
        let engine = args
            .next()
            .ok_or_else(|| invalid("ожидался путь к движку AWG"))?;
        let iface = args
            .next()
            .ok_or_else(|| invalid("ожидался интерфейс AWG"))?;
        if args.next().is_some() {
            return Err(invalid("лишний аргумент запуска AWG"));
        }
        return nfqws2_awg_profile::run_launcher(Path::new(&engine), &iface);
    }
    #[cfg(all(feature = "embedded-runs", not(feature = "compact")))]
    if cmd == "recover-matrix" {
        return nfqws2_runs::matrix::recover();
    }
    #[cfg(all(feature = "embedded-runs", not(feature = "compact")))]
    if matches!(cmd.as_str(), "measure-current" | "measure-matrix") {
        let rest: Vec<_> = args.collect();
        let [dir, id, live] = rest.as_slice() else {
            return Err(invalid("measure-current DATA ID LIVE_DIR"));
        };
        return if cmd == "measure-matrix" {
            nfqws2_runs::matrix::run(Path::new(dir), id, Path::new(live))
        } else {
            nfqws2_runs::measure::run(Path::new(dir), id, Path::new(live))
        };
    }
    if matches!(cmd.as_str(), "version" | "-v" | "--version") {
        println!("{VERSION}");
        return Ok(());
    }
    if !matches!(
        cmd.as_str(),
        "serve"
            | "config"
            | "openwrt-dns-restore"
            | "checkupdate"
            | "update"
            | "selftest"
            | "prepare-go-routing"
            | "finish-go-routing"
            | "finish-go-services"
            | "release-go-routing"
            | "release-native-clients"
    ) {
        return Err(invalid("usage: nfqws2-strategy version | config | checkupdate | update | selftest [-s INDEX | --current] HOST [HOST ...] | openwrt-dns-restore | serve [-l addr] [--ignore-saved-port] [-d] [-pid file] [-log file]"));
    }
    let (mut config, warning) = Config::load(VERSION, REPO);
    if let Some(warning) = warning {
        eprintln!("warn: {warning}");
    }
    if matches!(
        cmd.as_str(),
        "checkupdate"
            | "update"
            | "selftest"
            | "prepare-go-routing"
            | "finish-go-routing"
            | "finish-go-services"
            | "release-go-routing"
            | "release-native-clients"
    ) {
        return cli::run(&cmd, &config, args.collect());
    }
    if cmd == "config" {
        serde_json::to_writer_pretty(io::stdout().lock(), &config)?;
        println!();
        return Ok(());
    }
    if cmd == "openwrt-dns-restore" {
        return nfqws2_openwrt_dns::restore_for_uninstall(&config.data_dir);
    }
    let opts = Serve::parse(args)?;
    if let Some(addr) = &opts.listen {
        config.listen_addr.clone_from(addr);
    }
    if !opts.ignore_saved {
        config.listen_addr = saved_addr(Path::new(&config.data_dir), &config.listen_addr)?;
    }
    if opts.daemon && detach(&opts)? {
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()?;
    let mut previous = None;
    while let Some(socket) =
        runtime.block_on(serve(config, opts.log.as_deref(), previous.take()))?
    {
        let addr = socket.local_addr()?;
        previous = Some(socket);
        let (reloaded, warning) = Config::load(VERSION, REPO);
        if let Some(warning) = warning {
            eprintln!("warn: {warning}");
        }
        config = reloaded;
        config.listen_addr = if opts.ignore_saved {
            addr.to_string()
        } else {
            saved_addr(Path::new(&config.data_dir), &addr.to_string())?
        };
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(match e.kind() {
                io::ErrorKind::InvalidInput => 2,
                io::ErrorKind::Interrupted => 130,
                _ => 1,
            })
        }
    }
}
