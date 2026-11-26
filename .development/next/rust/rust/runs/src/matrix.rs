//! Candidate measurements in isolated NFQUEUE workers. The normal HTTPS check
//! intentionally has no strategy attribution; this runner requires evidence
//! that every measured target passed through the candidate's private queue.
mod baseline;
mod dns;
mod redirect;
mod sandbox;
pub mod selftest;
#[cfg(test)]
mod tests;

use crate::{filename, invalid, measure, save_completed};
pub use nfqws2_config::validate_https_strategy;
use nfqws2_store::Store;
use sandbox::{Config, Sandbox};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Write},
    net::Ipv4Addr,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

const MAX_STRATEGIES: usize = 1024;
const READ_CAP: u64 = 131_072;
const CANCELLED_PROBE: &str = "context canceled";

#[derive(Clone, Deserialize)]
struct Strategy {
    #[serde(default)]
    id: String,
    #[serde(default)]
    strategy_id: String,
    name: String,
    args: String,
    #[serde(default)]
    l7: String,
}
impl Strategy {
    fn id(&self) -> &str {
        if self.strategy_id.is_empty() {
            &self.id
        } else {
            &self.strategy_id
        }
    }
}
#[derive(Deserialize)]
struct Request {
    targets: Vec<String>,
    #[serde(skip)]
    authorities: BTreeMap<String, String>,
    threads: usize,
    strategies: Vec<Strategy>,
    config: Config,
    #[serde(default)]
    auto: bool,
    #[serde(default)]
    list_id: String,
    #[serde(default = "default_name")]
    list_name: String,
    #[serde(default)]
    legacy: bool,
    #[serde(default = "system_dns")]
    dns: Vec<Option<dns::Server>>,
}
impl Request {
    fn jobs(&self) -> usize {
        self.strategies.len().saturating_mul(self.dns.len())
    }

    fn target<'a>(&'a self, label: &'a str) -> ProbeTarget<'a> {
        ProbeTarget {
            label,
            authority: self.authorities.get(label).map_or(label, String::as_str),
        }
    }
}

struct ProbeTarget<'a> {
    label: &'a str,
    authority: &'a str,
}
fn system_dns() -> Vec<Option<dns::Server>> {
    vec![None]
}
fn default_name() -> String {
    "Автоматический подбор".into()
}

fn create(id: &str, req: &mut Request) -> io::Result<Value> {
    filename("runs", id)?;
    if !(1..=8).contains(&req.threads) {
        return Err(invalid("Выберите от 1 до 8 потоков."));
    }
    if req.jobs() == 0 || req.jobs() > MAX_STRATEGIES {
        return Err(invalid("Выберите от 1 до 1024 HTTPS-стратегий."));
    }
    if !req.list_id.is_empty() {
        filename("lists", &req.list_id)?;
    }
    let targets = std::mem::take(&mut req.targets);
    req.authorities.clear();
    req.targets = if req.legacy {
        measure::legacy_matrix_targets(targets)?
            .into_iter()
            .map(|target| {
                if target.label != target.authority {
                    req.authorities
                        .insert(target.label.clone(), target.authority);
                }
                target.label
            })
            .collect()
    } else {
        measure::normalize_targets(targets)?
    };
    let mut seen = BTreeSet::new();
    for strategy in &req.strategies {
        if strategy.id().is_empty()
            || strategy.id().len() > if req.legacy { 512 } else { 256 }
            || (!strategy.id.is_empty()
                && !strategy.strategy_id.is_empty()
                && strategy.id != strategy.strategy_id)
            || (!req.legacy && !seen.insert(strategy.id()))
            || strategy.name.len() > 1024
        {
            return Err(invalid("некорректный идентификатор стратегии"));
        }
        validate_https_strategy(&strategy.args)?;
    }
    Ok(
        json!({"id":id,"list_id":req.list_id,"list_name":req.list_name,"mode":"strategy_matrix",
        "auto":req.auto,"threads":req.threads,"status":"running","total":req.jobs(),
        "done":0,"started_at":measure::now(),"targets":req.targets,"baseline":[],"results":[]}),
    )
}

struct Control {
    cancel: AtomicBool,
    threads: AtomicUsize,
    legacy: bool,
    parent_closed: AtomicBool,
}
impl Control {
    fn new(threads: usize, legacy: bool) -> Self {
        Self {
            cancel: false.into(),
            threads: threads.into(),
            legacy,
            parent_closed: false.into(),
        }
    }

    fn keeps_cancelled_rows(&self) -> bool {
        self.legacy && self.parent_closed.load(Ordering::Acquire)
    }
}
fn commands(mut input: impl io::BufRead, control: Arc<Control>) {
    loop {
        let line = match measure::read_line(&mut input, 64) {
            Ok(Some(line)) => line,
            Ok(None) => {
                // Ordinary panel cancellation closes stdin. A broken command
                // or a worker's internal abort cannot qualify partial rows.
                if !control.cancel.load(Ordering::Acquire) {
                    control.parent_closed.store(true, Ordering::Release);
                }
                break;
            }
            Err(_) => break,
        };
        let Some(n) = std::str::from_utf8(&line)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|n| (1..=8).contains(n))
        else {
            break;
        };
        control.threads.store(n, Ordering::Release);
    }
    control.cancel.store(true, Ordering::Release);
}

fn lock() -> io::Result<File> {
    let path = std::env::temp_dir().join("nfqws2-strategy-matrix.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("некорректный файл блокировки подбора"));
    }
    file.try_lock()
        .map_err(|_| invalid("Другой подбор стратегий уже выполняется."))?;
    Ok(file)
}

/// Repair the exact rules left by a dead helper. A live helper holds this same
/// lock, so startup recovery cannot dismantle another active measurement.
pub fn recover() -> io::Result<()> {
    let _lock = lock()?;
    sandbox::recover()
}

fn result_row(strategy: &Strategy, server: Option<&dns::Server>, targets: usize) -> Value {
    let mut row = json!({"strategy_id":strategy.id(),"name":strategy.name,"args":strategy.args,"l7":strategy.l7,
        "dns":server.map_or("Системный", |dns| &dns.name),"targets_total":targets,"targets_ok":0,"success":false,"per_target":[],
        "avg_ttfb_ms":0,"avg_speed_bps":0,"coefficient":0});
    if let Some(server) = server {
        row["dns_id"] = server.id.as_str().into();
    }
    row
}

fn check_queue_traffic(sample: &mut Value, before: u32, after: io::Result<u32>) {
    match after {
        Ok(after) if before != after => (),
        other => {
            sample["ok"] = false.into();
            let detail = match other {
                Err(e) => format!("Проверка NFQUEUE после запроса: {e}"),
                Ok(_) => {
                    "Тестовая NFQUEUE не получила пакетов; проверьте VPN-маршрут и WAN-интерфейсы."
                        .into()
                }
            };
            sample["err"] = if sample["err"] == CANCELLED_PROBE {
                format!("{CANCELLED_PROBE}. {detail}")
            } else {
                detail
            }
            .into();
        }
    }
}

fn test_strategy(
    sandbox: &mut Sandbox,
    strategy: &Strategy,
    hosts: &[ProbeTarget<'_>],
    curl: &Path,
    control: &Control,
    resolver: &dns::Resolver,
    server: Option<&dns::Server>,
) -> io::Result<Option<Value>> {
    if control.cancel.load(Ordering::Acquire) {
        return Ok(None);
    }
    let mut row = result_row(strategy, server, hosts.len());
    if let Err(e) = sandbox.start(&strategy.args, &control.cancel) {
        sandbox.stop();
        if control.cancel.load(Ordering::Acquire) {
            return Ok(None);
        }
        row["error"] = e.to_string().into();
        return Ok(Some(row));
    }
    let local_ips = if control.legacy {
        sandbox.local_ipv4_addresses().to_vec()
    } else {
        Vec::new()
    };
    let measured = (|| {
        sandbox.check()?;
        capture_targets(&mut row, hosts, control, |target| {
            let host = target.label;
            let authority = target.authority;
            let started = Instant::now();
            let address = match resolver.resolve(server, authority, control) {
                Ok(address) => address,
                Err(error) => {
                    return Ok(Some(json!({"host":host,"ok":false,"err":error})));
                }
            };
            if control.legacy {
                let uri = format!("https://{authority}/")
                    .parse()
                    .map_err(|_| invalid("некорректный HTTPS-адрес проверки"))?;
                let (first, last) = sandbox.port_range();
                return redirect::follow_public(
                    host,
                    uri,
                    redirect::Chain {
                        lease: started..started + Duration::from_secs(20),
                        port_count: usize::from(last - first) + 1,
                        baseline: false,
                        address,
                        local_ips: &local_ips,
                    },
                    control,
                    |next, deadline| resolver.redirect_address(server, next, deadline, control),
                    |hop| {
                        if hop.redirected {
                            sandbox.check()?;
                        }
                        let before = sandbox.packets()?;
                        let port = sandbox.next_probe_port();
                        let output = probe_hop(
                            Command::new(curl),
                            host,
                            (port, port),
                            control,
                            ProbeLane::Candidate(None),
                            Some(hop),
                        )?;
                        Ok(output.map(|output| {
                            redirect::attest(output, host, before, sandbox.packets())
                        }))
                    },
                );
            }
            let before = sandbox.packets()?;
            let Some(mut sample) = probe(
                Command::new(curl),
                authority,
                sandbox.port_range(),
                control,
                ProbeLane::Candidate(address),
            )?
            else {
                return Ok(None);
            };
            check_queue_traffic(&mut sample, before, sandbox.packets());
            if host != authority {
                sample["host"] = host.into();
            }
            Ok(Some(sample))
        })?;
        sandbox.check()
    })();
    sandbox.stop();
    complete_candidate(row, measured, control)
}

fn capture_targets<T>(
    row: &mut Value,
    hosts: &[T],
    control: &Control,
    mut capture: impl FnMut(&T) -> io::Result<Option<Value>>,
) -> io::Result<()> {
    let samples = row["per_target"].as_array_mut().unwrap();
    for host in hosts {
        if control.cancel.load(Ordering::Acquire) {
            break;
        }
        let Some(sample) = capture(host)? else { break };
        samples.push(sample);
    }
    Ok(())
}

fn complete_candidate(
    mut row: Value,
    measured: io::Result<()>,
    control: &Control,
) -> io::Result<Option<Value>> {
    if control.cancel.load(Ordering::Acquire)
        && (!control.keeps_cancelled_rows() || measured.is_err())
    {
        return Ok(None);
    }
    if let Err(e) = measured {
        row["error"] = format!("Изоляция прогона: {e}").into();
    }
    // Live rows have the same aggregates as their persisted counterparts.
    let mut report = json!({"results":[row]});
    crate::summarize(&mut report)?;
    Ok(report["results"].as_array_mut().unwrap().pop())
}

fn measure_matrix(
    req: &Request,
    report: &mut Value,
    live: &Store,
    curl: &Path,
    control: &Control,
) -> io::Result<()> {
    let hosts = if req.auto {
        baseline::run(req, report, live, curl, control)?
    } else {
        req.targets.clone()
    };
    if hosts.is_empty() || control.cancel.load(Ordering::Acquire) {
        report["total"] = 0.into();
        return Ok(());
    }
    let hosts: Vec<_> = hosts.iter().map(|label| req.target(label)).collect();
    let next = AtomicUsize::new(0);
    let reserved = req
        .dns
        .iter()
        .any(Option::is_some)
        .then(|| sandbox::reserved_ports(&req.config, baseline::SLOT))
        .transpose()?;
    let resolver = dns::Resolver::new(reserved);
    let (send, recv) = mpsc::sync_channel(8);
    thread::scope(|scope| {
        let mut workers = 0;
        let mut completed = 0;
        let mut first_error = None;
        loop {
            let limit = control.threads.load(Ordering::Acquire);
            // Each worker keeps one private source-port range and queue until
            // all its jobs finish. Lowering the limit parks excess workers.
            while workers < limit && workers < req.jobs() && !control.cancel.load(Ordering::Acquire)
            {
                let worker = workers;
                let send = send.clone();
                let hosts = &hosts;
                let next = &next;
                let resolver = &resolver;
                let spawned =
                    thread::Builder::new()
                        .stack_size(256 << 10)
                        .spawn_scoped(scope, move || {
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    let mut sandbox = Sandbox::new(&req.config, worker)?;
                                    let measured = (|| {
                                        loop {
                                            if control.cancel.load(Ordering::Acquire) {
                                                break;
                                            }
                                            if worker >= control.threads.load(Ordering::Acquire) {
                                                if next.load(Ordering::Acquire) >= req.jobs() {
                                                    break;
                                                }
                                                thread::sleep(Duration::from_millis(25));
                                                continue;
                                            }
                                            let index = next.fetch_add(1, Ordering::AcqRel);
                                            let Some(strategy) =
                                                req.strategies.get(index / req.dns.len())
                                            else {
                                                break;
                                            };
                                            if let Some(row) = test_strategy(
                                                &mut sandbox,
                                                strategy,
                                                hosts,
                                                curl,
                                                control,
                                                resolver,
                                                req.dns[index % req.dns.len()].as_ref(),
                                            )? {
                                                if send.send(Ok(Some(row))).is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                        Ok(())
                                    })();
                                    let cleanup = sandbox.cleanup();
                                    cleanup?;
                                    measured
                                }))
                                .unwrap_or_else(|_| {
                                    Err(io::Error::other("strategy worker stopped"))
                                });
                            let _ = send.send(result.map(|()| None));
                        });
                if let Err(e) = spawned {
                    first_error.get_or_insert(e);
                    control.cancel.store(true, Ordering::Release);
                    break;
                }
                workers += 1;
            }
            if completed == workers {
                break;
            }
            match recv.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(Some(row))) => {
                    let rows = report["results"].as_array_mut().unwrap();
                    rows.push(row);
                    report["done"] = rows.len().into();
                    if let Err(e) = live.transaction(|tx| tx.save("active.json", report)) {
                        first_error.get_or_insert(e);
                        control.cancel.store(true, Ordering::Release);
                    }
                }
                Ok(Ok(None)) => completed += 1,
                Ok(Err(e)) => {
                    first_error.get_or_insert(e);
                    control.cancel.store(true, Ordering::Release);
                    completed += 1;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("worker stopped"))
                }
            }
            report["threads"] = limit.into();
        }
        if let Some(e) = first_error {
            Err(e)
        } else {
            Ok(())
        }
    })
}

enum ProbeLane {
    Baseline,
    Candidate(Option<Ipv4Addr>),
}

/// Download enough body to reject the usual 16 KiB cut-off. curl is forced to
/// IPv4, HTTPS, one fixed destination port and the worker's local port range.
/// No redirects or proxy environment can move a successful request outside it.
fn probe(
    cmd: Command,
    host: &str,
    ports: (u16, u16),
    control: &Control,
    lane: ProbeLane,
) -> io::Result<Option<Value>> {
    probe_hop(cmd, host, ports, control, lane, None).map(|result| {
        result.map(|result| match result {
            redirect::Output::Terminal(sample) => sample,
            redirect::Output::Redirect(_) => {
                unreachable!("single request can never follow redirects")
            }
        })
    })
}

fn probe_hop(
    mut cmd: Command,
    host: &str,
    ports: (u16, u16),
    control: &Control,
    lane: ProbeLane,
    hop: Option<redirect::Hop<'_>>,
) -> io::Result<Option<redirect::Output>> {
    if control.cancel.load(Ordering::Acquire) {
        return Ok(None);
    }
    let baseline = matches!(lane, ProbeLane::Baseline);
    let (url, max_time, connect_timeout) = if let Some(hop) = hop {
        let left = hop.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(Some(redirect::Output::Terminal(redirect::timed_out(
                host, baseline,
            ))));
        }
        let seconds = left.max(Duration::from_millis(1)).as_secs_f64();
        (
            hop.uri.to_string(),
            format!("{seconds:.3}"),
            format!("{:.3}", seconds.min(6.0)),
        )
    } else {
        (format!("https://{host}/"), "20".to_owned(), "6".to_owned())
    };
    let body = tempfile::NamedTempFile::new()?;
    let headers = tempfile::NamedTempFile::new()?;
    if baseline {
        cmd.env("LC_ALL", "C").stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = unsafe { libc::getpid() };
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Ok(())
            });
        }
    }
    struct OwnedChild(std::process::Child);
    impl std::ops::Deref for OwnedChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl std::ops::DerefMut for OwnedChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // curl's first flag must still be --disable, before any baseline options.
    cmd.args([
        "--disable",
        "--ipv4",
        "--silent",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--max-time",
        &max_time,
        "--connect-timeout",
        &connect_timeout,
        "--range",
        "0-131071",
        "--user-agent",
        "Mozilla/5.0 (nfqws2-strategy)",
        "--local-port",
        &format!("{}-{}", ports.0, ports.1),
        "--output",
    ]);
    cmd
        .arg(body.path()).arg("--dump-header").arg(headers.path())
        .args(["--write-out", "%{http_code} %{time_starttransfer} %{time_total} %{size_download} %{speed_download} %{remote_ip}"]);
    if baseline {
        cmd.args(["--verbose", "--show-error"]);
    }
    if hop.is_some() {
        // The validated URL is the sole request even when its path contains
        // curl glob characters. The redirect resolver already handled dots.
        cmd.args(["--globoff", "--path-as-is"]);
    }
    let pinned = hop.and_then(|hop| hop.address).or(match lane {
        ProbeLane::Candidate(address) => address,
        ProbeLane::Baseline => None,
    });
    if let Some(address) = pinned {
        let target = hop.and_then(|hop| hop.uri.host()).unwrap_or(host);
        cmd.arg("--resolve").arg(format!("{target}:443:{address}"));
    }
    let child = OwnedChild(
        cmd.args(["--", &url])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    thread::scope(move |scope| {
        // Owning the child inside the scope kills it before joining its reader on
        // cancellation or file errors. Only typed connect failures leave the pipe.
        let mut child = child;
        let diagnostic = child
            .stderr
            .take()
            .map(|pipe| {
                thread::Builder::new()
                    .stack_size(128 << 10)
                    .spawn_scoped(scope, move || baseline::connection_failure(pipe))
            })
            .transpose()?;
        let started = Instant::now();
        let deadline = hop.map_or(started + Duration::from_secs(21), |hop| hop.deadline);
        let mut headers_final = hop.is_none();
        let mut observed_header_size = 0;
        let mut first_byte = None;
        let mut capped = false;
        let terminal = loop {
            let cancelled = control.cancel.load(Ordering::Acquire);
            if cancelled || Instant::now() >= deadline {
                let preserve = !baseline && cancelled && control.keeps_cancelled_rows();
                if preserve {
                    // Exit may have raced the cancel signal. A reaped child
                    // can still contribute its complete observed result.
                    if let Some(status) = child.try_wait()? {
                        break Some(status);
                    }
                }
                let _ = child.kill();
                let reaped = child.wait();
                if preserve {
                    // It can still finish between try_wait and kill.
                    let status = reaped?;
                    if status.success() {
                        break Some(status);
                    }
                }
                if control.cancel.load(Ordering::Acquire) {
                    return Ok(
                        preserve.then(|| redirect::Output::Terminal(interrupted_probe(host)))
                    );
                }
                break None;
            }
            if !headers_final {
                let size = headers.as_file().metadata()?.len();
                if size != observed_header_size {
                    observed_header_size = size;
                    let mut raw = Vec::new();
                    File::open(headers.path())?
                        .take(redirect::HEADER_LIMIT)
                        .read_to_end(&mut raw)?;
                    match redirect::header(&String::from_utf8_lossy(&raw))? {
                        redirect::Header::Pending if size < redirect::HEADER_LIMIT => (),
                        redirect::Header::Pending => {
                            return Err(invalid("слишком длинные HTTP-заголовки"))
                        }
                        redirect::Header::Terminal => headers_final = true,
                        redirect::Header::Redirect(location) => {
                            // Do not spend the original lease streaming an
                            // intermediate response body. No next child can
                            // start before this one has actually gone away.
                            let _ = child.kill();
                            child.wait()?;
                            return Ok(Some(redirect::Output::Redirect(location)));
                        }
                    }
                }
            }
            let size = body.as_file().metadata()?.len();
            if size > 0 && first_byte.is_none() {
                first_byte = Some(started.elapsed());
            }
            if size >= READ_CAP {
                capped = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => thread::sleep(Duration::from_millis(25)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            }
        };
        let elapsed = started.elapsed();
        let mut metrics = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(512)
            .read_to_string(&mut metrics)?;
        let mut raw_headers = String::new();
        File::open(headers.path())?
            .take(64 << 10)
            .read_to_string(&mut raw_headers)?;
        if !headers_final {
            match redirect::header(&raw_headers)? {
                redirect::Header::Redirect(location) => {
                    let output = if Instant::now() < deadline {
                        redirect::Output::Redirect(location)
                    } else {
                        redirect::Output::Terminal(redirect::timed_out(host, baseline))
                    };
                    return Ok(Some(output));
                }
                redirect::Header::Terminal => headers_final = true,
                redirect::Header::Pending => (),
            }
        }
        let size = body.as_file().metadata()?.len().min(READ_CAP);
        let exit = terminal.and_then(|s| s.code()).unwrap_or(-1);
        let complete = terminal.is_some_and(|s| s.success());
        let mut sample = finish_probe(
            host,
            &metrics,
            &raw_headers,
            size,
            elapsed,
            first_byte,
            capped,
            exit,
            complete,
        );
        if let Some(diagnostic) = diagnostic {
            let failure = diagnostic
                .join()
                .map_err(|_| io::Error::other("curl diagnostic worker stopped"))?;
            if !headers_final {
                // An incomplete status line or header alone isn't a final
                // response for the redirecting baseline.
                sample["code"] = 0.into();
                sample["size"] = 0.into();
                sample["ok"] = false.into();
                sample["truncated"] = false.into();
            }
            baseline::classify(
                &mut sample,
                exit,
                terminal.is_none() && !capped,
                complete,
                failure,
            );
        }
        Ok(Some(redirect::Output::Terminal(sample)))
    })
}

fn interrupted_probe(host: &str) -> Value {
    json!({"host":host,"ok":false,"code":0,"size":0,"ttfb_ms":0,"total_ms":0,
        "speed_bps":0,"remote_ip":"","truncated":false,"err":CANCELLED_PROBE})
}

#[allow(clippy::too_many_arguments)]
fn finish_probe(
    host: &str,
    metrics: &str,
    raw_headers: &str,
    size: u64,
    elapsed: Duration,
    first_byte: Option<Duration>,
    capped: bool,
    exit: i32,
    success: bool,
) -> Value {
    let (code, ttfb, total, speed, remote) = parse_metrics(metrics).unwrap_or_else(|| {
        let code = raw_headers
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                if !parts.next()?.starts_with("HTTP/") {
                    return None;
                }
                parts
                    .next()?
                    .parse::<u16>()
                    .ok()
                    .filter(|v| (200..600).contains(v))
            })
            .next_back()
            .unwrap_or(0);
        let ms = elapsed.as_millis().max(1) as u64;
        (
            code,
            first_byte.unwrap_or(elapsed).as_millis() as u64,
            ms,
            size.saturating_mul(1000) / ms,
            String::new(),
        )
    });
    let complete = capped && size >= READ_CAP || success;
    let truncated = !complete && size > 0 && size <= 17_408;
    let ok = (200..400).contains(&code) && size > 16_384 && complete && !truncated;
    let mut sample = json!({"host":host,"ok":ok,"code":code,"size":size,"ttfb_ms":ttfb,"total_ms":total,
        "speed_bps":speed,"remote_ip":remote,"truncated":truncated});
    if !ok {
        sample["err"] =
            format!("HTTPS-проверка: curl {exit}, HTTP {code}, получено {size} байт.").into();
    }
    if exit == 45 {
        sample["local_error"] = true.into();
    }
    sample
}

fn parse_metrics(raw: &str) -> Option<(u16, u64, u64, u64, String)> {
    let parts: Vec<_> = raw.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let code = parts[0].parse::<u16>().ok()?;
    if code > 599 {
        return None;
    }
    let number = |value: &str| {
        value
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite() && *n >= 0.0)
    };
    let ttfb = number(parts[1])?;
    let total = number(parts[2])?;
    let size = number(parts[3])?;
    let speed = number(parts[4])?;
    if ttfb > 21.0 || total > 21.0 || size > u64::MAX as f64 || speed > u64::MAX as f64 {
        return None;
    }
    let remote = parts[5].parse::<std::net::Ipv4Addr>().ok()?.to_string();
    Some((
        code,
        (ttfb * 1000.0) as u64,
        (total * 1000.0) as u64,
        speed as u64,
        remote,
    ))
}

pub fn run(dir: &Path, id: &str, live_dir: &Path) -> io::Result<()> {
    let setup = (|| {
        let db = Store::open(dir)?;
        let live = Store::open(live_dir)?;
        let mut input = BufReader::new(io::stdin());
        let raw =
            measure::read_line(&mut input, 1 << 20)?.ok_or_else(|| invalid("missing request"))?;
        let mut request: Request = serde_json::from_slice(&raw)?;
        let mut report = create(id, &mut request)?;
        let executable = measure::curl()?;
        let _lock = lock()?;
        sandbox::recover()?;
        let file = filename("runs", id)?;
        db.transaction(|tx| {
            match db.read_limited::<serde::de::IgnoredAny>(&file, 1 << 20) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Ok(_) => return Err(invalid("run ID is in use")),
                Err(e) => return Err(e),
            }
            tx.save(&file, &report)
        })?;
        live.transaction(|tx| tx.save("active.json", &report))?;
        let control = Arc::new(Control::new(request.threads, request.legacy));
        let listener = control.clone();
        thread::Builder::new()
            .stack_size(128 << 10)
            .spawn(move || commands(input, listener))?;
        writeln!(io::stdout().lock(), "{}", json!({"started":report}))?;
        let result = measure_matrix(&request, &mut report, &live, &executable, &control);
        report["status"] = match result {
            Err(e) => {
                report["error"] = e.to_string().into();
                "error"
            }
            Ok(()) if control.cancel.load(Ordering::Acquire) => "cancelled",
            Ok(()) => "done",
        }
        .into();
        report["finished_at"] = measure::now().into();
        save_completed(&db, &mut report)?;
        live.transaction(|tx| tx.save("active.json", &report))
    })();
    if let Err(e) = &setup {
        let _ = writeln!(io::stdout().lock(), "{}", json!({"error":e.to_string()}));
    }
    setup
}
