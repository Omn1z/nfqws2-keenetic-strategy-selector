//! Explicit HTTPS HEAD measurements through the router's current configuration.
use crate::{filename, invalid, save_completed};
use nfqws2_store::Store;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv6Addr},
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_TARGETS: usize = 64;
const MAX_THREADS: usize = 8;
#[cfg(test)]
mod tests;
pub(super) fn curl() -> io::Result<std::path::PathBuf> {
    let name = format!("curl{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(&name))
        .find(|path| {
            path.metadata().is_ok_and(|m| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if m.permissions().mode() & 0o111 == 0 {
                        return false;
                    }
                }
                m.is_file()
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Для HTTPS-прогонов требуется curl.",
            )
        })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: String,
    #[serde(default)]
    list_id: String,
    #[serde(default)]
    targets: Vec<String>,
    threads: usize,
}
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(super) fn read_line(reader: &mut impl BufRead, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    if reader.take(limit + 1).read_until(b'\n', &mut buf)? == 0 {
        return Ok(None);
    }
    if buf.len() as u64 > limit || buf.last() != Some(&b'\n') {
        return Err(invalid("invalid or oversized run command"));
    }
    Ok(Some(buf))
}
fn create(db: &Store, id: &str, req: Request) -> io::Result<Value> {
    filename("runs", id)?;
    if req.mode != "current_https" || !(1..=MAX_THREADS).contains(&req.threads) {
        return Err(invalid("Выберите режим current_https и от 1 до 8 потоков."));
    }
    let (targets, name) = if req.list_id.is_empty() {
        (req.targets, "Выбранные домены".to_owned())
    } else {
        if !req.targets.is_empty() {
            return Err(invalid("Укажите список или домены одним способом."));
        }
        #[derive(Deserialize)]
        struct List {
            name: String,
            #[serde(default)]
            domains: Vec<String>,
        }
        let list: List = db.read_limited(&filename("lists", &req.list_id)?, 1 << 20)?;
        (list.domains, list.name)
    };
    let domains = normalize_targets(targets)?;
    Ok(
        json!({"id":id,"list_id":req.list_id,"list_name":name,"mode":"current_https","threads":req.threads,
        "auto":false,"status":"running","total":domains.len(),"done":0,"started_at":now(),
        "targets":domains,"checks":[],"results":[]}),
    )
}
fn valid_hostname(name: &str, allow_single_label: bool) -> bool {
    name.len() <= 253
        && (allow_single_label || name.contains('.'))
        && name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().any(|c| c.is_ascii_alphabetic()))
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

fn invalid_target() -> io::Error {
    invalid("Укажите доменные имена без URL, портов, масок и IP.")
}

pub(super) fn normalize_targets(targets: Vec<String>) -> io::Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut domains = Vec::new();
    for value in targets {
        let input = value.trim();
        let name = input
            .strip_suffix('.')
            .unwrap_or(input)
            .to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if !valid_hostname(&name, false) {
            return Err(invalid_target());
        }
        if seen.insert(name.clone()) {
            domains.push(name);
        }
        if domains.len() > MAX_TARGETS {
            return Err(invalid("За один прогон поддерживается до 64 доменов."));
        }
    }
    if domains.is_empty() {
        return Err(invalid("Список не содержит доменов."));
    }
    Ok(domains)
}

pub(super) fn legacy_matrix_targets(targets: Vec<String>) -> io::Result<Vec<SelftestTarget>> {
    let mut targets = probe_targets(targets, true)?;
    if targets.len() > MAX_TARGETS {
        return Err(invalid("За один прогон поддерживается до 64 целей."));
    }
    for target in &mut targets {
        target.label = if target.label.trim().is_ascii() {
            target.authority.clone()
        } else {
            target.label.trim().to_owned()
        };
    }
    Ok(targets)
}

pub(super) struct SelftestTarget {
    pub label: String,
    pub authority: String,
}

pub(super) fn selftest_targets(targets: Vec<String>) -> io::Result<Vec<SelftestTarget>> {
    probe_targets(targets, false)
}

fn idn_authority(input: &str) -> io::Result<String> {
    let dns_name = input.replace(['\u{3002}', '\u{ff0e}', '\u{ff61}'], ".");
    if dns_name.starts_with('.')
        || dns_name.contains(['*', '/', '\\', ':', '@', '?', '#', '[', ']'])
        || dns_name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid_target());
    }
    let mut authority =
        nfqws2_config::service_profiles::domain(&dns_name).map_err(|_| invalid_target())?;
    if !valid_hostname(&authority, false) {
        return Err(invalid_target());
    }
    if dns_name.ends_with('.') {
        authority.push('.');
    }
    Ok(authority)
}

fn probe_targets(targets: Vec<String>, allow_idn: bool) -> io::Result<Vec<SelftestTarget>> {
    let mut hosts = Vec::with_capacity(targets.len());
    for label in targets {
        let input = label.trim();
        let name = input.strip_suffix('.').unwrap_or(input);
        if name.is_empty() {
            continue;
        }
        let literal = name.parse::<IpAddr>().ok().or_else(|| {
            name.strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<Ipv6Addr>()
                .ok()
                .map(IpAddr::V6)
        });
        let authority = match literal {
            Some(IpAddr::V4(ip)) => ip.to_string(),
            Some(IpAddr::V6(ip)) => format!("[{ip}]"),
            None if valid_hostname(name, true) => input.to_owned(),
            None if allow_idn && !input.is_ascii() => idn_authority(input)?,
            None => return Err(invalid_target()),
        };
        hosts.push(SelftestTarget { label, authority });
    }
    if hosts.is_empty() {
        return Err(invalid("Список не содержит доменов."));
    }
    Ok(hosts)
}
struct Control {
    cancel: AtomicBool,
    threads: AtomicUsize,
}
/// One-shot diagnostics through the current network configuration. No run
/// history, router locks, external firewall rules or temporary state are used.
pub fn selftest(targets: Vec<String>) -> io::Result<Value> {
    let hosts = selftest_targets(targets)?;
    let executable = curl()?;
    let control = Control {
        cancel: AtomicBool::new(false),
        threads: AtomicUsize::new(1),
    };
    let mut results = Vec::with_capacity(hosts.len());
    for SelftestTarget { label, authority } in hosts {
        let mut cmd = Command::new(&executable);
        cmd.arg("--disable");
        let mut result =
            measurement(cmd, &authority, &control)?.ok_or(io::ErrorKind::Interrupted)?;
        result["host"] = label.into();
        results.push(result);
    }
    Ok(json!({"mode":"current_https","results":results}))
}
fn commands(mut input: impl BufRead, control: Arc<Control>) {
    while let Ok(Some(line)) = read_line(&mut input, 64) {
        let Some(n) = std::str::from_utf8(&line)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|n| (1..=MAX_THREADS).contains(n))
        else {
            break;
        };
        control.threads.store(n, Ordering::Release);
    }
    control.cancel.store(true, Ordering::Release);
}
fn measurement(mut cmd: Command, host: &str, control: &Control) -> io::Result<Option<Value>> {
    if control.cancel.load(Ordering::Acquire) {
        return Ok(None);
    }
    let mut child = cmd
        .args([
            "--head",
            "--silent",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--max-time",
            "6",
            "--connect-timeout",
            "4",
            "--output",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
            "--write-out",
            "%{http_code} %{time_starttransfer}",
            "--",
            &format!("https://{host}/"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(7);
    let terminal = loop {
        if control.cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            if control.cancel.load(Ordering::Acquire) {
                return Ok(None);
            }
            return Ok(Some(
                json!({"host":host,"ok":false,"code":0,"ttfb_ms":0,"error":"Истекло время запроса HTTPS."}),
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    };
    let mut buf = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(128)
        .read_to_string(&mut buf)?;
    if !terminal.success() {
        let code = terminal.code().unwrap_or(-1);
        return Ok(Some(
            json!({"host":host,"ok":false,"code":0,"ttfb_ms":0,"error":format!("Ошибка HTTPS (curl {code}).")}),
        ));
    }
    let (code, ttfb) = buf
        .trim()
        .split_once(' ')
        .ok_or_else(|| invalid("invalid curl result"))?;
    let code: u16 = code
        .parse()
        .ok()
        .filter(|c| (100..600).contains(c))
        .ok_or_else(|| invalid("invalid HTTP status"))?;
    let ttfb: f64 = ttfb
        .parse()
        .ok()
        .filter(|v: &f64| v.is_finite() && (0.0..=7.0).contains(v))
        .ok_or_else(|| invalid("invalid response time"))?;
    Ok(Some(
        json!({"host":host,"ok":(200..400).contains(&code),"code":code,"ttfb_ms":(ttfb*1000.0).round() as u64}),
    ))
}
fn measure(
    report: &mut Value,
    live: &Store,
    control: &Control,
    probe: &(impl Fn(&str, &Control) -> io::Result<Option<Value>> + Sync),
) -> io::Result<()> {
    let hosts: Vec<String> = serde_json::from_value(report["targets"].clone())?;
    let (send, recv) = mpsc::sync_channel(MAX_THREADS);
    thread::scope(|scope| {
        let mut pending = hosts.iter();
        let mut active = 0;
        loop {
            let limit = control.threads.load(Ordering::Acquire);
            let mut changed = report["threads"] != limit;
            report["threads"] = limit.into();
            while active < limit && !control.cancel.load(Ordering::Acquire) {
                let Some(host) = pending.next() else { break };
                let send = send.clone();
                thread::Builder::new()
                    .stack_size(128 << 10)
                    .spawn_scoped(scope, move || {
                        let result = probe(host, control);
                        let _ = send.send(result);
                    })?;
                active += 1;
            }
            if active == 0 {
                break;
            }
            if let Ok(item) = recv.recv_timeout(Duration::from_millis(50)) {
                active -= 1;
                if let Some(check) = item? {
                    let checks = report["checks"].as_array_mut().unwrap();
                    checks.push(check);
                    report["done"] = checks.len().into();
                    changed = true;
                }
            }
            if changed {
                live.transaction(|tx| tx.save("active.json", report))?;
            }
        }
        Ok(())
    })
}

pub fn run(dir: &Path, id: &str, live_dir: &Path) -> io::Result<()> {
    let db = Store::open(dir)?;
    let live = Store::open(live_dir)?;
    let mut input = BufReader::new(io::stdin());
    let setup = (|| {
        let raw = read_line(&mut input, 32 << 10)?.ok_or_else(|| invalid("missing request"))?;
        let mut report = create(
            &db,
            id,
            serde_json::from_slice(&raw).map_err(|_| {
                invalid("Нужен запрос current_https без параметров перебора стратегий.")
            })?,
        )?;
        let executable = curl()?;
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
        let control = Arc::new(Control {
            cancel: AtomicBool::new(false),
            threads: AtomicUsize::new(report["threads"].as_u64().unwrap() as usize),
        });
        let listener = control.clone();
        thread::Builder::new()
            .stack_size(128 << 10)
            .spawn(move || commands(input, listener))?;
        writeln!(io::stdout().lock(), "{}", json!({"started":report}))?;
        let result = measure(&mut report, &live, &control, &|host, c| {
            let mut cmd = Command::new(&executable);
            cmd.arg("--disable");
            measurement(cmd, host, c)
        });
        report["status"] = match &result {
            Err(e) => {
                report["error"] = e.to_string().into();
                "error"
            }
            Ok(()) if control.cancel.load(Ordering::Acquire) => "cancelled",
            Ok(()) => "done",
        }
        .into();
        report["finished_at"] = now().into();
        save_completed(&db, &mut report)?;
        live.transaction(|tx| tx.save("active.json", &report))?;
        Ok::<_, io::Error>(())
    })();
    if let Err(e) = &setup {
        let _ = writeln!(io::stdout().lock(), "{}", json!({"error":e.to_string()}));
    }
    setup
}
