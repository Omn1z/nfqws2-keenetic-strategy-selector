use super::{dns, probe, probe_hop, redirect, Control, ProbeLane, Request, Sandbox};
use nfqws2_store::Store;
use serde_json::Value;
use std::{
    io::{self, BufRead, BufReader, Read},
    net::Ipv4Addr,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
mod tests;

pub(super) const SLOT: usize = 8;
const MAX_PROBES: usize = 8;

struct Ports {
    bounds: (u16, u16),
    cursor: Mutex<u16>,
}

impl Ports {
    fn new(bounds: (u16, u16)) -> Self {
        Self {
            bounds,
            cursor: Mutex::new(bounds.0),
        }
    }

    fn count(&self) -> usize {
        usize::from(self.bounds.1 - self.bounds.0) + 1
    }

    fn next(&self, used: &[u16]) -> Option<u16> {
        let mut next = self.cursor.lock().unwrap();
        for _ in 0..(used.len() + 1).min(self.count()) {
            let port = *next;
            *next = if port == self.bounds.1 {
                self.bounds.0
            } else {
                port + 1
            };
            if !used.contains(&port) {
                return Some(port);
            }
        }
        None
    }
}

struct BaselineRedirect<'a> {
    control: &'a Control,
    local_ips: &'a [String],
    budget: Duration,
}

fn redirected_probe(
    host: &str,
    authority: &str,
    ports: &Ports,
    scope: BaselineRedirect<'_>,
    verify: &dyn Fn() -> bool,
    resolve: impl FnMut(&str, Instant) -> io::Result<Ipv4Addr>,
    mut command: impl FnMut(&str) -> Command,
) -> io::Result<Option<Value>> {
    let started = Instant::now();
    let uri = format!("https://{authority}/")
        .parse()
        .map_err(|_| super::invalid("некорректный HTTPS-адрес проверки"))?;
    let mut used = Vec::new();
    redirect::follow_public(
        host,
        uri,
        redirect::Chain {
            lease: started..started + scope.budget,
            port_count: ports.count(),
            baseline: true,
            address: None,
            local_ips: scope.local_ips,
        },
        scope.control,
        resolve,
        |hop| {
            if !used.is_empty() && !verify() {
                return Ok(None);
            }
            let Some(port) = ports.next(&used) else {
                return Ok(Some(redirect::Output::Terminal(redirect::no_port(
                    host, true,
                ))));
            };
            used.push(port);
            probe_hop(
                command(hop.uri.host().unwrap_or(authority)),
                host,
                (port, port),
                scope.control,
                ProbeLane::Baseline,
                Some(hop),
            )
        },
    )
}

pub(super) fn run(
    req: &Request,
    report: &mut Value,
    live: &Store,
    curl: &Path,
    control: &Control,
) -> io::Result<Vec<String>> {
    // One exclude-only lease keeps every baseline socket and TIME_WAIT entry
    // outside the candidate slots. No candidate or selected DNS runs yet.
    let mut sandbox = Sandbox::new_baseline(&req.config, SLOT)?;
    let ports = sandbox.port_range();
    let redirect_ports = Ports::new(ports);
    let local_ips = sandbox.local_ipv4_addresses().to_vec();
    let resolver = dns::Resolver::new(None);
    let sampled = (|| {
        sandbox.check()?;
        let rows = collect(
            &req.targets,
            &control.cancel,
            |host, verify| {
                if control.legacy {
                    return redirected_probe(
                        host,
                        req.target(host).authority,
                        &redirect_ports,
                        BaselineRedirect {
                            control,
                            local_ips: &local_ips,
                            budget: Duration::from_secs(20),
                        },
                        verify,
                        |next, deadline| resolver.redirect_address(None, next, deadline, control),
                        |_| Command::new(curl),
                    );
                }
                probe(
                    Command::new(curl),
                    host,
                    ports,
                    control,
                    ProbeLane::Baseline,
                )
            },
            || sandbox.check(),
        )?;
        sandbox.check()?;
        Ok::<_, io::Error>(rows)
    })();
    sandbox.cleanup()?;
    report["baseline"] = sampled?.into();
    live.transaction(|tx| tx.save("active.json", report))?;
    if control.cancel.load(Ordering::Acquire) {
        return Ok(Vec::new());
    }
    blocked_targets(report["baseline"].as_array().unwrap())
}

enum Event {
    Check(mpsc::SyncSender<()>),
    Finished(io::Result<(usize, Option<Value>)>),
}

fn collect(
    targets: &[String],
    cancel: &AtomicBool,
    fetch: impl Fn(&str, &dyn Fn() -> bool) -> io::Result<Option<Value>> + Sync,
    mut validate: impl FnMut() -> io::Result<()>,
) -> io::Result<Vec<Value>> {
    if cancel.load(Ordering::Acquire) {
        return Ok(Vec::new());
    }
    let next = AtomicUsize::new(0);
    let (send, receive) = mpsc::sync_channel(MAX_PROBES);
    thread::scope(|scope| {
        let mut rows = vec![None; targets.len()];
        let mut failure = None;
        for _ in 0..targets.len().min(MAX_PROBES) {
            let (worker, next, fetch) = (send.clone(), &next, &fetch);
            let spawned =
                thread::Builder::new()
                    .stack_size(256 << 10)
                    .spawn_scoped(scope, move || {
                        while !cancel.load(Ordering::Acquire) {
                            let index = next.fetch_add(1, Ordering::Relaxed);
                            let Some(host) = targets.get(index) else {
                                break;
                            };
                            let verify = || {
                                if cancel.load(Ordering::Acquire) {
                                    return false;
                                }
                                let (ready, approved) = mpsc::sync_channel(1);
                                worker.send(Event::Check(ready)).is_ok()
                                    && approved.recv().is_ok()
                                    && !cancel.load(Ordering::Acquire)
                            };
                            let result = fetch(host, &verify).map(|row| (index, row));
                            let failed = result.is_err();
                            if worker.send(Event::Finished(result)).is_err() || failed {
                                break;
                            }
                        }
                    });
            if let Err(error) = spawned {
                failure = Some(error);
                cancel.store(true, Ordering::Release);
                break;
            }
        }
        drop(send);
        // Drain until all workers have stopped before the lease can be freed.
        for event in receive {
            if failure.is_some() {
                continue;
            }
            let checked = match event {
                Event::Check(ready) => {
                    if cancel.load(Ordering::Acquire) {
                        continue;
                    }
                    // Record loss of isolation before releasing the waiting
                    // worker, so it cannot start another hop or a new target.
                    let checked = validate();
                    if checked.is_err() {
                        cancel.store(true, Ordering::Release);
                    } else {
                        let _ = ready.send(());
                    }
                    checked
                }
                Event::Finished(result) => result.and_then(|(index, row)| {
                    if let Some(row) = row {
                        validate()?;
                        rows[index] = Some(row);
                    }
                    Ok(())
                }),
            };
            if let Err(error) = checked {
                failure = Some(error);
                cancel.store(true, Ordering::Release);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(rows.into_iter().flatten().collect()),
        }
    })
}

fn blocked_targets(rows: &[Value]) -> io::Result<Vec<String>> {
    let mut targets = Vec::new();
    for row in rows {
        let host = row["host"].as_str().unwrap_or_default();
        if row["verdict"] == "local_error" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Локальная ошибка исходного запроса для {host}. Подбор остановлен."),
            ));
        }
        if row["blocked"] == true {
            targets.push(host.to_owned());
        }
    }
    Ok(targets)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectFailure {
    Reset,
    Refused,
}

pub(super) fn connection_failure(stderr: impl Read) -> Option<ConnectFailure> {
    const MAX_LINE: u64 = 512;
    let mut read = BufReader::new(stderr);
    let mut line = Vec::with_capacity(MAX_LINE as usize);
    let mut overlong = false;
    let mut result = None;
    loop {
        line.clear();
        match read.by_ref().take(MAX_LINE).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return result,
            _ => (),
        }
        // Drain even oversized or unrelated HTTP/TLS lines without retaining them.
        // Inspect only connection diagnostics emitted by curl itself.
        let end = line.last() == Some(&b'\n') || line.len() < MAX_LINE as usize;
        if !overlong && end {
            let text = String::from_utf8_lossy(&line).to_ascii_lowercase();
            if text.starts_with("* connect to ") && text.contains("connection refused") {
                result = Some(ConnectFailure::Refused);
            } else if (text.starts_with("* recv failure")
                || text.starts_with("* openssl ssl_")
                || text.starts_with("* tls connect error")
                || text.starts_with("curl: (")
                || text.starts_with("* connect to "))
                && [
                    "connection reset",
                    "connection was reset",
                    "forcibly closed",
                ]
                .iter()
                .any(|message| text.contains(message))
            {
                result = Some(ConnectFailure::Reset);
            }
        }
        overlong = !end;
    }
}

pub(super) fn classify(
    sample: &mut Value,
    exit: i32,
    watchdog: bool,
    complete: bool,
    failure: Option<ConnectFailure>,
) {
    let (verdict, blocked) = if sample["local_error"] == true {
        ("local_error", false)
    } else if sample["truncated"] == true {
        ("cap16k", true)
    } else if sample["code"].as_u64().unwrap_or_default() != 0 {
        if complete {
            sample.as_object_mut().unwrap().remove("err");
        }
        ("ok", false)
    } else {
        let verdict = match (exit, watchdog, failure) {
            (6, _, _) => "dns",
            (28, _, _) | (_, true, _) => "timeout",
            (7, _, Some(ConnectFailure::Refused)) => "refused",
            (7 | 35 | 52 | 55 | 56, _, Some(ConnectFailure::Reset)) => "reset",
            _ => "error",
        };
        (verdict, true)
    };
    sample["verdict"] = verdict.into();
    sample["blocked"] = blocked.into();
}
