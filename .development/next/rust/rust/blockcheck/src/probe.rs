use http::Uri;
use serde::Serialize;
use std::{
    io::{self, BufRead, BufReader, Read},
    net::Ipv4Addr,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const READ_CAP: u64 = 131072;
const HEADER_CAP: u64 = 65536;
const DEADLINE: Duration = Duration::from_secs(20);

#[derive(Debug, Default, Serialize)]
pub struct Measurement {
    pub code: u16,
    pub size: u64,
    pub ttfb_ms: u64,
    pub total_ms: u64,
    pub speed_bps: u64,
    pub remote_ip: String,
    pub local_error: bool,
    pub truncated: bool,
    pub ok: bool,
    pub err: String,
}
#[derive(Debug, Serialize)]
pub struct Target<'a> {
    pub host: &'a str,
    pub blocked: bool,
    pub verdict: &'static str,
    pub code: u16,
    pub size: u64,
    pub ttfb_ms: u64,
    pub speed_bps: u64,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub err: &'a str,
}
impl Measurement {
    pub fn classify<'a>(&'a self, host: &'a str) -> Target<'a> {
        let e = self.err.to_ascii_lowercase();
        let verdict = if self.local_error {
            "local_error"
        } else if self.truncated {
            "cap16k"
        } else if self.code != 0 {
            "ok"
        } else if [
            "no such host",
            "lookup",
            "server misbehaving",
            "could not resolve host",
        ]
        .iter()
        .any(|s| e.contains(s))
        {
            "dns"
        } else if e.contains("reset") || e.contains("forcibly closed") {
            "reset"
        } else if e.contains("refused") {
            "refused"
        } else if e.contains("timeout") || e.contains("deadline") || e.contains("timed out") {
            "timeout"
        } else {
            "error"
        };
        Target {
            host,
            blocked: !matches!(verdict, "ok" | "local_error"),
            verdict,
            code: self.code,
            size: self.size,
            ttfb_ms: self.ttfb_ms,
            speed_bps: self.speed_bps,
            err: &self.err,
        }
    }
}
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
fn https_url(url: &str) -> io::Result<Uri> {
    let uri = url
        .parse::<Uri>()
        .map_err(|_| invalid("invalid probe URL"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| invalid("missing HTTPS host"))?;
    let host = authority.host();
    let valid_host = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !valid_host
        || uri.scheme_str() != Some("https")
        || !(authority.as_str() == host || authority.as_str().strip_suffix(":443") == Some(host))
    {
        return Err(invalid("probe requires IPv4 HTTPS on port 443"));
    }
    Ok(uri)
}
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
fn redirect(from: &Uri, to: &str) -> io::Result<Uri> {
    let to = to.split('#').next().unwrap_or_default();
    let base = format!(
        "https://{}",
        from.authority()
            .ok_or_else(|| invalid("missing authority"))?
    );
    if to.starts_with("//") {
        return https_url(&format!("https:{to}"));
    }
    if to.starts_with('/') {
        return https_url(&format!("{base}{to}"));
    }
    if to.starts_with('?') {
        return https_url(&format!("{base}{}{to}", from.path()));
    }
    if to.is_empty() {
        return Ok(from.clone());
    }
    if to.split('/').next().is_some_and(|s| s.contains(':')) {
        return https_url(to);
    }
    let parent = from.path().rsplit_once('/').map_or("", |(p, _)| p);
    https_url(&format!("{base}{parent}/{to}"))
}
#[derive(Default)]
struct Response {
    code: u16,
    size: u64,
    ttfb_ms: u64,
    elapsed_ms: u64,
    location: String,
}
fn response(read: impl Read, start: Instant) -> io::Result<Response> {
    let mut read = BufReader::new(read);
    let mut res = Response::default();
    let mut line = Vec::new();
    let mut remaining = HEADER_CAP;
    loop {
        line.clear();
        let n = (&mut read).take(remaining).read_until(b'\n', &mut line)?;
        if n == 0 && res.code == 0 {
            return Ok(res);
        }
        if n == 0 || n as u64 >= remaining || line.last() != Some(&b'\n') {
            return Err(invalid("incomplete or oversized HTTP headers"));
        }
        remaining -= n as u64;
        let text = String::from_utf8_lossy(&line);
        if res.code == 0 {
            let mut status = text.split_whitespace();
            if !status.next().is_some_and(|s| s.starts_with("HTTP/")) {
                return Err(invalid("invalid HTTP status line"));
            }
            res.ttfb_ms = start.elapsed().as_millis() as u64;
            res.code = status
                .next()
                .and_then(|v| v.parse().ok())
                .filter(|c| (100..=599).contains(c))
                .ok_or_else(|| invalid("invalid HTTP status"))?;
        } else if text.trim_end_matches(['\r', '\n']).is_empty() {
            if (100..200).contains(&res.code) && res.code != 101 {
                res.code = 0;
                res.location.clear();
                continue;
            }
            break;
        } else if let Some((key, val)) = text.split_once(':') {
            if key.eq_ignore_ascii_case("location") {
                res.location = val.trim().into();
            }
        }
    }
    if !is_redirect(&res) {
        res.size = io::copy(&mut read.take(READ_CAP), &mut io::sink())?;
    }
    res.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(res)
}
fn is_redirect(r: &Response) -> bool {
    matches!(r.code, 301 | 302 | 303 | 307 | 308) && !r.location.is_empty()
}
fn curl_command(
    uri: &Uri,
    ports: (u16, u16),
    resolve: Option<Ipv4Addr>,
    remaining: Duration,
) -> Command {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--disable",
        "--silent",
        "--show-error",
        "--no-buffer",
        "--include",
        "--globoff",
        "--ipv4",
        "--insecure",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--local-port",
        &format!("{}-{}", ports.0, ports.1),
        "--connect-timeout",
        "6",
        "--max-time",
        &format!("{:.3}", remaining.as_secs_f64().max(0.001)),
        "--user-agent",
        "Mozilla/5.0 (nfqws2-strategy)",
        "--compressed",
        "--header",
        "Accept-Encoding: gzip",
        "--write-out",
        "%{stderr}\nN2S_REMOTE=%{remote_ip}\n",
    ]);
    if let Some(ip) = resolve {
        cmd.args([
            "--resolve",
            &format!("{}:443:{ip}", uri.host().unwrap_or_default()),
        ]);
    }
    cmd.arg("--")
        .arg(uri.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

struct Transfer {
    response: Response,
    status: Option<i32>,
    error: String,
    remote_ip: String,
}
fn transfer(mut cmd: Command, start: Instant, cancel: &AtomicBool) -> io::Result<Transfer> {
    crate::tied_to_parent(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("start curl: {e}")))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    thread::scope(|scope| {
        // Bound retained diagnostics, but keep draining the pipe to avoid
        // blocking curl if an OS or TLS backend writes a long error message.
        let mut stop_child_on_error = |e| {
            let _ = child.kill();
            let _ = child.wait();
            e
        };
        let diagnostics = thread::Builder::new()
            .stack_size(96 * 1024)
            .spawn_scoped(scope, move || {
                let mut bytes = Vec::new();
                let mut stream = stderr;
                (&mut stream).take(8192).read_to_end(&mut bytes)?;
                io::copy(&mut stream, &mut io::sink())?;
                Ok::<_, io::Error>(String::from_utf8_lossy(&bytes).into_owned())
            })
            .map_err(&mut stop_child_on_error)?;
        let (tx, rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .stack_size(96 * 1024)
            .spawn_scoped(scope, move || {
                let _ = tx.send(response(stdout, start));
            })
            .map_err(stop_child_on_error)?;
        let mut res = None;
        let status = loop {
            if res.is_none() {
                res = rx.try_recv().ok();
            }
            let stop = res.as_ref().is_some_and(|r| {
                r.as_ref()
                    .map_or(true, |v| v.size == READ_CAP || is_redirect(v))
            });
            if stop || cancel.load(Ordering::Relaxed) || start.elapsed() > DEADLINE {
                let _ = child.kill();
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            thread::sleep(Duration::from_millis(25));
        };
        let res = res
            .or_else(|| rx.recv().ok())
            .ok_or_else(|| io::Error::other("curl reader stopped"))?;
        let diag = diagnostics
            .join()
            .map_err(|_| io::Error::other("curl error reader stopped"))??;
        let (err, remote_ip) = diag
            .rsplit_once("N2S_REMOTE=")
            .map_or((diag.trim(), ""), |(e, ip)| (e.trim(), ip.trim()));
        let (response, mut error) = match res {
            Ok(v) => (v, err.to_string()),
            Err(e) => (Response::default(), e.to_string()),
        };
        if !status.success()
            && error.is_empty()
            && response.size < READ_CAP
            && !is_redirect(&response)
        {
            error = if start.elapsed() >= DEADLINE {
                "probe timeout".into()
            } else {
                format!("curl {status}")
            };
        }
        Ok(Transfer {
            response,
            status: status.code(),
            error,
            remote_ip: remote_ip.into(),
        })
    })
}
fn measurement(t: Transfer) -> Measurement {
    let r = t.response;
    let complete = t.status == Some(0) || r.size >= READ_CAP;
    let local_error = t.status == Some(45)
        || [
            "bind failed",
            "address already in use",
            "cannot assign requested address",
            "bind on port",
            "local port",
        ]
        .iter()
        .any(|e| t.error.to_ascii_lowercase().contains(e));
    let truncated = !complete && r.size > 0 && r.size <= 17408;
    let err = if complete { String::new() } else { t.error };
    Measurement {
        code: r.code,
        size: r.size,
        ttfb_ms: r.ttfb_ms,
        total_ms: r.elapsed_ms,
        speed_bps: (r.size * 1000).checked_div(r.elapsed_ms).unwrap_or(0),
        remote_ip: t.remote_ip,
        local_error,
        truncated,
        ok: complete && (200..400).contains(&r.code) && r.size > 16384,
        err,
    }
}

/// DNS overrides bind only the original host, retaining TLS SNI. Every hop is
/// checked before opening a socket so redirects cannot escape the firewall's
/// IPv4 TCP/443 match. The same twenty-second budget covers all redirects.
pub fn measure(
    host: &str,
    url: &str,
    ports: (u16, u16),
    resolve: Option<Ipv4Addr>,
    cancel: &AtomicBool,
) -> io::Result<Measurement> {
    let mut uri = match https_url(url) {
        Ok(u) => u,
        Err(e) => {
            return Ok(Measurement {
                err: e.to_string(),
                ..Default::default()
            })
        }
    };
    if ports.0 == 0 || ports.1 < ports.0 {
        return Err(invalid("invalid probe source-port range"));
    }
    let start = Instant::now();
    for _ in 0..10 {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let Some(remaining) = DEADLINE.checked_sub(start.elapsed()) else {
            return Ok(Measurement {
                err: "probe timeout".into(),
                ..Default::default()
            });
        };
        let address = resolve.filter(|_| uri.host().is_some_and(|h| h.eq_ignore_ascii_case(host)));
        let t = transfer(curl_command(&uri, ports, address, remaining), start, cancel)?;
        if !is_redirect(&t.response) {
            return Ok(measurement(t));
        }
        uri = match redirect(&uri, &t.response.location) {
            Ok(u) => u,
            Err(e) => {
                return Ok(Measurement {
                    err: e.to_string(),
                    ..Default::default()
                })
            }
        };
    }
    Ok(Measurement {
        err: "too many redirects".into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn result(code: u16, n: u64, completion: i32, msg: &str) -> Measurement {
        measurement(Transfer {
            response: Response {
                code,
                size: n,
                ttfb_ms: 10,
                elapsed_ms: 50,
                location: String::new(),
            },
            status: Some(completion),
            error: msg.into(),
            remote_ip: "192.0.2.2".into(),
        })
    }
    #[test]
    fn legacy_verdicts_and_transfer_boundaries() {
        for (code, size, exit, msg, expected, blocked) in [
            (403, 0, 0, "", "ok", false),
            (500, 5, 0, "", "ok", false),
            (200, 17408, 56, "reset", "cap16k", true),
            (200, 17409, 56, "reset", "ok", false),
            (200, 0, 56, "reset", "ok", false),
            (200, 120, 0, "", "ok", false),
            (0, 0, 45, "bind failed", "local_error", false),
            (0, 0, 6, "Could not resolve host", "dns", true),
            (0, 0, 56, "Forcibly closed", "reset", true),
            (0, 0, 7, "connection refused", "refused", true),
            (0, 0, 28, "operation timed out", "timeout", true),
            (0, 0, 35, "TLS alert", "error", true),
        ] {
            let m = result(code, size, exit, msg);
            let t = m.classify("example.test");
            assert_eq!((t.verdict, t.blocked), (expected, blocked));
            assert_eq!(t.speed_bps, size * 20);
        }
        assert!(!result(200, 16384, 0, "").ok);
        assert!(result(200, 16385, 0, "").ok);
        assert!(result(200, READ_CAP, 23, "write closed at cap").ok);
    }
    #[test]
    fn parses_informational_headers_and_stops_reading_large_bodies() {
        let mut bytes =
            b"HTTP/1.1 103 Early Hints\r\nLink: /a\r\n\r\nHTTP/2 200\r\nX-Test: t\r\n\r\n".to_vec();
        bytes.resize(bytes.len() + 2 * READ_CAP as usize, b'x');
        let r = response(bytes.as_slice(), Instant::now()).unwrap();
        assert_eq!((r.code, r.size), (200, READ_CAP));
        let r = response(
            b"HTTP/1.1 302 Found\r\nLocation: /finish\r\n\r\nignored".as_slice(),
            Instant::now(),
        )
        .unwrap();
        assert!(is_redirect(&r));
        assert_eq!(r.size, 0);
        assert!(response(b"HTTP/1.1 200 OK\r\n".as_slice(), Instant::now()).is_err());
        let huge = vec![b'a'; 70000];
        assert!(response(huge.as_slice(), Instant::now()).is_err());
    }
    #[test]
    fn every_redirect_and_dns_override_preserves_isolation() {
        let base = https_url("https://one.test:443/a/b?q=1").unwrap();
        for input in [
            "http://two.test/",
            "https://two.test:8443/x",
            "//user@two.test/",
            "https://two.test:x/",
            "https://[::1]/",
            "file:///tmp/a",
            "//%74wo.test/",
        ] {
            assert!(redirect(&base, input).is_err(), "{input}");
        }
        assert_eq!(redirect(&base, "end").unwrap().path(), "/a/end");
        assert_eq!(
            redirect(&base, "//two.test/end").unwrap().host(),
            Some("two.test")
        );
        assert_eq!(redirect(&base, "?q=2").unwrap().query(), Some("q=2"));
        let cmd = curl_command(
            &base,
            (50010, 50019),
            Some(Ipv4Addr::new(192, 0, 2, 9)),
            DEADLINE,
        );
        let argv: Vec<_> = cmd.get_args().map(|v| v.to_str().unwrap()).collect();
        for pair in [
            ["--local-port", "50010-50019"],
            ["--resolve", "one.test:443:192.0.2.9"],
            ["--proto", "=https"],
            ["--noproxy", "*"],
        ] {
            assert!(argv.windows(2).any(|w| w == pair));
        }
        assert!(argv.contains(&"--ipv4") && !argv.contains(&"--location"));
        assert!(!valid_host("example.test/../") && !valid_host("name@host.test"));
    }
    #[test]
    fn pre_cancelled_probe_never_spawns_curl() {
        let cancel = AtomicBool::new(true);
        assert_eq!(
            measure(
                "example.test",
                "https://example.test/",
                (50000, 50009),
                None,
                &cancel
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn process_stream_propagates_midbody_reset_and_cancels_blocked_child() {
        fn fixture(wait: bool) -> Command {
            #[cfg(windows)]
            let mut cmd = {
                let mut cmd = Command::new("powershell");
                cmd.args(["-NoProfile","-NonInteractive","-Command",if wait {"Start-Sleep -Seconds 20"} else {
                    "[Console]::WriteLine('HTTP/2 200'); [Console]::WriteLine(''); [Console]::Write(('x' * 16000)); [Console]::Error.WriteLine('connection reset'); exit 56"
                }]);
                cmd
            };
            #[cfg(not(windows))]
            let mut cmd = {
                let mut cmd = Command::new("sh");
                cmd.args(["-c",if wait {"exec sleep 20"} else {
                    "printf 'HTTP/2 200\\r\\n\\r\\n'; head -c 16000 /dev/zero; echo 'connection reset' >&2; exit 56"
                }]);
                cmd
            };
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }
        let cancel = AtomicBool::new(false);
        let measured = measurement(transfer(fixture(false), Instant::now(), &cancel).unwrap());
        assert_eq!(measured.size, 16000);
        assert_eq!(measured.classify("example.test").verdict, "cap16k");
        let start = Instant::now();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(60));
                cancel.store(true, Ordering::Relaxed);
            });
            let transfer = transfer(fixture(true), start, &cancel).unwrap();
            assert_ne!(transfer.status, Some(0));
        });
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
