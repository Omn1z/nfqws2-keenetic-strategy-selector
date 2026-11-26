use crate::http::AppState;
use std::{io, sync::Weak, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    task::JoinHandle,
    time::timeout,
};

const MAX_EVENT: u64 = 80;
const MAX_WS_EVENT: u64 = 160;

pub(super) struct Capture(JoinHandle<()>);

impl Capture {
    pub(super) fn start(
        stderr: impl AsyncRead + Unpin + Send + 'static,
        owner: Weak<AppState>,
    ) -> Self {
        Self(tokio::spawn(async move {
            let _ = consume(stderr, |event| {
                if let Some(owner) = owner.upgrade() {
                    match event {
                        Event::Refill(refill) => {
                            owner.logs.append("tgws", "error", &refill.message())
                        }
                        Event::RefillCapacity { dc, media } => owner.logs.append(
                            "tgws",
                            "info",
                            &format!("tgws: WS pool refill waiting for local setup capacity DC{dc} media={media}; retry in 1s"),
                        ),
                        Event::BadHandshake => owner.logs.append(
                            "tgws",
                            "warn",
                            "tgws: bad handshake (wrong secret or proto)",
                        ),
                        Event::NoFallback { dc, media, test } => {
                            let media = if media { " media" } else { "" };
                            let test = if test { " test" } else { "" };
                            owner.logs.append(
                                "tgws",
                                "error",
                                &format!("tgws: DC{dc}{media}{test} no fallback available"),
                            );
                        }
                        Event::CatalogRefreshFailed => owner.logs.append(
                            "tgws",
                            "error",
                            "tgws: CF domain refresh failed; keeping current pool",
                        ),
                        Event::ListenerLost => {
                            owner
                                .logs
                                .append("tgws", "error", "tgws: listener failed; reopening")
                        }
                        Event::ListenerRestored => {
                            owner.logs.append("tgws", "info", "tgws: listener restored")
                        }
                        Event::H2Transport404 => owner.logs.append(
                            "tgws",
                            "error",
                            "tgws: H2 session closed (HTTP download: MTProto transport error -404)",
                        ),
                        Event::H2Transport(error) => {
                            owner.logs.append("tgws", "error", &error.message())
                        }
                        Event::WsClosed(session) => {
                            owner.logs.append("tgws", "info", &session.message())
                        }
                        Event::WorkerUpgradeRejected { dc, test, status } => {
                            let test = if test { " test" } else { "" };
                            owner.logs.append(
                                "tgws",
                                "error",
                                &format!("tgws: DC{dc}{test} CF worker failed: HTTP {status}"),
                            );
                        }
                        Event::WebUpgradeRejected { dc, status } => owner.logs.append(
                            "tgws", "error", &format!("tgws: DC{dc} CF WebSocket failed: HTTP {status}"),
                        ),
                        Event::TcpFallbackFailed { dc, test, seconds } => {
                            let test = if test { " test" } else { "" };
                            let delay = retry_delay(seconds);
                            owner.logs.append(
                                "tgws",
                                "error",
                                &format!(
                                    "tgws: TCP fallback DC{dc}{test} failed; retry in {delay}"
                                ),
                            );
                        }
                    }
                }
            })
            .await;
        }))
    }

    pub(super) async fn finish(&mut self) {
        let _ = timeout(Duration::from_millis(200), &mut self.0).await;
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Refill {
    dc: u16,
    media: bool,
    seconds: u64,
}

enum H2Transport {
    Http(u16),
    Payload(i32),
}

impl H2Transport {
    fn parse(line: &[u8]) -> Option<Self> {
        let line = std::str::from_utf8(line.strip_suffix(b"\n")?).ok()?;
        let (source, value) = line.split_once(' ')?;
        match (source, value) {
            ("http", "403" | "404" | "429" | "444") => Some(Self::Http(value.parse().ok()?)),
            ("payload", value) => {
                let code: i32 = value.parse().ok()?;
                (code < 0 && code.to_string() == value).then_some(Self::Payload(code))
            }
            _ => None,
        }
    }

    fn message(&self) -> String {
        let (code, source) = match self {
            Self::Http(status) => (-i32::from(*status), format!("HTTP {status}")),
            Self::Payload(code) => (*code, "HTTP 200 payload".into()),
        };
        format!(
            "tgws: H2 session closed (HTTP download: MTProto transport error {code} ({source}))"
        )
    }
}

struct WsClosed {
    leg: &'static str,
    reason: &'static str,
    upload_bytes: u64,
    upload_chunks: u64,
    download_bytes: u64,
    download_frames: u64,
    tenths: u64,
}

impl WsClosed {
    fn parse(line: &[u8]) -> Option<Self> {
        let mut fields = std::str::from_utf8(line.strip_suffix(b"\n")?)
            .ok()?
            .split(' ');
        let (leg, reason) = match (fields.next()?, fields.next()?) {
            ("stop", "shutdown") => ("service", "shutdown"),
            (leg, reason) => {
                let leg = match leg {
                    "client-read" => "client",
                    "upstream-read" => "upstream",
                    "client-write" => "client write",
                    "upstream-write" => "upstream write",
                    _ => return None,
                };
                let reason = match reason {
                    "eof" => "EOF",
                    "timeout" => "timeout",
                    "closed" => "connection closed",
                    "invalid" => "invalid data",
                    "io" => "I/O error",
                    _ => return None,
                };
                (leg, reason)
            }
        };
        let mut read_number = || {
            let field = fields.next()?;
            let value: u64 = field.parse().ok()?;
            (value.to_string() == field).then_some(value)
        };
        let session = Self {
            leg,
            reason,
            upload_bytes: read_number()?,
            upload_chunks: read_number()?,
            download_bytes: read_number()?,
            download_frames: read_number()?,
            tenths: read_number()?,
        };
        fields.next().is_none().then_some(session)
    }

    fn message(&self) -> String {
        format!(
            "tgws: WS session closed ({}: {}): up={} ({} chunks) down={} ({} frames) in {}.{}s",
            self.leg,
            self.reason,
            self.upload_bytes,
            self.upload_chunks,
            self.download_bytes,
            self.download_frames,
            self.tenths / 10,
            self.tenths % 10,
        )
    }
}

enum Event {
    Refill(Refill),
    RefillCapacity { dc: u16, media: bool },
    BadHandshake,
    NoFallback { dc: u16, media: bool, test: bool },
    CatalogRefreshFailed,
    ListenerLost,
    ListenerRestored,
    H2Transport404,
    H2Transport(H2Transport),
    WsClosed(WsClosed),
    WorkerUpgradeRejected { dc: u16, test: bool, status: u16 },
    WebUpgradeRejected { dc: u16, status: u16 },
    TcpFallbackFailed { dc: u16, test: bool, seconds: u64 },
}

impl Event {
    fn upgrade_rejection(line: &[u8], worker: bool) -> Option<Self> {
        let mut fields = std::str::from_utf8(line.strip_suffix(b"\n")?)
            .ok()?
            .split(' ');
        let dc_text = fields.next()?;
        let dc: u16 = dc_text.parse().ok()?;
        let test = if worker {
            fields.next()?.parse().ok()?
        } else {
            false
        };
        let status_text = fields.next()?;
        let status: u16 = status_text.parse().ok()?;
        if !matches!((test, dc), (false, 1..=5 | 203) | (true, 1..=3))
            || !(100..=599).contains(&status)
            || status == 101
            || dc.to_string() != dc_text
            || status.to_string() != status_text
            || fields.next().is_some()
        {
            return None;
        }
        Some(if worker {
            Self::WorkerUpgradeRejected { dc, test, status }
        } else {
            Self::WebUpgradeRejected { dc, status }
        })
    }

    fn parse(line: &[u8]) -> Option<Self> {
        if let Some(session) = line.strip_prefix(b"n2s-tgws-ws-close-v1 ") {
            return WsClosed::parse(session).map(Self::WsClosed);
        }
        if line.len() as u64 > MAX_EVENT {
            return None;
        }
        match line {
            b"n2s-tgws-bad-handshake-v1\n" => return Some(Self::BadHandshake),
            b"n2s-tgws-catalog-refresh-failed-v1\n" => return Some(Self::CatalogRefreshFailed),
            b"n2s-tgws-listener-lost-v1\n" => return Some(Self::ListenerLost),
            b"n2s-tgws-listener-restored-v1\n" => return Some(Self::ListenerRestored),
            b"n2s-tgws-h2-transport-404-v1\n" => return Some(Self::H2Transport404),
            _ => (),
        }
        if let Some(error) = line.strip_prefix(b"n2s-tgws-h2-transport-error-v1 ") {
            return H2Transport::parse(error).map(Self::H2Transport);
        }
        if let Some(rejection) = line.strip_prefix(b"n2s-tgws-worker-upgrade-rejected-v1 ") {
            return Self::upgrade_rejection(rejection, true);
        }
        if let Some(rejection) = line.strip_prefix(b"n2s-tgws-cf-web-upgrade-rejected-v1 ") {
            return Self::upgrade_rejection(rejection, false);
        }
        if let Some(waiting) = line.strip_prefix(b"n2s-tgws-refill-capacity-v1 ") {
            let mut fields = std::str::from_utf8(waiting.strip_suffix(b"\n")?)
                .ok()?
                .split(' ');
            let dc = fields.next()?.parse().ok()?;
            let media = fields.next()?.parse().ok()?;
            if !matches!(dc, 1..=5 | 203) || fields.next().is_some() {
                return None;
            }
            return Some(Self::RefillCapacity { dc, media });
        }
        if let Some(failure) = line.strip_prefix(b"n2s-tgws-tcp-fallback-failed-v1 ") {
            let mut fields = std::str::from_utf8(failure.strip_suffix(b"\n")?)
                .ok()?
                .split(' ');
            let dc = fields.next()?.parse().ok()?;
            let test = fields.next()?.parse().ok()?;
            let seconds = fields.next()?.parse().ok()?;
            if !matches!((test, dc), (false, 1..=5 | 203) | (true, 1..=3))
                || !matches!(seconds, 30 | 60 | 120 | 240 | 480 | 960 | 1920 | 3600)
                || fields.next().is_some()
            {
                return None;
            }
            return Some(Self::TcpFallbackFailed { dc, test, seconds });
        }
        let Some(fallback) = line.strip_prefix(b"n2s-tgws-no-fallback-v1 ") else {
            return Refill::parse(line).map(Self::Refill);
        };
        let mut fields = std::str::from_utf8(fallback.strip_suffix(b"\n")?)
            .ok()?
            .split(' ');
        let dc = fields.next()?.parse().ok()?;
        let media = fields.next()?.parse().ok()?;
        let test = fields.next()?.parse().ok()?;
        if !matches!(dc, 1..=5 | 203) || fields.next().is_some() {
            return None;
        }
        Some(Self::NoFallback { dc, media, test })
    }
}

impl Refill {
    fn parse(line: &[u8]) -> Option<Self> {
        let line = std::str::from_utf8(line.strip_suffix(b"\n")?).ok()?;
        let mut fields = line.strip_prefix("n2s-tgws-refill-v1 ")?.split(' ');
        let dc = fields.next()?.parse().ok()?;
        let media = fields.next()?.parse().ok()?;
        let seconds = fields.next()?.parse().ok()?;
        if !(1..=9999).contains(&dc) || !(1..=3600).contains(&seconds) || fields.next().is_some() {
            return None;
        }
        Some(Self { dc, media, seconds })
    }

    fn message(&self) -> String {
        let delay = retry_delay(self.seconds);
        format!(
            "tgws: WS pool refill failed DC{} media={}; retry in {delay}",
            self.dc, self.media
        )
    }
}

fn retry_delay(seconds: u64) -> String {
    match seconds {
        3600 => "1h0m0s".into(),
        60..=3599 => format!("{}m{}s", seconds / 60, seconds % 60),
        seconds => format!("{seconds}s"),
    }
}

async fn consume(stderr: impl AsyncRead + Unpin, mut emit: impl FnMut(Event)) -> io::Result<()> {
    let mut stderr = BufReader::new(stderr);
    let mut line = Vec::new();
    let mut continued = false;
    loop {
        line.clear();
        let n = (&mut stderr)
            .take(MAX_WS_EVENT + 1)
            .read_until(b'\n', &mut line)
            .await?;
        if n == 0 {
            return Ok(());
        }
        if !continued && n as u64 <= MAX_WS_EVENT {
            if let Some(event) = Event::parse(&line) {
                emit(event);
            }
        }
        // Ignore all further pieces of an oversized line up to its newline.
        continued = line.last() != Some(&b'\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use nfqws2_config::{Config, Resolver};
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn worker_listener_restored_and_refill_capacity_require_exact_recovery_records() {
        let stderr = concat!(
            "n2s-tgws-listener-restored-v1 extra\n",
            "n2s-tgws-listener-restored-v1\n",
            "n2s-tgws-refill-capacity-v1 9999 true\n",
            "n2s-tgws-refill-capacity-v1 2 false extra\n",
            "n2s-tgws-refill-capacity-v1 2 true\n",
            "n2s-tgws-refill-capacity-v1 2 false",
        );
        let mut events = Vec::new();
        consume(io::Cursor::new(stderr), |event| events.push(event))
            .await
            .unwrap();
        assert!(matches!(
            events.as_slice(),
            [
                Event::ListenerRestored,
                Event::RefillCapacity { dc: 2, media: true }
            ]
        ));
    }

    #[tokio::test]
    async fn api_logs_only_valid_bounded_worker_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::open(
            Config {
                data_dir: dir.path().display().to_string(),
                ..Config::from_resolver(&Resolver::new_at(dir.path()))
            },
            dir.path(),
            true,
        )
        .unwrap();
        let mut stderr =
            b"raw stderr without validated data\nn2s-tgws-refill-v1 2 false 1\n".to_vec();
        stderr.extend(std::iter::repeat_n(b'x', 64 * 1024));
        stderr.extend_from_slice(
            concat!(
                "n2s-tgws-refill-v1 8 false 120\n",
                "n2s-tgws-refill-v1 7 false 3601\n",
                "n2s-tgws-refill-v1 6 true 2 extra\n",
                "n2s-tgws-bad-handshake-v1 extra\n",
                "n2s-tgws-bad-handshake-v1\n",
                "n2s-tgws-no-fallback-v1 101 false true\n",
                "n2s-tgws-no-fallback-v1 203 true true extra\n",
                "n2s-tgws-no-fallback-v1 203 true true\n",
                "n2s-tgws-refill-v1 203 true 3600\n",
                "n2s-tgws-catalog-refresh-failed-v1 extra\n",
                "n2s-tgws-catalog-refresh-failed-v1\n",
                "n2s-tgws-listener-lost-v1 extra\n",
                "n2s-tgws-listener-lost-v1\n",
                "n2s-tgws-listener-restored-v1\n",
                "n2s-tgws-refill-capacity-v1 4 false\n",
                "n2s-tgws-h2-transport-404-v1 extra\n",
                "n2s-tgws-h2-transport-404-v1\n",
                "n2s-tgws-tcp-fallback-failed-v1 203 true 30\n",
                "n2s-tgws-tcp-fallback-failed-v1 2 true 31\n",
                "n2s-tgws-tcp-fallback-failed-v1 2 true 30 extra\n",
                "n2s-tgws-tcp-fallback-failed-v1 2 true 30\n",
                "n2s-tgws-tcp-fallback-failed-v1 203 false 3600\n",
                "n2s-tgws-h2-transport-error-v1 http 200\n",
                "n2s-tgws-h2-transport-error-v1 http 0403\n",
                "n2s-tgws-h2-transport-error-v1 http -403\n",
                "n2s-tgws-h2-transport-error-v1 http 403 unused\n",
                "n2s-tgws-h2-transport-error-v1 payload 404\n",
                "n2s-tgws-h2-transport-error-v1 payload -0\n",
                "n2s-tgws-h2-transport-error-v1 payload -002\n",
                "n2s-tgws-h2-transport-error-v1 payload -2147483649\n",
                "n2s-tgws-h2-transport-error-v1 other -429\n",
                "n2s-tgws-h2-transport-error-v1 http 403\n",
                "n2s-tgws-h2-transport-error-v1 http 404\n",
                "n2s-tgws-h2-transport-error-v1 http 429\n",
                "n2s-tgws-h2-transport-error-v1 http 444\n",
                "n2s-tgws-h2-transport-error-v1 payload -404\n",
                "n2s-tgws-h2-transport-error-v1 payload -2147483648\n",
                "n2s-tgws-ws-close-v1 upstream example.invalid 8 2 5 1 13\n",
                "n2s-tgws-ws-close-v1 client-read shutdown 8 2 5 1 13\n",
                "n2s-tgws-ws-close-v1 stop eof 8 2 5 1 13\n",
                "n2s-tgws-ws-close-v1 client-read eof 8 2 0 1 13 extra\n",
                "n2s-tgws-ws-close-v1 client-read eof 08 2 0 1 13\n",
                "n2s-tgws-ws-close-v1 client-read eof 18446744073709551616 2 0 1 13\n",
                "n2s-tgws-ws-close-v1 client-read eof 8 2 0 1 13\n",
                "n2s-tgws-ws-close-v1 upstream-write closed 18446744073709551615 18446744073709551615 18446744073709551615 18446744073709551615 18446744073709551615\n",
                "n2s-tgws-ws-close-v1 stop shutdown 0 0 0 0 0\n",
                "n2s-tgws-worker-upgrade-rejected-v1 2 false 429 worker.example.test\n",
                "n2s-tgws-worker-upgrade-rejected-v1 2 false 101\n",
                "n2s-tgws-worker-upgrade-rejected-v1 2 false 099\n",
                "n2s-tgws-worker-upgrade-rejected-v1 2 false 600\n",
                "n2s-tgws-worker-upgrade-rejected-v1 2 false 0429\n",
                "n2s-tgws-worker-upgrade-rejected-v1 02 false 429\n",
                "n2s-tgws-worker-upgrade-rejected-v1 4 true 403\n",
                "n2s-tgws-worker-upgrade-rejected-v1 203 true 429\n",
                "n2s-tgws-worker-upgrade-rejected-v1 0 false 429\n",
                "n2s-tgws-worker-upgrade-rejected-v1 2 false 429\n",
                "n2s-tgws-worker-upgrade-rejected-v1 3 true 403\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 2 503 catalog.example.test\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 2 false 503\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 2 101\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 2 600\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 2 0503\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 00 503\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 10002 503\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 2 503\n",
                "n2s-tgws-cf-web-upgrade-rejected-v1 203 429\n",
                "n2s-tgws-refill-v1 5 true 8",
            )
            .as_bytes(),
        );
        let mut ws = Vec::new();
        consume(io::Cursor::new(stderr.as_slice()), |event| {
            if let Event::WsClosed(session) = event {
                ws.push(session.message());
            }
        })
        .await
        .unwrap();
        assert_eq!(ws, [
            "tgws: WS session closed (client: EOF): up=8 (2 chunks) down=0 (1 frames) in 1.3s",
            "tgws: WS session closed (upstream write: connection closed): up=18446744073709551615 (18446744073709551615 chunks) down=18446744073709551615 (18446744073709551615 frames) in 1844674407370955161.5s",
            "tgws: WS session closed (service: shutdown): up=0 (0 chunks) down=0 (0 frames) in 0.0s",
        ]);
        let mut capture =
            Capture::start(io::Cursor::new(stderr), std::sync::Arc::downgrade(&state));
        (&mut capture.0).await.unwrap();
        let app = crate::http::router(state);
        let response = app
            .oneshot(
                Request::get("/api/logs?module=tgws")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let logs: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
        let entries = logs["entries"].as_array().unwrap();
        // The legacy logger suppresses informational proxy records.
        assert_eq!(entries.len(), 19);
        assert_eq!(
            entries[0]["msg"],
            "tgws: WS pool refill failed DC2 media=false; retry in 1s"
        );
        assert_eq!(
            entries[1]["msg"],
            "tgws: bad handshake (wrong secret or proto)"
        );
        assert_eq!(entries[1]["level"], "warn");
        assert_eq!(
            entries[2]["msg"],
            "tgws: DC203 media test no fallback available"
        );
        assert_eq!(entries[2]["level"], "error");
        assert_eq!(
            entries[3]["msg"],
            "tgws: WS pool refill failed DC203 media=true; retry in 1h0m0s"
        );
        assert_eq!(entries[0]["level"], "error");
        assert_eq!(entries[3]["level"], "error");
        assert_eq!(
            entries[4]["msg"],
            "tgws: CF domain refresh failed; keeping current pool"
        );
        assert_eq!(entries[4]["level"], "error");
        assert_eq!(entries[5]["msg"], "tgws: listener failed; reopening");
        assert_eq!(entries[5]["level"], "error");
        assert_eq!(
            entries[6]["msg"],
            "tgws: H2 session closed (HTTP download: MTProto transport error -404)"
        );
        assert_eq!(entries[6]["level"], "error");
        assert_eq!(
            entries[7]["msg"],
            "tgws: TCP fallback DC2 test failed; retry in 30s"
        );
        assert_eq!(entries[7]["level"], "error");
        assert_eq!(
            entries[8]["msg"],
            "tgws: TCP fallback DC203 failed; retry in 1h0m0s"
        );
        assert_eq!(entries[8]["level"], "error");
        let h2 = [
            "-403 (HTTP 403)",
            "-404 (HTTP 404)",
            "-429 (HTTP 429)",
            "-444 (HTTP 444)",
            "-404 (HTTP 200 payload)",
            "-2147483648 (HTTP 200 payload)",
        ];
        for (entry, expected) in entries[9..].iter().zip(h2) {
            assert_eq!(entry["level"], "error");
            assert_eq!(
                entry["msg"],
                format!(
                    "tgws: H2 session closed (HTTP download: MTProto transport error {expected})"
                )
            );
        }
        for (entry, expected) in entries[15..].iter().zip([
            "tgws: DC2 CF worker failed: HTTP 429",
            "tgws: DC3 test CF worker failed: HTTP 403",
            "tgws: DC2 CF WebSocket failed: HTTP 503",
            "tgws: DC203 CF WebSocket failed: HTTP 429",
        ]) {
            assert_eq!(entry["level"], "error");
            assert_eq!(entry["msg"], expected);
        }
    }
}
