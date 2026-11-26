use std::{
    io::{self, Write},
    sync::{
        mpsc::{sync_channel, SyncSender},
        Arc,
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum H2Terminal {
    Http(u16),
    Payload(i32),
}

impl H2Terminal {
    pub fn code(self) -> i32 {
        match self {
            Self::Http(status) => -i32::from(status),
            Self::Payload(code) => code,
        }
    }

    fn write(self, mut output: impl Write) -> io::Result<()> {
        match self {
            Self::Http(status) => writeln!(output, "n2s-tgws-h2-transport-error-v1 http {status}"),
            Self::Payload(code) => {
                writeln!(output, "n2s-tgws-h2-transport-error-v1 payload {code}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WsLeg {
    ClientRead,
    UpstreamRead,
    ClientWrite,
    UpstreamWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WsCause {
    Eof,
    Timeout,
    Closed,
    Invalid,
    Io,
}

impl WsCause {
    pub fn from_io(error: Option<&io::Error>) -> Self {
        use tokio_tungstenite::tungstenite::Error as WsError;
        let error = match error.and_then(|error| error.get_ref()?.downcast_ref::<WsError>()) {
            Some(WsError::ConnectionClosed | WsError::AlreadyClosed) => return Self::Closed,
            Some(WsError::Io(inner)) => Some(inner),
            Some(WsError::Protocol(_) | WsError::Capacity(_) | WsError::Utf8(_)) => {
                return Self::Invalid
            }
            _ => error,
        };
        use io::ErrorKind::{
            BrokenPipe, ConnectionAborted, ConnectionReset, InvalidData, NotConnected, TimedOut,
            UnexpectedEof,
        };
        match error.map(io::Error::kind) {
            None | Some(UnexpectedEof) => Self::Eof,
            Some(TimedOut) => Self::Timeout,
            Some(BrokenPipe | ConnectionAborted | ConnectionReset | NotConnected) => Self::Closed,
            Some(InvalidData) => Self::Invalid,
            _ => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WsEnd {
    Flow(WsLeg, WsCause),
    Stopped,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub(super) struct WsTraffic {
    pub bytes: u64,
    pub units: u64,
}

impl WsTraffic {
    pub fn record(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        self.units = self.units.saturating_add(1);
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct WsSessionClosed {
    pub end: WsEnd,
    pub upload: WsTraffic,
    pub download: WsTraffic,
    pub tenths: u64,
}

impl WsSessionClosed {
    fn write(&self, mut output: impl Write) -> io::Result<()> {
        let (leg, cause) = match self.end {
            WsEnd::Flow(leg, cause) => (
                match leg {
                    WsLeg::ClientRead => "client-read",
                    WsLeg::UpstreamRead => "upstream-read",
                    WsLeg::ClientWrite => "client-write",
                    WsLeg::UpstreamWrite => "upstream-write",
                },
                match cause {
                    WsCause::Eof => "eof",
                    WsCause::Timeout => "timeout",
                    WsCause::Closed => "closed",
                    WsCause::Invalid => "invalid",
                    WsCause::Io => "io",
                },
            ),
            WsEnd::Stopped => ("stop", "shutdown"),
        };
        writeln!(
            output,
            "n2s-tgws-ws-close-v1 {leg} {cause} {} {} {} {} {}",
            self.upload.bytes,
            self.upload.units,
            self.download.bytes,
            self.download.units,
            self.tenths
        )
    }
}

#[derive(Clone, Debug)]
pub(super) struct Drain(Arc<tokio::sync::Notify>);

impl PartialEq for Drain {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Drain {}

pub(super) async fn drain(sender: &SyncSender<Event>) {
    let drain = Drain(Arc::new(tokio::sync::Notify::new()));
    if sender.try_send(Event::Drain(drain.clone())).is_ok() {
        let _ = tokio::time::timeout(Duration::from_millis(100), drain.0.notified()).await;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    Refill { dc: i16, seconds: u64 },
    RefillCapacity { dc: i16 },
    BadHandshake,
    NoFallback { dc: i16, test: bool },
    CatalogRefreshFailed,
    ListenerLost,
    ListenerRestored,
    H2Transport(H2Terminal),
    WsSessionClosed(WsSessionClosed),
    Drain(Drain),
    WorkerUpgradeRejected { dc: i16, test: bool, status: u16 },
    WebUpgradeRejected { dc: i16, status: u16 },
    TcpFallbackFailed { dc: i16, test: bool, seconds: u64 },
}

pub(super) fn start() -> Option<SyncSender<Event>> {
    let (send, receive) = sync_channel::<Event>(64);
    // A blocked or missing stderr reader must not hold the proxy runtime.
    std::thread::Builder::new()
        .name("tgws-diagnostics".into())
        .spawn(move || {
            for event in receive {
                let result = match event {
                    Event::Refill { dc, seconds } => {
                        let number = dc.unsigned_abs() % 10_000;
                        let media = dc < 0;
                        writeln!(
                            io::stderr(),
                            "n2s-tgws-refill-v1 {number} {media} {seconds}"
                        )
                    }
                    Event::RefillCapacity { dc } => {
                        let number = dc.unsigned_abs() % 10_000;
                        let media = dc < 0;
                        writeln!(io::stderr(), "n2s-tgws-refill-capacity-v1 {number} {media}")
                    }
                    Event::BadHandshake => writeln!(io::stderr(), "n2s-tgws-bad-handshake-v1"),
                    Event::NoFallback { dc, test } => {
                        let number = dc.unsigned_abs() % 10_000;
                        let media = dc < 0;
                        writeln!(
                            io::stderr(),
                            "n2s-tgws-no-fallback-v1 {number} {media} {test}"
                        )
                    }
                    Event::CatalogRefreshFailed => {
                        writeln!(io::stderr(), "n2s-tgws-catalog-refresh-failed-v1")
                    }
                    Event::ListenerLost => writeln!(io::stderr(), "n2s-tgws-listener-lost-v1"),
                    Event::ListenerRestored => {
                        writeln!(io::stderr(), "n2s-tgws-listener-restored-v1")
                    }
                    Event::H2Transport(terminal) => terminal.write(io::stderr()),
                    Event::WsSessionClosed(session) => session.write(io::stderr()),
                    Event::Drain(drain) => {
                        let result = io::stderr().flush();
                        drain.0.notify_one();
                        result
                    }
                    Event::WorkerUpgradeRejected { dc, test, status } => {
                        let number = dc.unsigned_abs() % 10_000;
                        writeln!(
                            io::stderr(),
                            "n2s-tgws-worker-upgrade-rejected-v1 {number} {test} {status}"
                        )
                    }
                    Event::WebUpgradeRejected { dc, status } => {
                        let number = dc.unsigned_abs();
                        writeln!(
                            io::stderr(),
                            "n2s-tgws-cf-web-upgrade-rejected-v1 {number} {status}"
                        )
                    }
                    Event::TcpFallbackFailed { dc, test, seconds } => {
                        let number = dc.unsigned_abs() % 10_000;
                        writeln!(
                            io::stderr(),
                            "n2s-tgws-tcp-fallback-failed-v1 {number} {test} {seconds}"
                        )
                    }
                };
                if result.is_err() {
                    break;
                }
            }
        })
        .ok()?;
    Some(send)
}

#[test]
fn h2_terminal_diagnostics_have_only_fixed_source_and_numeric_value() {
    for (terminal, expected) in [
        (H2Terminal::Http(403), "http 403"),
        (H2Terminal::Http(404), "http 404"),
        (H2Terminal::Http(429), "http 429"),
        (H2Terminal::Http(444), "http 444"),
        (H2Terminal::Payload(-404), "payload -404"),
        (H2Terminal::Payload(i32::MIN), "payload -2147483648"),
    ] {
        let mut line = Vec::new();
        terminal.write(&mut line).unwrap();
        assert_eq!(
            line,
            format!("n2s-tgws-h2-transport-error-v1 {expected}\n").as_bytes()
        );
        assert!(line.len() <= 80);
    }
}

#[tokio::test(start_paused = true)]
async fn diagnostics_drain_is_bounded_when_the_writer_cannot_respond() {
    let (sender, receiver) = sync_channel(1);
    let started = tokio::time::Instant::now();
    drain(&sender).await;
    assert_eq!(started.elapsed(), Duration::from_millis(100));
    assert!(matches!(receiver.try_recv().unwrap(), Event::Drain(_)));

    sender.try_send(Event::ListenerRestored).unwrap();
    let started = tokio::time::Instant::now();
    drain(&sender).await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(receiver.try_recv().unwrap(), Event::ListenerRestored);
}
