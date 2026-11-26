use crate::{
    crypto::{packet_len, Cipher, Transport},
    diagnostics::{Event, WsCause, WsEnd, WsLeg, WsSessionClosed, WsTraffic},
    pool::{Endpoint, Pool},
    Stats,
};
use ctr::cipher::StreamCipher;
use futures_util::{Sink, SinkExt, StreamExt};
use nfqws2_tgws_config::{fallback::connect_named, Config};
use nfqws2_tgws_transport::active::{self, Wire};
#[cfg(test)]
pub(super) use nfqws2_tgws_transport::tls_config;
pub(super) use nfqws2_tgws_transport::{configure_socket, upgrade, Ws};
use portable_atomic::AtomicU64;
use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader, ReadBuf,
    },
    net::TcpStream,
    sync::{Semaphore, SemaphorePermit},
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    tungstenite::{
        protocol::{
            frame::{
                coding::{Data, OpCode},
                Frame,
            },
            CloseFrame,
        },
        Message,
    },
    WebSocketStream,
};

const CLOSE_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
const UPLOAD_WORKSPACE: usize = 16 << 10;
const WORKER_UPLOAD_WORKSPACE: usize = 64 << 10;
const LEGACY_FRAME_SLOT_BYTES: usize = 128 << 10;
const LEGACY_SINGLE_FRAME: usize = 2 * LEGACY_FRAME_SLOT_BYTES;
const MASKED_DATA_HEADER: usize = 14;
const MASKED_CONTROL_FRAME: usize = 2 + 4 + 125;
// Each slot covers a bounded staging allocation and the WebSocket encoder's
// retained large-frame buffer. The active socket owns the slot until teardown.
static LEGACY_FRAME_SLOTS: Semaphore = Semaphore::const_new(4);

struct LegacyFrameBudget<'a> {
    slots: &'a Semaphore,
    held: Option<SemaphorePermit<'a>>,
    output_limit: Option<active::PendingWriteLimit>,
}

impl<'a> LegacyFrameBudget<'a> {
    fn new(slots: &'a Semaphore) -> Self {
        Self {
            slots,
            held: None,
            output_limit: None,
        }
    }

    fn admits(&mut self, length: usize) -> bool {
        if !(UPLOAD_WORKSPACE + 1..=LEGACY_SINGLE_FRAME).contains(&length) {
            return false;
        }
        let needed = length.div_ceil(LEGACY_FRAME_SLOT_BYTES);
        let held = self.held.as_ref().map_or(0, SemaphorePermit::num_permits);
        if needed <= held {
            return true;
        }
        let Ok(permit) = self.slots.try_acquire_many((needed - held) as u32) else {
            return false;
        };
        if let Some(remaining) = &mut self.held {
            remaining.merge(permit);
        } else {
            self.held = Some(permit);
        }
        if let Some(limit) = &self.output_limit {
            limit.increase_to(wire_output_limit(needed * LEGACY_FRAME_SLOT_BYTES));
        }
        true
    }

    fn worker_workspace(&self) -> usize {
        if self.held.is_some() {
            WORKER_UPLOAD_WORKSPACE
        } else {
            UPLOAD_WORKSPACE
        }
    }
}

fn wire_output_limit(payload: usize) -> usize {
    payload + MASKED_DATA_HEADER + 2 * MASKED_CONTROL_FRAME
}

enum PeerCloseReply {
    Short,
    Status(CloseFrame),
}

pub(super) async fn vpn_iface(path: &std::path::Path) -> io::Result<Option<String>> {
    #[cfg(unix)]
    {
        let mut out = Vec::with_capacity(16);
        timeout(Duration::from_secs(2), async {
            tokio::net::UnixStream::connect(path)
                .await?
                .take(16)
                .read_to_end(&mut out)
                .await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        let iface = String::from_utf8(out).map_err(io::Error::other)?;
        if iface.is_empty() {
            return Ok(None);
        }
        if nfqws2_tgws_config::fallback::valid_iface(&iface) {
            return Ok(Some(iface));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "некорректный ответ при выборе VPN",
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::ErrorKind::Unsupported.into())
    }
}
struct Connection {
    ws: Ws,
    reserve: Option<Endpoint>,
}

pub(super) fn ws_domains(dc: i16) -> Vec<String> {
    let number = dc.unsigned_abs() % 10000;
    let number = if number == 203 { 2 } else { number };
    let main = format!("kws{number}.web.telegram.org");
    if dc < 0 {
        vec![format!("kws{number}-1.web.telegram.org"), main]
    } else {
        vec![main]
    }
}

fn can_reserve(ip: Option<IpAddr>) -> bool {
    ip.is_none_or(|ip| {
        ip.to_canonical() == IpAddr::from([149, 154, 167, 220])
            || nfqws2_tgws_config::fallback::Telegram::address(ip, 443).is_some()
    })
}
#[test]
fn only_stock_routes_can_request_idle_dials() {
    assert!(can_reserve(None));
    for ip in [
        "149.154.167.220",
        "::ffff:149.154.167.220",
        "149.154.174.100",
    ] {
        assert!(can_reserve(Some(ip.parse().unwrap())));
    }
    for ip in ["127.0.0.1", "192.0.2.2", "::1"] {
        assert!(!can_reserve(Some(ip.parse().unwrap())));
    }
}

async fn connect(
    tls: &crate::direct::Direct,
    dc: i16,
    ip: Option<IpAddr>,
    cfg: &Config,
    broker: Option<&std::path::Path>,
) -> io::Result<(Connection, bool)> {
    let number = dc.unsigned_abs();
    let test = cfg.force_test_dc || number >= 10000;
    let path = if test { "/apiws_test" } else { "/apiws" };
    let names = ws_domains(dc);
    let direct = async {
        for domain in &names {
            let socket = |deadline| async move {
                match ip {
                    Some(ip) => TcpStream::connect((ip, 443)).await,
                    None => connect_named(domain, 443, deadline).await,
                }
            };
            if let Ok(ws) = tls.dial(domain, path, cfg.buffer_size, ip, socket).await {
                let reserve = if cfg.pool_size > 0 && can_reserve(ip) {
                    nfqws2_tgws_transport::socket(&ws)
                        .peer_addr()
                        .ok()
                        .map(|peer| Endpoint {
                            peer: crate::pool::Peer::Direct(peer),
                            managed: ip.is_some(),
                            host: domain.clone(),
                            path,
                        })
                } else {
                    None
                };
                return Ok(Connection { ws, reserve });
            }
        }
        Err(io::Error::other(
            "не удалось установить защищённое соединение с Telegram",
        ))
    }
    .await;
    nfqws2_tgws_config::fallback::after_direct(
        direct,
        nfqws2_tgws_config::fallback::Telegram::web(dc, test),
        |endpoint| async move {
            let Some(broker) = broker else {
                return Ok(None);
            };
            let Some(iface) = vpn_iface(broker).await? else {
                return Ok(None);
            };
            for domain in names {
                if let Ok(ws) = tls
                    .dial(&domain, path, cfg.buffer_size, None, |_| {
                        endpoint.connect(&iface)
                    })
                    .await
                {
                    return Ok(Some(Connection { ws, reserve: None }));
                }
            }
            Err(io::Error::other(
                "не удалось установить защищённое соединение с Telegram через выбранный VPN",
            ))
        },
    )
    .await
}

async fn read_traffic(
    source: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
    counter: &AtomicU64,
) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = source.read(&mut buffer[filled..]).await?;
        if read == 0 {
            break;
        }
        counter.fetch_add(read as u64, Ordering::Relaxed);
        filled += read;
    }
    Ok(filled)
}

async fn upload<S>(
    mut source: impl AsyncRead + Unpin,
    mut sink: S,
    tag: u8,
    (mut from, mut to): (Cipher, Cipher),
    (stats, writing): (&Stats, &UpstreamWrite),
    mode: BridgeMode,
    staging: &mut LegacyFrameBudget<'_>,
) -> io::Result<()>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    // Each MTProto packet is one logical WebSocket message. Legacy can stage
    // a bounded packet for Go's single frame when the shared budget permits.
    // The traffic counter includes any bytes read before EOF or a write error.
    if mode == BridgeMode::LegacyWorker {
        let buffer = vec![0; staging.worker_workspace()];
        return upload_unframed(source, sink, (from, to), stats, writing, buffer).await;
    }
    let mut buffer = vec![0; UPLOAD_WORKSPACE];
    loop {
        let first = if tag == 0xef { 1 } else { 4 };
        let n = source.read(&mut buffer[..first]).await?;
        if n == 0 {
            return Ok(());
        }
        stats.up.fetch_add(n as u64, Ordering::Relaxed);
        let n = n + read_traffic(&mut source, &mut buffer[n..first], &stats.up).await?;
        if n < first {
            return finish_partial_packet(
                &mut sink,
                Data::Binary,
                &mut buffer[..n],
                0,
                (&mut from, &mut to),
                writing,
                mode,
            )
            .await;
        }
        from.apply_keystream(&mut buffer[..first]);
        let mut header = first;
        if tag == 0xef && buffer[0] & 127 == 127 {
            let n = 1 + read_traffic(&mut source, &mut buffer[1..4], &stats.up).await?;
            if n < 4 {
                return finish_partial_packet(
                    &mut sink,
                    Data::Binary,
                    &mut buffer[..n],
                    1,
                    (&mut from, &mut to),
                    writing,
                    mode,
                )
                .await;
            }
            from.apply_keystream(&mut buffer[1..4]);
            header = 4;
        }
        if mode == BridgeMode::Legacy && zero_length_header(&buffer[..header], tag) {
            // Go's splitter stops parsing after a zero-length packet shape.
            // Its current header is already decrypted. Forward it once and
            // continue with the same two ciphers using bounded raw reads.
            to.apply_keystream(&mut buffer[..header]);
            send_data(
                &mut sink,
                Message::binary(buffer[..header].to_vec()),
                writing,
            )
            .await?;
            return upload_unframed(source, sink, (from, to), stats, writing, buffer).await;
        }
        let mut remain = packet_len(&buffer[..header], tag)?;
        if mode == BridgeMode::Legacy && staging.admits(header + remain) {
            let complete = upload_staged_packet(
                &mut source,
                &mut sink,
                &buffer[..header],
                remain,
                (&mut from, &mut to),
                (stats, writing),
            )
            .await?;
            if complete {
                continue;
            }
            return Ok(());
        }
        let mut code = Data::Binary;
        while remain > 0 {
            let n = (buffer.len() - header).min(remain);
            let len = header + n;
            let read = read_traffic(&mut source, &mut buffer[header..len], &stats.up).await?;
            if read < n {
                return finish_partial_packet(
                    &mut sink,
                    code,
                    &mut buffer[..header + read],
                    header,
                    (&mut from, &mut to),
                    writing,
                    mode,
                )
                .await;
            }
            from.apply_keystream(&mut buffer[header..len]);
            to.apply_keystream(&mut buffer[..len]);
            remain -= n;
            let frame = Frame::message(buffer[..len].to_vec(), OpCode::Data(code), remain == 0);
            send_data(&mut sink, Message::Frame(frame), writing).await?;
            code = Data::Continue;
            header = 0;
        }
    }
}

async fn upload_staged_packet(
    source: &mut (impl AsyncRead + Unpin),
    sink: &mut (impl Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    header: &[u8],
    body_length: usize,
    (decrypt, encrypt): (&mut Cipher, &mut Cipher),
    (stats, writing): (&Stats, &UpstreamWrite),
) -> io::Result<bool> {
    let mut packet = vec![0; header.len() + body_length];
    packet[..header.len()].copy_from_slice(header);
    let read = read_traffic(source, &mut packet[header.len()..], &stats.up).await?;
    packet.truncate(header.len() + read);
    decrypt.apply_keystream(&mut packet[header.len()..]);
    encrypt.apply_keystream(&mut packet);
    let frame = Frame::message(packet, OpCode::Data(Data::Binary), true);
    let result = send_data(sink, Message::Frame(frame), writing).await;
    if read == body_length {
        result.map(|()| true)
    } else {
        result
            .map(|()| false)
            .map_err(|_| io::ErrorKind::UnexpectedEof.into())
    }
}

fn zero_length_header(header: &[u8], tag: u8) -> bool {
    match (tag, header) {
        (0xef, [flag]) => flag & 0x7f == 0,
        (0xef, [0x7f | 0xff, 0, 0, 0]) => true,
        (0xee | 0xdd, [0, 0, 0, flag]) => flag & 0x7f == 0,
        _ => false,
    }
}

async fn upload_unframed(
    mut source: impl AsyncRead + Unpin,
    mut sink: impl Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    (mut from, mut to): (Cipher, Cipher),
    stats: &Stats,
    writing: &UpstreamWrite,
    mut buffer: Vec<u8>,
) -> io::Result<()> {
    loop {
        let n = source.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        stats.up.fetch_add(n as u64, Ordering::Relaxed);
        from.apply_keystream(&mut buffer[..n]);
        to.apply_keystream(&mut buffer[..n]);
        send_data(&mut sink, Message::binary(buffer[..n].to_vec()), writing).await?;
    }
}

async fn finish_partial_packet(
    sink: &mut (impl Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    opcode: Data,
    bytes: &mut [u8],
    clear_prefix: usize,
    (decrypt, encrypt): (&mut Cipher, &mut Cipher),
    writing: &UpstreamWrite,
    mode: BridgeMode,
) -> io::Result<()> {
    if mode != BridgeMode::Legacy {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    // The leading bytes may already have been decoded to inspect the header.
    // Finish the same logical binary message using the current opcode, even
    // when EOF at a fragment boundary leaves an empty final continuation.
    decrypt.apply_keystream(&mut bytes[clear_prefix..]);
    encrypt.apply_keystream(bytes);
    let frame = Frame::message(bytes.to_vec(), OpCode::Data(opcode), true);
    send_data(sink, Message::Frame(frame), writing)
        .await
        .map_err(|_| io::ErrorKind::UnexpectedEof.into())
}

#[derive(Default)]
struct UpstreamWrite {
    in_progress: AtomicBool,
    failed: AtomicBool,
}

async fn send_data(
    sink: &mut (impl Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    message: Message,
    writing: &UpstreamWrite,
) -> io::Result<()> {
    writing.in_progress.store(true, Ordering::Relaxed);
    let result = active::write(sink.send(message)).await;
    if result.is_err() {
        writing.failed.store(true, Ordering::Relaxed);
    }
    writing.in_progress.store(false, Ordering::Relaxed);
    result
}

#[tokio::test]
async fn upload_counts_read_bytes_before_eof_and_websocket_write_failure() {
    use crate::crypto::client_fixture;
    use futures_util::sink;
    use tokio_tungstenite::tungstenite::Error;

    let plaintext = b"\x04\0\0\0test";
    for (length, expected) in [
        (2, io::ErrorKind::UnexpectedEof),
        (6, io::ErrorKind::UnexpectedEof),
        (plaintext.len(), io::ErrorKind::Other),
    ] {
        let key = [1; 16];
        let (init, mut encrypt, _) = client_fixture(&key, 2, 0xee);
        let session = Transport::client(init, &key).unwrap();
        let mut bytes = plaintext[..length].to_vec();
        encrypt.apply_keystream(&mut bytes);
        let disconnected = sink::unfold((), |(), _: Message| {
            std::future::ready(Err::<(), _>(Error::ConnectionClosed))
        });
        let stats = Stats::default();
        let error = upload(
            bytes.as_slice(),
            disconnected,
            session.tag,
            (session.client_in, session.server_out),
            (&stats, &UpstreamWrite::default()),
            BridgeMode::Native,
            &mut LegacyFrameBudget::new(&Semaphore::new(0)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), expected);
        assert_eq!(stats.up.load(Ordering::Relaxed), length as u64);
    }
}

#[tokio::test]
async fn upload_preserves_eof_after_failed_tail_or_native_fragment() {
    use crate::crypto::client_fixture;
    use futures_util::sink;
    use std::sync::Mutex;
    use tokio_tungstenite::tungstenite::Error;

    let mut large = 32768u32.to_le_bytes().to_vec();
    large.resize(16384 + 9, 42);
    let first_fragment = (OpCode::Data(Data::Binary), false, 16384);
    for (mut payload, mode, fail_at, expected) in [
        (
            b"\x04\0\0\0x".to_vec(),
            BridgeMode::Legacy,
            Some(0),
            vec![(OpCode::Data(Data::Binary), true, 5)],
        ),
        (
            large.clone(),
            BridgeMode::Legacy,
            Some(1),
            vec![first_fragment, (OpCode::Data(Data::Continue), true, 9)],
        ),
        (large, BridgeMode::Native, None, vec![first_fragment]),
    ] {
        let key = [2; 16];
        let (init, mut encrypt, _) = client_fixture(&key, 2, 0xee);
        let session = Transport::client(init, &key).unwrap();
        encrypt.apply_keystream(&mut payload);

        let writes = Arc::new(Mutex::new(Vec::new()));
        let upstream = sink::unfold(writes.clone(), move |writes, message: Message| {
            let index = {
                let mut messages = writes.lock().unwrap();
                let index = messages.len();
                messages.push(message);
                index
            };
            std::future::ready(if fail_at == Some(index) {
                Err(Error::ConnectionClosed)
            } else {
                Ok(writes)
            })
        });
        let stats = Stats::default();
        let error = upload(
            payload.as_slice(),
            upstream,
            session.tag,
            (session.client_in, session.server_out),
            (&stats, &UpstreamWrite::default()),
            mode,
            &mut LegacyFrameBudget::new(&Semaphore::new(0)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(stats.up.load(Ordering::Relaxed), payload.len() as u64);
        let sent: Vec<_> = writes
            .lock()
            .unwrap()
            .iter()
            .map(|message| {
                let Message::Frame(frame) = message else {
                    panic!("expected an application data frame")
                };
                (
                    frame.header().opcode,
                    frame.header().is_final,
                    frame.payload().len(),
                )
            })
            .collect();
        assert_eq!(sent, expected);
    }
}

#[tokio::test]
async fn legacy_upload_holds_staging_quota_until_its_websocket_is_gone() {
    use crate::crypto::client_fixture;
    use futures_util::sink;
    use std::sync::Mutex;

    async fn upload_fixture(
        staging: &mut LegacyFrameBudget<'_>,
        body: u32,
    ) -> Vec<(OpCode, bool, usize)> {
        let key = [43; 16];
        let (init, mut encrypt, _) = client_fixture(&key, 2, 0xee);
        let session = Transport::client(init, &key).unwrap();
        let mut packet = body.to_le_bytes().to_vec();
        packet.resize(body as usize + 4, 42);
        encrypt.apply_keystream(&mut packet);
        let saved = Arc::new(Mutex::new(Vec::new()));
        let upstream = sink::unfold(saved.clone(), |saved, message: Message| {
            let Message::Frame(frame) = message else {
                panic!("expected framed upload");
            };
            saved.lock().unwrap().push((
                frame.header().opcode,
                frame.header().is_final,
                frame.payload().len(),
            ));
            std::future::ready(Ok(saved))
        });
        let stats = Stats::default();
        upload(
            packet.as_slice(),
            upstream,
            session.tag,
            (session.client_in, session.server_out),
            (&stats, &UpstreamWrite::default()),
            BridgeMode::Legacy,
            staging,
        )
        .await
        .unwrap();
        assert_eq!(stats.up.load(Ordering::Relaxed), packet.len() as u64);
        Arc::try_unwrap(saved).unwrap().into_inner().unwrap()
    }

    let slots = Semaphore::new(1);
    let mut first = LegacyFrameBudget::new(&slots);
    let mut second = LegacyFrameBudget::new(&slots);
    let whole = [(OpCode::Data(Data::Binary), true, 70_004)];
    assert_eq!(upload_fixture(&mut first, 70_000).await, whole);
    assert_eq!(slots.available_permits(), 0);

    let fragments = upload_fixture(&mut second, 70_000).await;
    assert_eq!(
        fragments[0],
        (OpCode::Data(Data::Binary), false, UPLOAD_WORKSPACE)
    );
    assert_eq!(
        fragments.last(),
        Some(&(OpCode::Data(Data::Continue), true, 4_468))
    );
    assert_eq!(
        fragments.iter().map(|(_, _, bytes)| bytes).sum::<usize>(),
        70_004
    );

    drop(first);
    assert_eq!(slots.available_permits(), 1);
    assert_eq!(upload_fixture(&mut second, 70_000).await, whole);

    let slots = Semaphore::new(2);
    let mut large = LegacyFrameBudget::new(&slots);
    let mut other = LegacyFrameBudget::new(&slots);
    assert_eq!(upload_fixture(&mut large, 70_000).await, whole);
    let blocked = slots.try_acquire().unwrap();
    let body = (LEGACY_SINGLE_FRAME - 4) as u32;
    let fragments = upload_fixture(&mut large, body).await;
    assert_eq!(
        fragments.first(),
        Some(&(OpCode::Data(Data::Binary), false, UPLOAD_WORKSPACE))
    );
    assert_eq!(
        fragments.last(),
        Some(&(OpCode::Data(Data::Continue), true, UPLOAD_WORKSPACE))
    );
    assert_eq!(
        fragments.iter().map(|(_, _, bytes)| bytes).sum::<usize>(),
        LEGACY_SINGLE_FRAME
    );
    drop(blocked);
    // The earlier frame still owns one permit. Another socket can't take
    // a partial grant while this socket can grow its existing reservation.
    assert!(!other.admits(LEGACY_SINGLE_FRAME));
    assert_eq!(slots.available_permits(), 1);
    assert_eq!(
        upload_fixture(&mut large, body).await,
        [(OpCode::Data(Data::Binary), true, LEGACY_SINGLE_FRAME)]
    );
    assert_eq!(slots.available_permits(), 0);
    assert!(!large.admits(LEGACY_SINGLE_FRAME + 1));
    drop(large);
    assert_eq!(slots.available_permits(), 2);
}

#[tokio::test]
async fn legacy_websocket_resumes_as_bounded_raw_stream_after_zero_length_header() {
    use crate::crypto::{client_fixture, upstream_fixture};
    use futures_util::sink;
    use std::sync::Mutex;

    for (tag, zero) in [
        (0xef, &b"\0"[..]),
        (0xef, &b"\x80"[..]),
        (0xef, &b"\xff\0\0\0"[..]),
        (0xee, &b"\0\0\0\x80"[..]),
        (0xdd, &b"\0\0\0\0"[..]),
    ] {
        let framed = if tag == 0xef {
            &b"\x01test"[..]
        } else {
            &b"\x04\0\0\0test"[..]
        };
        let mut plaintext = [framed, zero, &[0xff; 4]].concat();
        plaintext.extend(std::iter::repeat_n(0x5a, 32768 + 7));
        for mode in [BridgeMode::Legacy, BridgeMode::Native] {
            let key = [41; 16];
            let (init, mut encrypt, _) = client_fixture(&key, 2, tag);
            let session = Transport::client(init, &key).unwrap();
            let (_, _, mut decrypt, _) = upstream_fixture(session.init);
            let mut ciphertext = plaintext.clone();
            encrypt.apply_keystream(&mut ciphertext);
            let writes = Arc::new(Mutex::new(Vec::new()));
            let upstream = sink::unfold(writes.clone(), |writes, message: Message| {
                writes.lock().unwrap().push(message);
                std::future::ready(Ok(writes))
            });
            let stats = Stats::default();
            let result = upload(
                ciphertext.as_slice(),
                upstream,
                session.tag,
                (session.client_in, session.server_out),
                (&stats, &UpstreamWrite::default()),
                mode,
                &mut LegacyFrameBudget::new(&Semaphore::new(0)),
            )
            .await;

            let writes = writes.lock().unwrap();
            let Message::Frame(first) = &writes[0] else {
                panic!("the packet preceding the zero header must stay framed");
            };
            assert_eq!(first.header().opcode, OpCode::Data(Data::Binary));
            assert!(first.header().is_final);
            let mut relayed = first.payload().to_vec();
            assert_eq!(relayed.len(), framed.len());
            if mode == BridgeMode::Legacy {
                result.unwrap();
                assert_eq!(stats.up.load(Ordering::Relaxed), plaintext.len() as u64);
                for message in &writes[1..] {
                    let Message::Binary(bytes) = message else {
                        panic!("the zero header and all following bytes must use raw chunks");
                    };
                    assert!((1..=16384).contains(&bytes.len()));
                    relayed.extend_from_slice(bytes);
                }
                decrypt.apply_keystream(&mut relayed);
                assert_eq!(relayed, plaintext);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert_eq!(writes.len(), 1);
                assert_eq!(
                    stats.up.load(Ordering::Relaxed),
                    (framed.len() + zero.len()) as u64
                );
            }
        }
    }
}

#[tokio::test]
async fn legacy_websocket_still_rejects_an_oversize_framed_header() {
    use crate::crypto::client_fixture;
    use futures_util::sink;
    use tokio_tungstenite::tungstenite::Error;

    let key = [42; 16];
    let (init, mut encrypt, _) = client_fixture(&key, 2, 0xee);
    let session = Transport::client(init, &key).unwrap();
    let size = (nfqws2_tgws_transport::MAX_PACKET + 1) as u32;
    let mut oversized = size.to_le_bytes();
    encrypt.apply_keystream(&mut oversized);
    let upstream = sink::unfold(
        (),
        |(), _: Message| -> std::future::Ready<Result<(), Error>> {
            panic!("oversize packet must fail before sending a frame")
        },
    );
    let stats = Stats::default();
    let error = upload(
        oversized.as_slice(),
        upstream,
        session.tag,
        (session.client_in, session.server_out),
        (&stats, &UpstreamWrite::default()),
        BridgeMode::Legacy,
        &mut LegacyFrameBudget::new(&Semaphore::new(0)),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(stats.up.load(Ordering::Relaxed), 4);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BridgeMode {
    Native,
    Legacy,
    LegacyWorker,
}

struct SessionReport<'a> {
    pool: &'a Pool,
    first: Mutex<Option<WsEnd>>,
    started: Instant,
    upload: WsTraffic,
    download: WsTraffic,
}

impl Drop for SessionReport<'_> {
    fn drop(&mut self) {
        let end = (*self.first.get_mut().unwrap())
            .or_else(|| self.pool.is_planned_stop().then_some(WsEnd::Stopped));
        if let Some(end) = end {
            let tenths = (self.started.elapsed().as_millis().saturating_add(50) / 100)
                .try_into()
                .unwrap_or(u64::MAX);
            self.pool
                .report_diagnostic(Event::WsSessionClosed(WsSessionClosed {
                    end,
                    upload: self.upload,
                    download: self.download,
                    tenths,
                }));
        }
    }
}

fn first_end(first: Option<&Mutex<Option<WsEnd>>>, leg: WsLeg, error: Option<&io::Error>) {
    if let Some(first) = first {
        first
            .lock()
            .unwrap()
            .get_or_insert_with(|| WsEnd::Flow(leg, WsCause::from_io(error)));
    }
}

struct CountedRead<'a, R> {
    source: R,
    first: Option<&'a Mutex<Option<WsEnd>>>,
    traffic: Option<&'a mut WsTraffic>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountedRead<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let can_read = buf.remaining() != 0;
        let outcome = std::task::ready!(Pin::new(&mut self.source).poll_read(cx, buf));
        match &outcome {
            Ok(()) if buf.filled().len() > before => {
                if let Some(traffic) = &mut self.traffic {
                    traffic.record(buf.filled().len() - before);
                }
            }
            Ok(()) if can_read => first_end(self.first, WsLeg::ClientRead, None),
            Err(error) => first_end(self.first, WsLeg::ClientRead, Some(error)),
            _ => (),
        }
        Poll::Ready(outcome)
    }
}

pub(super) async fn bridge(
    tcp: impl AsyncRead + AsyncWrite + Unpin,
    mut ws: Ws,
    session: Transport,
    stats: &Stats,
    mode: BridgeMode,
    reporter: Option<&Pool>,
) -> io::Result<()> {
    active::write(ws.send(Message::binary(session.init.to_vec()))).await?;
    bridge_initialized(tcp, ws, session, stats, mode, reporter).await
}
pub(super) async fn bridge_initialized(
    tcp: impl AsyncRead + AsyncWrite + Unpin,
    ws: WebSocketStream<Wire<impl AsyncBufRead + AsyncWrite + Unpin>>,
    session: Transport,
    stats: &Stats,
    mode: BridgeMode,
    reporter: Option<&Pool>,
) -> io::Result<()> {
    bridge_with_frame_slots(tcp, ws, session, stats, mode, reporter, &LEGACY_FRAME_SLOTS).await
}

pub(super) async fn bridge_with_frame_slots(
    tcp: impl AsyncRead + AsyncWrite + Unpin,
    mut ws: WebSocketStream<Wire<impl AsyncBufRead + AsyncWrite + Unpin>>,
    mut session: Transport,
    stats: &Stats,
    mode: BridgeMode,
    reporter: Option<&Pool>,
    frame_slots: &Semaphore,
) -> io::Result<()> {
    let mut report = reporter
        .filter(|_| mode != BridgeMode::Native)
        .map(|pool| SessionReport {
            pool,
            first: Mutex::new(None),
            started: Instant::now(),
            upload: WsTraffic::default(),
            download: WsTraffic::default(),
        });
    let (first, upload_traffic, mut download_traffic) = match &mut report {
        Some(report) => (
            Some(&report.first),
            Some(&mut report.upload),
            Some(&mut report.download),
        ),
        None => (None, None, None),
    };
    // Tungstenite keeps its frame buffer capacity even after flushing. Drop
    // the budget after both WebSocket halves, including the terminal flush.
    let mut staging = LegacyFrameBudget::new(frame_slots);
    // A blocked codec can queue controls between application writes. Keep
    // the pending output bound at the session's total admitted frame size.
    match mode {
        BridgeMode::Native => (),
        BridgeMode::Legacy => {
            staging.output_limit = Some(
                ws.get_mut()
                    .limit_pending_writes(wire_output_limit(UPLOAD_WORKSPACE)),
            );
        }
        BridgeMode::LegacyWorker => {
            staging.admits(WORKER_UPLOAD_WORKSPACE);
            ws.get_mut()
                .limit_pending_writes(wire_output_limit(staging.worker_workspace()));
        }
    }
    let (from, mut to) = tokio::io::split(tcp);
    let mut active = ws.get_ref().active();
    let (mut sink, mut incoming) = ws.split();
    let writing = UpstreamWrite::default();
    let mut acknowledge = None;
    let mut client_write_failed = false;
    let down = async {
        let mut buffer = vec![0; 16384];
        {
            let mut messages = incoming.by_ref().inspect(|message| {
                if mode != BridgeMode::Native {
                    if let Ok(Message::Close(frame)) = message {
                        acknowledge = match frame {
                            None => Some(PeerCloseReply::Short),
                            Some(frame) if !frame.code.is_allowed() => None,
                            Some(frame) if frame.reason.is_empty() => Some(PeerCloseReply::Short),
                            Some(frame) => Some(PeerCloseReply::Status(frame.clone())),
                        };
                    }
                }
            });
            while let Some(message) =
                active.next_data(&mut messages).await.inspect_err(|error| {
                    first_end(first, WsLeg::UpstreamRead, Some(error));
                })?
            {
                stats
                    .down
                    .fetch_add(message.len() as u64, Ordering::Relaxed);
                if let Some(traffic) = &mut download_traffic {
                    traffic.record(message.len());
                }
                // RFC 6455 messages can contain several MTProto packets.
                // Re-encrypt incrementally without another message-sized allocation.
                for chunk in message.chunks(buffer.len()) {
                    let bytes = &mut buffer[..chunk.len()];
                    bytes.copy_from_slice(chunk);
                    session.server_in.apply_keystream(bytes);
                    session.client_out.apply_keystream(bytes);
                    to.write_all(bytes).await.inspect_err(|error| {
                        client_write_failed = true;
                        first_end(first, WsLeg::ClientWrite, Some(error));
                    })?;
                }
            }
        }
        first_end(first, WsLeg::UpstreamRead, None);
        if acknowledge.is_some() {
            // Drop the upload future before flushing the queued Close reply.
            Ok(())
        } else {
            to.shutdown().await
        }
    };
    let (result, client_finished) = {
        let up = async {
            let result = upload(
                CountedRead {
                    source: from,
                    first,
                    traffic: upload_traffic,
                },
                &mut sink,
                session.tag,
                (session.client_in, session.server_out),
                (stats, &writing),
                mode,
                &mut staging,
            )
            .await;
            let leg = if writing.failed.load(Ordering::Relaxed) {
                WsLeg::UpstreamWrite
            } else {
                WsLeg::ClientRead
            };
            first_end(first, leg, result.as_ref().err());
            result
        };
        tokio::select! {
            res = up => (res, true),
            res = down => (res, false),
        }
    };
    if let (false, Some(reply)) = (client_finished, acknowledge) {
        match (!writing.in_progress.load(Ordering::Relaxed), reply) {
            (true, PeerCloseReply::Short) => {
                let _ = timeout(CLOSE_WRITE_TIMEOUT, sink.flush()).await;
                drop((sink, incoming));
            }
            (true, PeerCloseReply::Status(frame)) => {
                if let Ok(ws) = sink.reunite(incoming) {
                    let _ = timeout(
                        CLOSE_WRITE_TIMEOUT,
                        active::reply_peer_close_status(ws, frame),
                    )
                    .await;
                }
            }
            (false, _) => drop((sink, incoming)),
        }
        return to.shutdown().await;
    }
    let client_eof = client_finished && result.is_ok();
    if mode != BridgeMode::Native
        && (client_eof || client_write_failed)
        && !writing.in_progress.load(Ordering::Relaxed)
    {
        // Finish the active WebSocket without waiting on a peer reply or
        // replacing the original client I/O result.
        let _ = timeout(CLOSE_WRITE_TIMEOUT, sink.close()).await;
    }
    if client_eof && mode != BridgeMode::LegacyWorker {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    result
}
struct Active(Arc<Stats>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}
pub(super) async fn proxy_line(mut reader: impl AsyncBufRead + Unpin) -> io::Result<()> {
    let mut line = Vec::with_capacity(64);
    (&mut reader).take(107).read_until(b'\n', &mut line).await?;
    if line.starts_with(b"PROXY ") && line.ends_with(b"\r\n") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PROXY v1 header",
        ))
    }
}
pub(super) async fn read_init(
    stream: &mut (impl AsyncRead + Unpin),
    proxy_protocol: bool,
) -> io::Result<[u8; 64]> {
    let mut init = [0; 64];
    let mut used = 0;
    if proxy_protocol {
        // Limit read-ahead to one handshake so subsequent payload stays in the socket.
        let mut reader = BufReader::with_capacity(init.len(), &mut *stream);
        proxy_line(&mut reader).await?;
        let ahead = reader.buffer();
        used = ahead.len();
        init[..used].copy_from_slice(ahead);
    }
    stream.read_exact(&mut init[used..]).await?;
    Ok(init)
}
pub(super) async fn client(
    tcp: TcpStream,
    cfg: Arc<Config>,
    stats: Arc<Stats>,
    broker: Option<Arc<std::path::Path>>,
    pool: Arc<Pool>,
) {
    stats.total.fetch_add(1, Ordering::Relaxed);
    configure_socket(&tcp, cfg.buffer_size);
    stats.active.fetch_add(1, Ordering::Relaxed);
    let _active = Active(stats.clone());
    let handshake = crate::inbound::receive(tcp, &cfg);
    let (tcp, session, pump) = match timeout(Duration::from_secs(10), handshake).await {
        Ok(Ok(crate::inbound::Handshake::Session { io, session, pump })) => (io, *session, pump),
        Ok(Ok(crate::inbound::Handshake::Redirected)) => return,
        Ok(Ok(crate::inbound::Handshake::Https(client, hello))) => {
            stats.masked.fetch_add(1, Ordering::Relaxed);
            let _ = pool.https_origin.serve(client, &hello).await;
            return;
        }
        Ok(Ok(crate::inbound::Handshake::Rejected)) => {
            stats.bad.fetch_add(1, Ordering::Relaxed);
            pool.report_diagnostic(crate::diagnostics::Event::BadHandshake);
            return;
        }
        // Go counts only a complete MTProto header with a bad secret or
        // protocol. EOF, timeouts and malformed PROXY or HTTPS headers do not.
        Ok(Err(_)) | Err(_) => return,
    };
    authenticated(tcp, session, &cfg, &stats, &pool, broker.as_deref()).await;
    if let Some(pump) = pump {
        pump.finish().await;
    }
}
async fn authenticated(
    tcp: impl AsyncRead + AsyncWrite + Unpin,
    session: Transport,
    cfg: &Config,
    stats: &Stats,
    pool: &Pool,
    broker: Option<&std::path::Path>,
) {
    if cfg.transport.is_empty() {
        let _ = crate::legacy::serve(tcp, session, cfg, pool, stats, broker).await;
        return;
    }
    let dc = i32::from(session.dc.unsigned_abs()) % 10000;
    let ip = cfg.dc_redirects.as_ref().and_then(|m| m.get(&dc)).copied();
    let cached = if cfg.pool_size > 0 && can_reserve(ip) {
        pool.take(session.dc, stats).await
    } else {
        None
    };
    let connection = match cached {
        Some((ws, endpoint)) => {
            configure_socket(nfqws2_tgws_transport::socket(&ws), cfg.buffer_size);
            Ok((
                Connection {
                    ws,
                    reserve: Some(endpoint),
                },
                false,
            ))
        }
        None => connect(&pool.direct, session.dc, ip, cfg, broker).await,
    };
    match connection {
        Ok((Connection { ws, reserve }, vpn)) => {
            if let Some(endpoint) = reserve {
                pool.warm(session.dc, endpoint);
            }
            stats.ws.fetch_add(1, Ordering::Relaxed);
            stats.vpn.fetch_add(u64::from(vpn), Ordering::Relaxed);
            let _ = bridge(tcp, ws, session, stats, BridgeMode::Native, None).await;
        }
        Err(_) if cfg.configured_tls_relays() => {
            if crate::legacy::fallback(tcp, session, cfg, pool, stats)
                .await
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(_) => {
            stats.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}
