use super::*;
use tokio::{
    io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream},
    time::advance,
};
use tokio_tungstenite::{
    tungstenite::protocol::{frame::coding::CloseCode, Role, WebSocketConfig},
    WebSocketStream,
};

async fn client() -> (WebSocketStream<Wire<DuplexStream>>, DuplexStream) {
    let (socket, peer) = duplex(8192);
    let wire = Wire::after_upgrade(socket);
    let config = WebSocketConfig::default()
        .read_buffer_size(8192)
        .max_frame_size(Some(MAX_WS_MESSAGE))
        .max_message_size(Some(MAX_WS_MESSAGE));
    (
        WebSocketStream::from_raw_socket(wire, Role::Client, Some(config)).await,
        peer,
    )
}

fn large_header(opcode: u8, len: usize) -> Vec<u8> {
    assert!(len >= 65536);
    let mut header = vec![opcode, 127];
    header.extend_from_slice(&(len as u64).to_be_bytes());
    header
}
async fn frame(peer: &mut DuplexStream, opcode: u8, len: usize, byte: u8) {
    peer.write_all(&large_header(opcode, len)).await.unwrap();
    let chunk = [byte; 8192];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len());
        peer.write_all(&chunk[..n]).await.unwrap();
        left -= n;
    }
}

#[tokio::test]
async fn fragmented_sixteen_mib_message_is_forwarded() {
    let limit = MAX_WS_MESSAGE;
    let (mut ws, mut peer) = client().await;
    let mut active = ws.get_ref().active();
    let sender = tokio::spawn(async move {
        frame(&mut peer, 2, 5 << 20, 1).await;
        frame(&mut peer, 128, 11 << 20, 2).await;
    });
    let msg = active.next(&mut ws).await.unwrap().unwrap().into_data();
    assert_eq!(msg.len(), limit);
    assert!(msg[..5 << 20].iter().all(|&b| b == 1));
    assert!(msg[5 << 20..].iter().all(|&b| b == 2));
    sender.await.unwrap();
}

#[tokio::test]
async fn pending_write_limit_bounds_automatic_pongs_on_a_blocked_socket() {
    let (mut ws, mut peer) = client().await;
    ws.get_mut().limit_pending_writes(512);
    let sender = tokio::spawn(async move {
        let mut ping = [0; 127];
        ping[..2].copy_from_slice(&[0x89, 125]);
        for _ in 0..128 {
            if peer.write_all(&ping).await.is_err() {
                break;
            }
        }
        peer
    });
    let error = timeout(
        Duration::from_secs(1),
        ws.get_ref().active().next_data(&mut ws),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        error.get_ref().and_then(|error| error.downcast_ref::<Error>()),
        Some(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidData
    ));
    drop(ws);
    let mut peer = sender.await.unwrap();
    let mut outgoing = Vec::new();
    peer.read_to_end(&mut outgoing).await.unwrap();
    assert_eq!(outgoing.len(), 8192);
}

#[test]
fn oversized_frames_and_messages_are_rejected_before_payload() {
    let mut a = Tracker::new();
    a.received(b"\x02").unwrap();
    a.received(&large_header(2, 9 << 20)[1..]).unwrap();
    let chunk = [0; 8192];
    for _ in 0..(9 << 20) / chunk.len() {
        a.received(&chunk).unwrap();
    }
    assert_eq!(
        a.received(&large_header(128, 7 * 1024 * 1024 + 1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let mut single = Tracker::new();
    assert_eq!(
        single
            .received(&large_header(130, MAX_WS_MESSAGE + 1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let mut control = Tracker::new();
    assert_eq!(
        control
            .received(&large_header(137, 1 << 20))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn simultaneous_large_messages_keep_independent_limits() {
    let mut jobs = tokio::task::JoinSet::new();
    for byte in [1, 2, 3] {
        jobs.spawn(async move {
            let (mut ws, mut peer) = client().await;
            let mut active = ws.get_ref().active();
            let send = frame(&mut peer, 130, 12 << 20, byte);
            let receive = active.next_data(&mut ws);
            let ((), received) = tokio::join!(send, receive);
            let received = received.unwrap().unwrap();
            assert_eq!(received.len(), 12 << 20);
            assert!(received.iter().all(|&b| b == byte));
            received
        });
    }
    // Keep all three results alive so the test covers 36 MiB delivered at once.
    let mut results = Vec::new();
    while let Some(result) = jobs.join_next().await {
        results.push(result.unwrap());
    }
    assert_eq!(results.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn completed_continuations_extend_active_idle_deadline() {
    let (mut ws, mut peer) = client().await;
    let mut active = ws.get_ref().active();
    let task = tokio::spawn(async move { active.next(&mut ws).await });
    tokio::task::yield_now().await;
    advance(IDLE - Duration::from_secs(1)).await;
    peer.write_all(&[2, 1, b'a']).await.unwrap();
    tokio::task::yield_now().await;
    advance(IDLE - Duration::from_secs(1)).await;
    assert!(!task.is_finished());
    peer.write_all(&[128, 1, b'b']).await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap().unwrap().into_data().as_ref(),
        b"ab"
    );
}

#[tokio::test]
async fn fragmented_utf8_text_delivers_original_bytes_and_rejects_invalid_encoding() {
    let (mut ws, mut peer) = client().await;
    let mut active = ws.get_ref().active();
    // Split one multibyte UTF-8 code point across the text and continuation frames.
    peer.write_all(&[1, 1, 0xd1, 128, 1, 0x91]).await.unwrap();
    assert_eq!(
        active.next_data(&mut ws).await.unwrap().unwrap().as_ref(),
        "ё".as_bytes()
    );
    peer.write_all(&[129, 1, 0xff]).await.unwrap();
    assert!(active.next_data(&mut ws).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn partial_wire_frame_and_blocked_write_expire_after_180_seconds() {
    let (mut ws, mut peer) = client().await;
    let mut active = ws.get_ref().active();
    let reader = tokio::spawn(async move { active.next(&mut ws).await });
    let writer = tokio::spawn(write(std::future::pending::<Result<(), Error>>()));
    tokio::task::yield_now().await;
    advance(IDLE - Duration::from_secs(1)).await;
    peer.write_all(&[130, 32, 1]).await.unwrap();
    tokio::task::yield_now().await;
    assert!(!reader.is_finished() && !writer.is_finished());
    advance(Duration::from_secs(1)).await;
    assert_eq!(
        reader.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        writer.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

fn reasonful_close(code: CloseCode, reason: &'static str) -> (CloseFrame, Vec<u8>, Vec<u8>) {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    let mut payload = u16::from(code).to_be_bytes().to_vec();
    payload.extend_from_slice(reason.as_bytes());
    let mut incoming = vec![0x88, payload.len() as u8];
    incoming.extend_from_slice(&payload);
    let mask = [7, 11, 17, 19];
    let mut outgoing = vec![0x88, 0x80 | payload.len() as u8];
    outgoing.extend_from_slice(&mask);
    outgoing.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    (frame, incoming, outgoing)
}

#[test]
fn peer_close_receipt_uses_first_complete_original_status() {
    let (frame, close, _) = reasonful_close(CloseCode::Protocol, "Protocol violation");
    let mut tracker = Tracker::new();
    tracker.received(b"\x89\x01!").unwrap();
    for byte in &close[..close.len() - 1] {
        tracker.received(&[*byte]).unwrap();
        assert!(!tracker.first_close.matches(&frame));
    }
    tracker.received(&close[close.len() - 1..]).unwrap();
    assert!(tracker.first_close.matches(&frame));

    let mut reserved = close.clone();
    reserved[2..4].copy_from_slice(&1005u16.to_be_bytes());
    reserved.extend_from_slice(&close);
    let mut tracker = Tracker::new();
    tracker.received(&reserved).unwrap();
    assert!(!tracker.first_close.matches(&frame));

    let mut tracker = Tracker::new();
    tracker.received(b"\x88\x00").unwrap();
    tracker.received(&close).unwrap();
    assert!(!tracker.first_close.matches(&frame));
}

#[tokio::test]
async fn terminal_peer_close_flushes_only_masked_status_across_short_writes() {
    let (frame, _, outgoing) = reasonful_close(CloseCode::Away, "пока");
    let (socket, mut peer) = duplex(3);
    let mut wire = Wire::after_upgrade(socket);
    wire.terminal_close = Some(TerminalClose::Expected(frame));
    timeout(Duration::from_secs(1), wire.write_all(&outgoing))
        .await
        .unwrap()
        .unwrap();
    let mut reply = [0; 8];
    let (flush, read) = timeout(Duration::from_secs(1), async {
        tokio::join!(wire.flush(), peer.read_exact(&mut reply))
    })
    .await
    .unwrap();
    flush.unwrap();
    read.unwrap();
    assert_eq!(reply[..2], [0x88, 0x82]);
    assert_eq!(reply[2..], outgoing[2..8]);
    assert_eq!(
        wire.write_all(&outgoing).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    drop(wire);
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn terminal_peer_close_rejects_queued_or_unproven_output_without_writing() {
    let (frame, _, outgoing) = reasonful_close(CloseCode::Away, "пока");
    let mut wrong_reason = outgoing.clone();
    *wrong_reason.last_mut().unwrap() ^= 1;
    for output in [
        [&b"\x8a\x81\x01\x02\x03\x04\x05"[..], outgoing.as_slice()].concat(),
        [&b"\x02\x03\x04\x05"[..], outgoing.as_slice()].concat(),
        outgoing[..outgoing.len() - 1].to_vec(),
        wrong_reason,
    ] {
        let (socket, mut peer) = duplex(256);
        let mut wire = Wire::after_upgrade(socket);
        wire.terminal_close = Some(TerminalClose::Expected(frame.clone()));
        assert_eq!(
            wire.write_all(&output).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            wire.flush().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(wire);
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }
}
