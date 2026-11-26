use super::*;

#[test]
fn only_complete_http11_upgrade_declines_carry_a_typed_status() {
    for (response, expected) in [
        (
            "HTTP/1.1 429 Too Many Requests\r\nX-Private: ignored\r\n\r\n",
            Some(429),
        ),
        ("HTTP/1.1 403 Forbidden\r\n\r\n", Some(403)),
        ("HTTP/1.1 101 Switching Protocols\r\n\r\n", None),
        ("HTTP/1.0 429 Too Many Requests\r\n\r\n", None),
        ("HTTP/1.1 429 Missing End\r\n", None),
        ("HTTP/1.1 600 Unknown\r\n\r\n", None),
        (
            "HTTP/1.1 429 Too Many Requests\r\nnot a header\r\n\r\n",
            None,
        ),
    ] {
        let error = verify(response.as_bytes(), 2, "expected").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(ws_rejection_status(&error), expected);
        assert_eq!(error.to_string(), "invalid WebSocket upgrade response");
    }
}
use futures_util::StreamExt;
use tokio::io::duplex;

#[tokio::test]
async fn valid_upgrade_with_optional_protocol_and_connection_tokens_preserves_first_frame() {
    for (connection, protocol) in [
        ("Upgrade", ""),
        ("keep-alive, uPgRaDe", "Sec-WebSocket-Protocol: binary\r\n"),
        ("keep-alive\r\nConnection: upgrade", ""),
    ] {
        let (socket, server) = duplex(2048);
        let server = tokio::spawn(async move {
            let mut server = BufReader::new(server);
            let mut key = None;
            let mut offered = false;
            loop {
                let mut line = String::new();
                assert!(server.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                        key = Some(derive_accept_key(value.trim().as_bytes()));
                    }
                    if name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
                        offered = value.trim() == "binary";
                    }
                }
            }
            assert!(offered);
            let mut response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: {connection}\r\nSec-WebSocket-Accept: {}\r\n{protocol}\r\n",key.unwrap()).into_bytes();
            response.extend_from_slice(b"\x82\x02ok");
            server.write_all(&response).await.unwrap();
        });
        let mut ws = client(socket, "ws://fixture.test/apiws").await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_data().as_ref(),
            b"ok"
        );
        server.await.unwrap();
    }
}

#[test]
fn upgrade_requires_valid_accept_and_offer_compatible_headers() {
    for (connection, accept, extra) in [
        ("keep-alive", "expected", ""),
        ("Upgrade", "wrong", ""),
        ("Upgrade", "expected", "Sec-WebSocket-Protocol: chat\r\n"),
        ("Upgrade", "expected", "Sec-WebSocket-Accept: expected\r\n"),
        (
            "Upgrade",
            "expected",
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
        ),
    ] {
        let response=format!("HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: {connection}\r\nSec-WebSocket-Accept: {accept}\r\n{extra}\r\n");
        assert!(verify(response.as_bytes(), 5, "expected").is_err());
    }
}
