use crate::{active::Wire, MAX_WS_MESSAGE};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_tungstenite::{
    tungstenite::{
        client::IntoClientRequest,
        handshake::{client::generate_request, derive_accept_key},
        protocol::{Role, WebSocketConfig},
    },
    WebSocketStream,
};

const HEADER_LIMIT: u64 = 64 << 10;

#[derive(Debug)]
struct RejectedStatus(u16);

impl std::fmt::Display for RejectedStatus {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("invalid WebSocket upgrade response")
    }
}

impl std::error::Error for RejectedStatus {}

pub fn ws_rejection_status(error: &io::Error) -> Option<u16> {
    error
        .get_ref()?
        .downcast_ref::<RejectedStatus>()
        .map(|status| status.0)
}

pub(super) async fn client<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    url: &str,
) -> io::Result<WebSocketStream<Wire<BufReader<S>>>> {
    let mut request = url.into_client_request().map_err(io::Error::other)?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
    let (wire, key) = generate_request(request).map_err(io::Error::other)?;
    socket.write_all(&wire).await?;
    socket.flush().await?;

    let mut reader = BufReader::with_capacity(8192, socket);
    let mut response = Vec::new();
    let mut count = 0usize;
    let mut bounded = (&mut reader).take(HEADER_LIMIT);
    loop {
        let start = response.len();
        if bounded.read_until(b'\n', &mut response).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete WebSocket HTTP response",
            ));
        }
        if &response[start..] == b"\r\n" {
            break;
        }
        count += 1;
    }
    verify(
        &response,
        count.saturating_sub(1),
        &derive_accept_key(key.as_bytes()),
    )?;
    let limits = WebSocketConfig::default()
        .read_buffer_size(8192)
        .write_buffer_size(4096)
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE));
    // Any bytes following the 101 remain in this same buffered reader.
    Ok(
        WebSocketStream::from_raw_socket(Wire::after_upgrade(reader), Role::Client, Some(limits))
            .await,
    )
}

fn verify(bytes: &[u8], count: usize, expected: &str) -> io::Result<()> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WebSocket upgrade response",
        )
    };
    let mut fields = vec![httparse::EMPTY_HEADER; count];
    let mut response = httparse::Response::new(&mut fields);
    if !response.parse(bytes).map_err(|_| invalid())?.is_complete() || response.version != Some(1) {
        return Err(invalid());
    }
    match response.code {
        Some(101) => (),
        Some(status @ 100..=599) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                RejectedStatus(status),
            ));
        }
        _ => return Err(invalid()),
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut accept = false;
    let mut protocol = false;
    for h in response.headers.iter() {
        if h.name.eq_ignore_ascii_case("Upgrade") {
            if upgrade || !h.value.eq_ignore_ascii_case(b"websocket") {
                return Err(invalid());
            }
            upgrade = true;
        } else if h.name.eq_ignore_ascii_case("Connection") {
            connection |= h
                .value
                .split(|&byte| byte == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"));
        } else if h.name.eq_ignore_ascii_case("Sec-WebSocket-Accept") {
            if accept || h.value != expected.as_bytes() {
                return Err(invalid());
            }
            accept = true;
        } else if h.name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
            if protocol || h.value != b"binary" {
                return Err(invalid());
            }
            protocol = true;
        } else if h.name.eq_ignore_ascii_case("Sec-WebSocket-Extensions") {
            // This client did not offer any extension.
            return Err(invalid());
        }
    }
    if upgrade && connection && accept {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
mod tests;
