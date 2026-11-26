//! Validate frame lengths before tungstenite reads their payloads.
//! Its public Stream emits completed messages, while Go's active read deadline
//! starts again at each complete wire frame, including continuations and pings.
use super::{Message, MAX_WS_MESSAGE};
use futures_util::{SinkExt, Stream, StreamExt};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    tungstenite::{protocol::CloseFrame, Bytes, Error},
    WebSocketStream,
};

const IDLE: Duration = Duration::from_secs(180);
pub struct Active {
    completed: watch::Receiver<()>,
}
impl Active {
    pub async fn next_data<S: Stream<Item = Result<Message, Error>> + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> io::Result<Option<Bytes>> {
        loop {
            match self.next(stream).await? {
                Some(Message::Binary(bytes)) => return Ok(Some(bytes)),
                Some(Message::Text(text)) => return Ok(Some(text.into())),
                Some(Message::Close(_)) | None => return Ok(None),
                _ => {}
            }
        }
    }
    async fn next<S: Stream<Item = Result<Message, Error>> + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> io::Result<Option<Message>> {
        let next = stream.next();
        tokio::pin!(next);
        self.completed.borrow_and_update();
        loop {
            tokio::select! {
                biased;
                result=&mut next=>return result.transpose().map_err(io::Error::other),
                changed=self.completed.changed()=>changed.map_err(|_|io::ErrorKind::BrokenPipe)?,
                _=sleep(IDLE)=>return Err(io::ErrorKind::TimedOut.into()),
            }
        }
    }
}
pub async fn write<T>(send: impl Future<Output = Result<T, Error>>) -> io::Result<T> {
    timeout(IDLE, send)
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .map_err(io::Error::other)
}

/// Flush a legacy peer's Close with its original status and no reason, then drop the transport.
/// The caller bounds the write and must first cancel the application writer.
pub async fn reply_peer_close_status<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws: WebSocketStream<Wire<S>>,
    frame: CloseFrame,
) {
    // With the default maximum, tungstenite appends its queued Close before
    // offering the complete outgoing buffer to Wire.
    if ws.get_config().max_write_buffer_size == usize::MAX
        && ws.get_ref().tracker.first_close.matches(&frame)
    {
        ws.get_mut().terminal_close = Some(TerminalClose::Expected(frame));
        let _ = ws.flush().await;
    }
}

pub struct Wire<S> {
    pub(super) socket: S,
    tracker: Tracker,
    idle_prefix: Option<u8>,
    terminal_close: Option<TerminalClose>,
    outbound_limit: Option<PendingWriteLimit>,
}

pub struct PendingWriteLimit(Arc<AtomicUsize>);

impl PendingWriteLimit {
    pub fn increase_to(&self, maximum: usize) {
        self.0.fetch_max(maximum, Ordering::Relaxed);
    }
}
impl<S> Wire<S> {
    pub fn after_upgrade(socket: S) -> Self {
        Self {
            socket,
            tracker: Tracker::new(),
            idle_prefix: None,
            terminal_close: None,
            outbound_limit: None,
        }
    }
    pub fn active(&self) -> Active {
        Active {
            completed: self.tracker.progress.subscribe(),
        }
    }

    /// Abort a write before oversized queued frames reach the socket.
    pub fn limit_pending_writes(&mut self, maximum: usize) -> PendingWriteLimit {
        let limit = Arc::new(AtomicUsize::new(maximum));
        self.outbound_limit = Some(PendingWriteLimit(limit.clone()));
        PendingWriteLimit(limit)
    }
}
impl<S: AsyncBufRead + Unpin> Wire<S> {
    /// Called only on an unused WebSocket, before the decoder reads any frames.
    pub async fn peek_open(&mut self) -> io::Result<bool> {
        let available = self.socket.fill_buf().await?;
        if self.idle_prefix.is_some() {
            return Ok(!available.is_empty());
        }
        match available {
            [] => Ok(false),
            [first, ..] if first & 15 == 8 => Ok(false),
            [first] => {
                // BufReader cannot extend a nonempty buffer. Keep this byte
                // across cancellation and return it to the active decoder.
                self.idle_prefix = Some(*first);
                self.socket.consume(1);
                Ok(!self.socket.fill_buf().await?.is_empty())
            }
            _ => Ok(true),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Wire<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() > 0 {
            if let Some(first) = self.idle_prefix.take() {
                self.tracker.received(&[first])?;
                buf.put_slice(&[first]);
                return Poll::Ready(Ok(()));
            }
        }
        let start = buf.filled().len();
        std::task::ready!(Pin::new(&mut self.socket).poll_read(cx, buf))?;
        if let Err(e) = self.tracker.received(&buf.filled()[start..]) {
            buf.set_filled(start);
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Wire<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self
            .outbound_limit
            .as_ref()
            .is_some_and(|limit| buf.len() > limit.0.load(Ordering::Relaxed))
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket output buffer exceeds relay limit",
            )));
        }
        if let Some(close) = &mut self.terminal_close {
            // Accept the original buffer atomically; poll_flush owns any
            // partial writes of the shorter frame to the underlying TLS stream.
            return Poll::Ready(close.buffer_status(buf).map(|()| buf.len()));
        }
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let wire = &mut *self;
        if let Some(close) = &mut wire.terminal_close {
            let TerminalClose::Buffered { bytes, written } = close else {
                *close = TerminalClose::Rejected;
                return Poll::Ready(Err(TerminalClose::invalid_output()));
            };
            while *written < bytes.len() {
                let n = std::task::ready!(
                    Pin::new(&mut wire.socket).poll_write(cx, &bytes[*written..])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                *written += n;
            }
        }
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

enum TerminalClose {
    Expected(CloseFrame),
    Buffered { bytes: [u8; 8], written: usize },
    Rejected,
}
impl TerminalClose {
    fn buffer_status(&mut self, output: &[u8]) -> io::Result<()> {
        let Self::Expected(frame) = std::mem::replace(self, Self::Rejected) else {
            return Err(Self::invalid_output());
        };
        let code = u16::from(frame.code).to_be_bytes();
        let payload = code.iter().chain(frame.reason.as_bytes());
        let length = 2 + frame.reason.len();
        // Accept one exact masked Close from the codec. An earlier buffered
        // Pong or any other queued bytes must prevent the terminal write.
        if output.len() != 6 + length
            || output[..2] != [0x88, 0x80 | length as u8]
            || !payload
                .enumerate()
                .all(|(i, b)| output[6 + i] ^ output[2 + i % 4] == *b)
        {
            return Err(Self::invalid_output());
        }
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&output[..8]);
        bytes[1] = 0x82;
        *self = Self::Buffered { bytes, written: 0 };
        Ok(())
    }
    fn invalid_output() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected queued WebSocket Close output",
        )
    }
}

enum FirstClose {
    Unseen,
    Ineligible,
    Reading { length: u8, code: [u8; 2] },
    Complete { length: u8, code: u16 },
}
impl FirstClose {
    fn matches(&self, frame: &CloseFrame) -> bool {
        // Tungstenite can replace a reserved incoming code with 1002 and a
        // reason. Only an actual status from the first valid wire Close may echo.
        matches!(self, Self::Complete { length, code }
            if frame.code.is_allowed() && *code == u16::from(frame.code)
                && usize::from(*length) == 2 + frame.reason.len())
    }
}

struct Tracker {
    header: [u8; 14],
    have: usize,
    need: usize,
    remaining: usize,
    message_bytes: usize,
    final_data: bool,
    first_close: FirstClose,
    progress: watch::Sender<()>,
}
impl Tracker {
    fn new() -> Self {
        Self {
            header: [0; 14],
            have: 0,
            need: 2,
            remaining: 0,
            message_bytes: 0,
            final_data: false,
            first_close: FirstClose::Unseen,
            progress: watch::channel(()).0,
        }
    }
    fn received(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.have < self.need {
                let n = (self.need - self.have).min(bytes.len());
                self.header[self.have..self.have + n].copy_from_slice(&bytes[..n]);
                self.have += n;
                bytes = &bytes[n..];
                if self.have == 2 {
                    self.need =
                        2 + match self.header[1] & 127 {
                            126 => 2,
                            127 => 8,
                            _ => 0,
                        } + if self.header[1] & 128 != 0 { 4 } else { 0 };
                }
                if self.have < self.need {
                    continue;
                }
                self.begin()?;
            }
            let n = self.remaining.min(bytes.len());
            if let FirstClose::Reading { length, code } = &mut self.first_close {
                let offset = usize::from(*length) - self.remaining;
                if offset < code.len() {
                    let count = n.min(code.len() - offset);
                    code[offset..offset + count].copy_from_slice(&bytes[..count]);
                }
            }
            self.remaining -= n;
            bytes = &bytes[n..];
            if self.remaining == 0 {
                self.complete();
            }
        }
        Ok(())
    }
    fn begin(&mut self) -> io::Result<()> {
        let length = match self.header[1] & 127 {
            126 => u64::from(u16::from_be_bytes(self.header[2..4].try_into().unwrap())),
            127 => u64::from_be_bytes(self.header[2..10].try_into().unwrap()),
            n => u64::from(n),
        };
        if length > MAX_WS_MESSAGE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket frame exceeds limit",
            ));
        }
        self.remaining = length as usize;
        let data = self.header[0] & 8 == 0;
        // Tungstenite validates control payloads after reading them. Reject
        // oversized ones before the decoder attempts to read the payload.
        if !data && length > 125 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket control frame exceeds limit",
            ));
        }
        if matches!(self.first_close, FirstClose::Unseen) && self.header[0] & 15 == 8 {
            self.first_close = if self.header[0] == 0x88 && (3..=125).contains(&self.header[1]) {
                FirstClose::Reading {
                    length: self.header[1],
                    code: [0; 2],
                }
            } else {
                FirstClose::Ineligible
            };
        }
        self.final_data = data && self.header[0] & 128 != 0;
        if data {
            self.message_bytes += self.remaining;
            if self.message_bytes > MAX_WS_MESSAGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket message exceeds limit",
                ));
            }
        }
        Ok(())
    }
    fn complete(&mut self) {
        if let FirstClose::Reading { length, code } = self.first_close {
            self.first_close = FirstClose::Complete {
                length,
                code: u16::from_be_bytes(code),
            };
        }
        if self.final_data {
            self.message_bytes = 0;
        }
        self.have = 0;
        self.need = 2;
        self.progress.send_replace(());
    }
}
#[cfg(test)]
mod tests;
