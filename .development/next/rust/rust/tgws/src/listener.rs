use crate::diagnostics::Event;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep_until, Instant},
};

/// Restore the same listening address after a failed accept. The control pipe
/// and already accepted sessions keep running while this listener retries.
pub(super) struct Listener {
    address: SocketAddr,
    socket: Option<TcpListener>,
    retry_at: Instant,
}

impl Listener {
    pub async fn bind(address: &str) -> io::Result<Self> {
        let socket = match address.parse::<SocketAddr>() {
            Ok(addr) if addr.ip().is_unspecified() => {
                nfqws2_tgws_transport::bind_wildcard(addr.port())?
            }
            _ => TcpListener::bind(address).await?,
        };
        Ok(Self {
            address: socket.local_addr()?,
            socket: Some(socket),
            retry_at: Instant::now(),
        })
    }

    fn schedule_retry(&mut self) {
        self.socket = None;
        self.retry_at = Instant::now() + Duration::from_secs(1);
    }

    fn failed_accept(&mut self, error: io::Error, report: &impl Fn(Event)) {
        if error.kind() != io::ErrorKind::Interrupted {
            self.schedule_retry();
            report(Event::ListenerLost);
        }
    }

    pub async fn accept(&mut self, report: impl Fn(Event)) -> TcpStream {
        loop {
            if let Some(socket) = &self.socket {
                match socket.accept().await {
                    Ok((stream, _)) => return stream,
                    Err(error) => self.failed_accept(error, &report),
                }
            } else {
                // select! also serves status and stop. Polling it again must
                // not postpone retries each time the control branch wins.
                sleep_until(self.retry_at).await;
                let retry = if self.address.ip().is_unspecified() {
                    nfqws2_tgws_transport::bind_wildcard(self.address.port())
                } else {
                    TcpListener::bind(self.address).await
                };
                match retry {
                    Ok(socket) => {
                        self.socket = Some(socket);
                        report(Event::ListenerRestored);
                    }
                    Err(_) => self.schedule_retry(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn rebind_survives_busy_address_and_control_polls_on_the_original_port() {
        let events = std::cell::RefCell::new(Vec::new());
        let report = |event| events.borrow_mut().push(event);
        let mut listener = Listener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.address;
        listener.failed_accept(io::ErrorKind::Interrupted.into(), &report);
        assert!(listener.socket.is_some());
        assert!(events.borrow().is_empty());
        let (mut established, mut peer) = tokio::try_join!(
            async { Ok(listener.accept(report).await) },
            TcpStream::connect(address)
        )
        .unwrap();
        listener.failed_accept(io::ErrorKind::ConnectionAborted.into(), &report);
        assert_eq!(*events.borrow(), [Event::ListenerLost]);
        let busy = TcpListener::bind(address).await.unwrap();
        let retry = listener.retry_at;
        assert!(listener.accept(report).now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(250)).await;
        assert!(listener.accept(report).now_or_never().is_none());
        assert_eq!(listener.retry_at, retry);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(listener.accept(report).now_or_never().is_none());
        assert!(listener.retry_at > retry);
        assert_eq!(*events.borrow(), [Event::ListenerLost]);
        drop(busy);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(listener.accept(report).now_or_never().is_none());
        assert!(listener.socket.is_some());
        assert_eq!(
            *events.borrow(),
            [Event::ListenerLost, Event::ListenerRestored]
        );
        tokio::try_join!(
            async { Ok(listener.accept(report).await) },
            TcpStream::connect(address)
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            [Event::ListenerLost, Event::ListenerRestored]
        );
        peer.write_all(b"x").await.unwrap();
        assert_eq!(established.read_u8().await.unwrap(), b'x');
    }
}
