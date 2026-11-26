use super::ApiError;
use axum::{
    body::{Body, Bytes},
    http::{header, StatusCode},
    response::Response,
};
use std::io::{self, BufWriter, Write};
use tokio::sync::mpsc;

const CHUNK: usize = 16 * 1024;
struct Pipe(mpsc::Sender<io::Result<Bytes>>);
impl Write for Pipe {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(CHUNK);
        if n > 0 {
            self.0
                .blocking_send(Ok(Bytes::copy_from_slice(&data[..n])))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) async fn json_stream(
    write: impl FnOnce(&mut dyn Write) -> io::Result<()> + Send + 'static,
) -> Result<Response, ApiError> {
    let (send, mut recv) = mpsc::channel(2);
    tokio::task::spawn_blocking(move || {
        let mut out = BufWriter::with_capacity(CHUNK, Pipe(send.clone()));
        if let Err(err) = write(&mut out).and_then(|_| out.flush()) {
            // Do not let BufWriter's destructor flush bytes from a failed export.
            let _ = out.into_parts();
            let _ = send.blocking_send(Err(err));
        }
    });
    let first = match recv.recv().await {
        Some(Ok(data)) => data,
        Some(Err(e)) if e.kind() == io::ErrorKind::Unsupported => {
            return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
        }
        Some(Err(e)) => return Err(e.into()),
        None => {
            return Err(ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "empty JSON response".into(),
            ))
        }
    };
    let stream =
        futures_util::stream::unfold((Some(first), recv), |(first, mut recv)| async move {
            let next = match first {
                Some(data) => Ok(data),
                None => recv.recv().await?,
            };
            Some((next, (None, recv)))
        });
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("fixed response headers"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn slow_or_disconnected_clients_bound_buffering_and_release_producer() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let response = json_stream(move |out| {
            let block = [b'a'; CHUNK];
            let mut completed = 0usize;
            while out.write_all(&block).is_ok() {
                completed += 1;
            }
            let _ = tx.send(completed);
            Err(io::ErrorKind::BrokenPipe.into())
        })
        .await
        .map_err(|e| e.1)
        .unwrap();
        drop(response);
        let completed = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap();
        assert!((1..=4).contains(&completed));
    }
}
