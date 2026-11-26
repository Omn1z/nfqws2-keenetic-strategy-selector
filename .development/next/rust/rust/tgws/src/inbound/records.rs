use super::invalid;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

pub(super) async fn bridge(
    socket: impl AsyncRead + AsyncWrite + Unpin,
    plain: DuplexStream,
    legacy: bool,
) {
    let (r, w) = tokio::io::split(socket);
    let (pr, pw) = tokio::io::split(plain);
    let output = wrap_records(pr, w);
    tokio::pin!(output);
    tokio::select! {_=&mut output=>{},_=unwrap_records(r,pw,legacy)=>{let _=tokio::time::timeout(std::time::Duration::from_secs(1),output).await;}}
}
pub(super) async fn unwrap_records(
    mut r: impl AsyncRead + Unpin,
    mut w: impl AsyncWrite + Unpin,
    legacy: bool,
) -> io::Result<()> {
    let mut buf = [0; 4096];
    let mut header = [0; 5];
    loop {
        r.read_exact(&mut header).await?;
        let mut left = usize::from(u16::from_be_bytes([header[3], header[4]]));
        // Go FakeTLS treats the authenticated record layer as framing only.
        // Its full u16 lengths still use one fixed-size streaming buffer.
        if !legacy && (header[1..3] != [3, 3] || left > 16384) {
            return Err(invalid());
        }
        let discard = match header[0] {
            23 => false,
            20 if legacy => true,
            20 if left == 1 && r.read_u8().await? == 1 => continue,
            _ => return Err(invalid()),
        };
        while left > 0 {
            let size = left.min(buf.len());
            let n = r.read(&mut buf[..size]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if !discard {
                w.write_all(&buf[..n]).await?;
            }
            left -= n;
        }
    }
}
async fn wrap_records(
    mut r: impl AsyncRead + Unpin,
    mut w: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut buf = vec![0; 16384 + 5];
    buf[..3].copy_from_slice(&[23, 3, 3]);
    loop {
        let n = r.read(&mut buf[5..]).await?;
        if n == 0 {
            return w.shutdown().await;
        }
        buf[3..5].copy_from_slice(&(n as u16).to_be_bytes());
        w.write_all(&buf[..5 + n]).await?;
    }
}
