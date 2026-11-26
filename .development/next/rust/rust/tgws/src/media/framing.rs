use super::MAX;
use crate::crypto::Cipher;
use ctr::cipher::StreamCipher;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) async fn length(
    r: &mut (impl AsyncRead + Unpin),
    decrypt: &mut Cipher,
    tag: u8,
) -> io::Result<usize> {
    let mut word = [0; 4];
    let n = if tag == 0xef {
        r.read_exact(&mut word[..1]).await?;
        decrypt.apply_keystream(&mut word[..1]);
        let count = word[0] & 127;
        if count == 127 {
            r.read_exact(&mut word[..3]).await?;
            decrypt.apply_keystream(&mut word[..3]);
            u32::from_le_bytes(word) as usize * 4
        } else {
            usize::from(count) * 4
        }
    } else {
        r.read_exact(&mut word).await?;
        decrypt.apply_keystream(&mut word);
        (u32::from_le_bytes(word) & 0x7fff_ffff) as usize
    };
    let limit = if tag == 0xdd { MAX + 256 } else { MAX };
    if n < 24 || n > limit {
        return Err(io::Error::other("invalid HTTP/2 native frame length"));
    }
    Ok(n)
}
pub(super) fn packet_size(buf: &[u8], tag: u8) -> io::Result<usize> {
    let n = buf.len();
    if n < 24 {
        return Err(io::Error::other("short native MTProto message"));
    }
    let size = if tag != 0xdd {
        n
    } else if buf[..8] == [0; 8] {
        let len = 20u64 + u64::from(u32::from_le_bytes(buf[16..20].try_into().unwrap()));
        if len > n as u64 || n as u64 - len > 256 {
            return Err(io::Error::other("invalid MTProto plaintext padding"));
        }
        len as usize
    } else {
        24 + (n - 24) / 16 * 16
    };
    if !(24..=MAX).contains(&size) || !size.is_multiple_of(4) {
        return Err(io::Error::other("invalid aligned MTProto message"));
    }
    Ok(size)
}
pub(super) fn frame(body: &[u8], tag: u8) -> io::Result<Vec<u8>> {
    let n = body.len();
    if n == 0 || n > MAX || !n.is_multiple_of(4) {
        return Err(io::Error::other("invalid HTTP/2 MTProto reply"));
    }
    let mut pad = [0; 4];
    let mut pad_len = 0;
    let mut out = Vec::with_capacity(n + 7);
    if tag == 0xef {
        let words = n / 4;
        if words < 127 {
            out.push(words as u8);
        } else {
            out.push(127);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
    } else {
        if tag == 0xdd {
            getrandom::getrandom(&mut pad)
                .map_err(|_| io::Error::other("randomness unavailable"))?;
            pad_len = usize::from(pad[0] % 4);
        }
        out.extend_from_slice(&((n + pad_len) as u32).to_le_bytes());
    }
    out.extend_from_slice(body);
    out.extend_from_slice(&pad[1..1 + pad_len]);
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removes_only_transport_padding_within_the_native_length_and_packet_limits() {
        let mut encrypted = vec![7; 53];
        assert_eq!(packet_size(&encrypted, 0xdd).unwrap(), 40);
        encrypted[..8].fill(0);
        encrypted[16..20].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(packet_size(&encrypted, 0xdd).unwrap(), 28);
        encrypted[16..20].fill(255);
        assert!(packet_size(&encrypted, 0xdd).is_err());
        encrypted[16..20].copy_from_slice(&8u32.to_le_bytes());
        encrypted.resize(285, 0);
        assert!(packet_size(&encrypted, 0xdd).is_err());
        assert!(packet_size(&[0; 26], 0xee).is_err());
        assert_eq!(frame(&[1; 8], 0xef).unwrap()[0], 2);
        assert_eq!(&frame(&[1; 512], 0xef).unwrap()[..4], &[127, 128, 0, 0]);
        let padded = frame(&[1; 8], 0xdd).unwrap();
        assert!((12..=15).contains(&padded.len()));
        assert_eq!(&padded[4..12], &[1; 8]);
        assert_eq!(padded[0] as usize, padded.len() - 4);
    }
}
