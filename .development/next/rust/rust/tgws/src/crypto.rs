use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use std::io;

pub type Cipher = ctr::Ctr128BE<Aes256>;
use nfqws2_tgws_transport::MAX_PACKET;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid MTProto transport")
}
fn cipher(seed: &[u8; 48], secret: Option<&[u8; 16]>) -> Cipher {
    let key: [u8; 32] = if let Some(secret) = secret {
        let mut h = Sha256::new();
        h.update(&seed[..32]);
        h.update(secret);
        h.finalize().into()
    } else {
        seed[..32].try_into().unwrap()
    };
    Cipher::new((&key).into(), seed[32..].into())
}
fn pair(head: &[u8; 64], secret: Option<&[u8; 16]>) -> (Cipher, Cipher) {
    let mut seed: [u8; 48] = head[8..56].try_into().unwrap();
    let forward = cipher(&seed, secret);
    seed.reverse();
    (forward, cipher(&seed, secret))
}
pub struct Transport {
    pub dc: i16,
    pub tag: u8,
    pub client_in: Cipher,
    pub client_out: Cipher,
    pub server_in: Cipher,
    pub server_out: Cipher,
    pub init: [u8; 64],
}
fn prefix_allowed(buf: &[u8; 64]) -> bool {
    buf[0] != 0xef
        && buf[4..8] != [0; 4]
        && ![
            *b"HEAD",
            *b"POST",
            *b"GET ",
            *b"OPTI",
            [0xee; 4],
            [0xdd; 4],
            [0x16, 3, 1, 2],
        ]
        .contains(&buf[..4].try_into().unwrap())
}
impl Transport {
    pub fn client(mut init: [u8; 64], secret: &[u8; 16]) -> io::Result<Self> {
        let (mut client_in, client_out) = pair(&init, Some(secret));
        client_in.apply_keystream(&mut init);
        let tag = init[56];
        let dc = i16::from_le_bytes([init[60], init[61]]);
        if !matches!(tag, 0xdd | 0xee | 0xef)
            || init[56..60] != [tag; 4]
            || !matches!(dc.unsigned_abs(),1..=5|203|10001..=10005|10203)
        {
            return Err(invalid());
        }
        let mut relay = [0; 64];
        loop {
            getrandom::getrandom(&mut relay).map_err(|e| io::Error::other(e.to_string()))?;
            if prefix_allowed(&relay) {
                break;
            }
        }
        let (mut server_out, server_in) = pair(&relay, None);
        let mut plain = relay;
        plain[56..60].fill(tag);
        // Test DCs use the test WebSocket path and the normal signed DC
        // number in the upstream MTProto header.
        plain[60..62].copy_from_slice(&(dc % 10000).to_le_bytes());
        server_out.apply_keystream(&mut plain);
        relay[56..].copy_from_slice(&plain[56..]);
        Ok(Self {
            dc,
            tag,
            client_in,
            client_out,
            server_in,
            server_out,
            init: relay,
        })
    }
}
pub fn packet_len(header: &[u8], tag: u8) -> io::Result<usize> {
    let length = if tag == 0xef {
        if header[0] & 127 == 127 {
            let n = u32::from_le_bytes([header[1], header[2], header[3], 0]);
            n as usize * 4
        } else {
            usize::from(header[0] & 127) * 4
        }
    } else {
        (u32::from_le_bytes(header.try_into().map_err(|_| invalid())?) & 0x7fff_ffff) as usize
    };
    if (1..=MAX_PACKET).contains(&length) {
        Ok(length)
    } else {
        Err(invalid())
    }
}
#[cfg(test)]
pub fn client_fixture(key: &[u8; 16], dc: i16, tag: u8) -> ([u8; 64], Cipher, Cipher) {
    let mut head = std::array::from_fn(|i| i as u8 + 2);
    let (mut send, recv) = pair(&head, Some(key));
    let mut plain = head;
    plain[56..60].fill(tag);
    plain[60..62].copy_from_slice(&dc.to_le_bytes());
    send.apply_keystream(&mut plain);
    head[56..].copy_from_slice(&plain[56..]);
    (head, send, recv)
}
#[cfg(test)]
pub fn upstream_fixture(mut head: [u8; 64]) -> (u8, i16, Cipher, Cipher) {
    let (mut recv, send) = pair(&head, None);
    recv.apply_keystream(&mut head);
    (
        head[56],
        i16::from_le_bytes([head[60], head[61]]),
        recv,
        send,
    )
}
