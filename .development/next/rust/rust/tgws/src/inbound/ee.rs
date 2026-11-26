use super::invalid;
use ring::hmac;
use std::io;
use subtle::ConstantTimeEq;

fn entropy(dst: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(dst).map_err(|_| io::Error::other("OS random source unavailable"))
}
pub(super) enum Reply {
    Authenticated(Vec<u8>),
    Expired,
    Unauthenticated,
}

pub(super) fn reply(hello: &[u8], secret: &[u8; 16], now: u64) -> io::Result<Reply> {
    let random = hello.get(11..43).ok_or_else(invalid)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut sign = hmac::Context::with_key(&key);
    sign.update(&hello[..11]);
    sign.update(&[0; 32]);
    sign.update(&hello[43..]);
    let expected = sign.sign();
    let digest = expected.as_ref();
    if !bool::from(random[..28].ct_eq(&digest[..28])) {
        return Ok(Reply::Unauthenticated);
    }
    let stamp = u32::from_le_bytes(std::array::from_fn(|i| random[28 + i] ^ digest[28 + i]));
    if now.abs_diff(u64::from(stamp)) > 120 {
        return Ok(Reply::Expired);
    }
    let mut response = vec![0; 127];
    response[..11].copy_from_slice(&[22, 3, 3, 0, 122, 2, 0, 0, 118, 3, 3]);
    response[43] = 32;
    if hello.get(43) == Some(&32) {
        response[44..76].copy_from_slice(hello.get(44..76).ok_or_else(invalid)?);
    }
    response[76..89].copy_from_slice(&[0x13, 1, 0, 0, 46, 0, 51, 0, 36, 0, 29, 0, 32]);
    entropy(&mut response[89..121])?;
    response[121..].copy_from_slice(&[0, 43, 0, 2, 3, 4]);
    response.extend_from_slice(&[20, 3, 3, 0, 1, 1, 23, 3, 3]);
    let mut sample = [0; 2];
    entropy(&mut sample)?;
    let length = 1900 + u16::from_le_bytes(sample) % 201;
    response.extend_from_slice(&length.to_be_bytes());
    let start = response.len();
    response.resize(start + usize::from(length), 0);
    entropy(&mut response[start..])?;
    let mut sign = hmac::Context::with_key(&key);
    sign.update(random);
    sign.update(&response);
    response[11..43].copy_from_slice(sign.sign().as_ref());
    Ok(Reply::Authenticated(response))
}
