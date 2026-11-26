//! Legacy crypt encodings for the router's existing passwd/shadow records.
//! MD5-crypt and APR1 follow the project's Go implementation by Jeramey
//! Crawford, Copyright 2012, distributed under LICENSE-crypt.
use base64ct::{Base64ShaCrypt, Encoding};
use md5::{Digest, Md5};
use sha_crypt::{sha256_crypt, sha512_crypt, Params};
use subtle::ConstantTimeEq;

const MD5_ORDER: [usize; 16] = [12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11];
const SHA256_ORDER: [usize; 32] = [
    20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15, 26, 16, 6, 17, 7, 27, 8, 28,
    18, 29, 19, 9, 30, 31,
];
const SHA512_ORDER: [usize; 64] = [
    42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47, 48, 27, 6, 7, 49, 28, 29, 8,
    50, 51, 30, 9, 10, 52, 31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58,
    37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
];

fn md5_crypt(magic: &[u8], key: &[u8], salt: &[u8]) -> [u8; 16] {
    let other = Md5::new()
        .chain_update(key)
        .chain_update(salt)
        .chain_update(key)
        .finalize();
    let mut digest = Md5::new()
        .chain_update(key)
        .chain_update(magic)
        .chain_update(salt);
    for part in key.chunks(16) {
        digest.update(&other[..part.len()]);
    }
    let mut bits = key.len();
    while bits != 0 {
        digest.update(if bits & 1 == 0 { &key[..1] } else { &[0] });
        bits >>= 1;
    }
    let mut sum = digest.finalize();
    for round in 0..1000 {
        let mut digest = Md5::new();
        digest.update(if round % 2 == 0 { &sum[..] } else { key });
        if round % 3 != 0 {
            digest.update(salt);
        }
        if round % 7 != 0 {
            digest.update(key);
        }
        digest.update(if round % 2 == 0 { key } else { &sum[..] });
        sum = digest.finalize();
    }
    sum.into()
}

fn matches_checksum<const N: usize>(sum: [u8; N], order: &[usize; N], stored: &str) -> bool {
    let ordered = order.map(|index| sum[index]);
    let mut encoded = [0; 86];
    let text =
        Base64ShaCrypt::encode(&ordered, &mut encoded).expect("buffer fits a SHA-512 checksum");
    text.as_bytes().ct_eq(stored.as_bytes()).into()
}

pub(super) fn check_hash(key: &str, stored: &str) -> bool {
    let Some((id, parameters)) = stored.strip_prefix('$').and_then(|v| v.split_once('$')) else {
        return false;
    };
    let Some((salt, checksum)) = parameters.rsplit_once('$') else {
        return false;
    };
    let key = key.as_bytes();
    match id {
        "1" | "apr1" if salt.len() <= 8 && !salt.contains('$') && checksum.len() == 22 => {
            let magic: &[u8] = if id == "1" { b"$1$" } else { b"$apr1$" };
            matches_checksum(md5_crypt(magic, key, salt.as_bytes()), &MD5_ORDER, checksum)
        }
        "5" | "6" => {
            if checksum.len() != if id == "5" { 43 } else { 86 } {
                return false;
            }
            let (params, salt) = if let Some(rest) = salt.strip_prefix("rounds=") {
                let Some((n, salt)) = rest.split_once('$') else {
                    return false;
                };
                let Ok(rounds) = n.parse::<u32>() else {
                    return false;
                };
                let Ok(params) = Params::new(rounds) else {
                    return false;
                };
                if n != rounds.to_string() {
                    return false;
                }
                (params, salt)
            } else {
                (Params::default(), salt)
            };
            if salt.len() > 16 || salt.contains('$') {
                return false;
            }
            if id == "5" {
                matches_checksum(
                    sha256_crypt(key, salt.as_bytes(), params),
                    &SHA256_ORDER,
                    checksum,
                )
            } else {
                matches_checksum(
                    sha512_crypt(key, salt.as_bytes(), params),
                    &SHA512_ORDER,
                    checksum,
                )
            }
        }
        _ => false,
    }
}
