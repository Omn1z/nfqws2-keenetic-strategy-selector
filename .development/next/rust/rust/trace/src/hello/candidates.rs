use super::{header_size, word, Segment};
use serde::Serialize;
use std::{borrow::Cow, collections::BTreeMap, net::IpAddr};

const MAX_PENDING: usize = 12;
const MAX_CANDIDATES: usize = 50;
const MAX_SAVED: usize = 256 * 1024;

#[derive(Serialize)]
pub struct Candidate {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    sni: String,
    size: usize,
    valid: bool,
    detail: String,
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

struct Partial {
    seq: u32,
    size: usize,
    bytes: Vec<u8>,
}

#[derive(Default)]
pub(super) struct Capture {
    // The source IP and destination port are fixed for the entire capture.
    pending: BTreeMap<(IpAddr, u16), Partial>,
    ready: Vec<Candidate>,
    saved: usize,
    pub(super) limited: bool,
}

impl Capture {
    pub(super) fn observe(&mut self, s: Segment<'_>) {
        if s.payload.is_empty() || self.ready.len() == MAX_CANDIDATES {
            return;
        }
        let key = (s.dest, s.port);
        if let Some(part) = self.pending.get_mut(&key) {
            let at = s.seq.wrapping_sub(part.seq) as usize;
            if at <= part.bytes.len() {
                let overlap = (part.bytes.len() - at).min(s.payload.len());
                if part.bytes[at..at + overlap] != s.payload[..overlap] {
                    self.pending.remove(&key);
                    return;
                }
                let more = (part.size - part.bytes.len()).min(s.payload.len() - overlap);
                part.bytes
                    .extend_from_slice(&s.payload[overlap..overlap + more]);
                if part.bytes.len() == part.size {
                    let bytes = self.pending.remove(&key).unwrap().bytes;
                    self.add(&s, Cow::Owned(bytes));
                }
                return;
            }
        }
        // Start buffering only if this segment begins a ClientHello record.
        let data = s.payload;
        if data.len() < 6 || data[..2] != [22, 3] || data[2] > 3 || data[5] != 1 {
            return;
        }
        let size = 5 + usize::from(word(data, 3).unwrap());
        if !(50..=16389).contains(&size) {
            return;
        }
        self.pending.remove(&key);
        if data.len() >= size {
            self.add(&s, Cow::Borrowed(&data[..size]));
        } else if self.pending.len() < MAX_PENDING {
            self.pending.insert(
                key,
                Partial {
                    seq: s.seq,
                    size,
                    bytes: data.to_vec(),
                },
            );
        } else {
            self.limited = true;
        }
    }
    fn add(&mut self, s: &Segment<'_>, bytes: Cow<'_, [u8]>) {
        if header_size(&bytes).is_none() {
            return;
        }
        let sni = nfqws2_tls_record::server_name(&bytes).unwrap_or_default();
        // A server name is a DNS hostname. Keep arbitrary extension bytes and
        // control characters out of the public capture metadata.
        if sni.len() > 253 || !sni.bytes().all(|b| b.is_ascii_graphic()) {
            return;
        }
        if !sni.is_empty() && self.ready.iter().any(|r| r.sni == sni) {
            return;
        }
        if self.saved + bytes.len() > MAX_SAVED {
            self.limited = true;
            return;
        }
        let (valid, detail) = nfqws2_tls_record::validate(&bytes);
        if !valid {
            return;
        }
        self.saved += bytes.len();
        self.ready.push(Candidate {
            src_ip: s.source,
            dst_ip: s.dest,
            dst_port: 443,
            sni: sni.to_owned(),
            size: bytes.len(),
            valid,
            detail,
            bytes: bytes.into_owned(),
        });
        self.limited |= self.ready.len() == MAX_CANDIDATES;
    }
    pub(super) fn finish(&mut self) -> Vec<Candidate> {
        self.ready.sort_by_key(|row| row.size);
        std::mem::take(&mut self.ready)
    }
}
