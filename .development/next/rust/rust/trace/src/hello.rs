//! Passive inspection of outbound TLS records during an explicit device capture.
mod candidates;
pub use candidates::Candidate;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const SNAP: usize = 65535;
const DESTINATIONS: usize = 128;
#[derive(Default, Serialize)]
pub struct Observation {
    pub headers: u64,
    pub record_bytes: u64,
}
pub struct Summary {
    source: IpAddr,
    pub destinations: BTreeMap<IpAddr, Observation>,
    pub overflow: bool,
    capture: candidates::Capture,
}
impl Summary {
    pub fn new(source: IpAddr) -> Self {
        Self {
            source,
            destinations: BTreeMap::new(),
            overflow: false,
            capture: candidates::Capture::default(),
        }
    }
    pub fn header(&self, ethernet: bool, snap: usize) -> io::Result<()> {
        if !ethernet || snap > SNAP {
            return Err(io::Error::other(
                "для диагностики TLS нужен Ethernet с ограниченной длиной снимка",
            ));
        }
        Ok(())
    }
    pub fn observe(&mut self, frame: &[u8]) {
        let Some(segment) = segment(frame) else {
            return;
        };
        if segment.source != self.source {
            return;
        }
        let dest = segment.dest;
        let size = header_size(segment.payload);
        self.capture.observe(segment);
        let Some(size) = size else { return };
        if self.destinations.len() >= DESTINATIONS && !self.destinations.contains_key(&dest) {
            self.overflow = true;
            return;
        }
        let record = self.destinations.entry(dest).or_default();
        record.headers += 1;
        record.record_bytes += u64::from(size) + 5;
    }
    pub fn finish(&mut self) -> Vec<Candidate> {
        self.overflow |= self.capture.limited;
        self.capture.finish()
    }
}
fn word(bytes: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(i..i + 2)?.try_into().ok()?))
}
struct Segment<'a> {
    source: IpAddr,
    dest: IpAddr,
    port: u16,
    seq: u32,
    payload: &'a [u8],
}
fn segment(frame: &[u8]) -> Option<Segment<'_>> {
    let mut kind = word(frame, 12)?;
    let mut data = frame.get(14..)?;
    for _ in 0..2 {
        if !matches!(kind, 0x8100 | 0x88a8) {
            break;
        }
        kind = word(data, 2)?;
        data = data.get(4..)?;
    }
    let (source, dest, tcp) = match kind {
        0x0800 if data.first()? >> 4 == 4 => {
            let size = usize::from(data[0] & 15) * 4;
            if size < 20 || *data.get(9)? != 6 || word(data, 6)? & 0x3fff != 0 {
                return None;
            }
            let sip = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(12..16)?).ok()?);
            let dip = Ipv4Addr::from(<[u8; 4]>::try_from(data.get(16..20)?).ok()?);
            let end = usize::from(word(data, 2)?).min(data.len());
            (IpAddr::V4(sip), IpAddr::V4(dip), data.get(size..end)?)
        }
        0x86dd if data.first()? >> 4 == 6 => {
            let sip = Ipv6Addr::from(<[u8; 16]>::try_from(data.get(8..24)?).ok()?);
            let dip = Ipv6Addr::from(<[u8; 16]>::try_from(data.get(24..40)?).ok()?);
            let end = (40 + usize::from(word(data, 4)?)).min(data.len());
            let mut transport = data.get(40..end)?;
            let mut next = data[6];
            while matches!(next, 0 | 43 | 60) {
                let len = (1 + usize::from(*transport.get(1)?)) * 8;
                next = transport[0];
                transport = transport.get(len..)?;
            }
            if next != 6 {
                return None;
            }
            (IpAddr::V6(sip), IpAddr::V6(dip), transport)
        }
        _ => return None,
    };
    let header = usize::from(*tcp.get(12)? >> 4) * 4;
    if header < 20 || word(tcp, 2)? != 443 {
        return None;
    }
    Some(Segment {
        source,
        dest,
        port: word(tcp, 0)?,
        seq: u32::from_be_bytes(tcp.get(4..8)?.try_into().ok()?),
        payload: tcp.get(header..)?,
    })
}
fn header_size(tls: &[u8]) -> Option<u16> {
    if tls.len() < 11
        || tls[0] != 22
        || tls[1] != 3
        || tls[2] > 3
        || tls[5] != 1
        || tls[9] != 3
        || tls[10] > 3
    {
        return None;
    }
    let len = word(tls, 3)?;
    let body = u32::from_be_bytes([0, tls[6], tls[7], tls[8]]);
    ((6..=16384).contains(&len) && body >= 41).then_some(len)
}

/// Metadata from a single untagged IPv4/TCP 443 ClientHello. This path
/// does not reassemble streams or retain the observed record.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn single_ipv4_sni(frame: &[u8]) -> Option<(Ipv4Addr, &str)> {
    if word(frame, 12)? != 0x0800 {
        return None;
    }
    let segment = segment(frame)?;
    let IpAddr::V4(dest) = segment.dest else {
        return None;
    };
    header_size(segment.payload)?;
    let name = nfqws2_tls_record::server_name_prefix(segment.payload)?;
    (name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }))
    .then_some((dest, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(v6: bool, last: u8) -> (IpAddr, Vec<u8>) {
        let mut frame = vec![0; 14];
        let source = if v6 {
            frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            let ip: Ipv6Addr = "fd00::1".parse().unwrap();
            let mut head = [0u8; 48];
            head[0] = 0x60;
            head[4..6].copy_from_slice(&128u16.to_be_bytes());
            head[6] = 60;
            head[40] = 6;
            head[8..24].copy_from_slice(&ip.octets());
            head[24] = 0x20;
            head[39] = last;
            frame.extend(head);
            IpAddr::V6(ip)
        } else {
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            let ip = Ipv4Addr::new(192, 0, 2, 4);
            let mut head = [0u8; 20];
            head[0] = 0x45;
            head[9] = 6;
            head[2..4].copy_from_slice(&120u16.to_be_bytes());
            head[12..16].copy_from_slice(&ip.octets());
            head[16..20].copy_from_slice(&[198, 51, 100, last]);
            frame.extend(head);
            IpAddr::V4(ip)
        };
        let mut tcp = [0u8; 20];
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        frame.extend(tcp);
        frame.extend([22, 3, 1, 0, 70, 1, 0, 0, 66, 3, 3]);
        (source, frame)
    }
    #[test]
    fn ipv4_and_ipv6_tls_counters_require_a_complete_header_and_the_selected_client() {
        for v6 in [false, true] {
            let (src, frame) = packet(v6, 1);
            let mut s = Summary::new(src);
            for n in 0..frame.len() {
                s.observe(&frame[..n]);
            }
            assert!(s.destinations.is_empty());
            let mut vlan = frame.clone();
            vlan.splice(12..12, [0x81, 0, 0, 3]);
            s.observe(&vlan);
            s.observe(&frame);
            let row = s.destinations.values().next().unwrap();
            assert_eq!((row.headers, row.record_bytes), (2, 150));
            let mut other = Summary::new("192.0.2.98".parse().unwrap());
            other.observe(&frame);
            assert!(other.destinations.is_empty());
            assert!(s.header(false, SNAP).is_err());
            assert!(s.header(true, SNAP + 1).is_err());
        }
    }
    #[test]
    fn limit_retains_existing_destinations_and_ignores_non_hello_and_fragmented_traffic() {
        let (source, mut bytes) = packet(false, 0);
        let mut s = Summary::new(source);
        bytes[20] = 0x20;
        s.observe(&bytes);
        bytes[20] = 0;
        bytes[59] = 2;
        s.observe(&bytes);
        assert!(s.destinations.is_empty());
        for i in 0..=180 {
            s.observe(&packet(false, i).1);
        }
        s.observe(&packet(false, 0).1);
        assert_eq!(s.destinations.len(), DESTINATIONS);
        assert!(s.overflow);
        assert_eq!(
            s.destinations[&"198.51.100.0".parse::<IpAddr>().unwrap()].headers,
            2
        );
    }
    fn tls(name: &str, padding: usize) -> Vec<u8> {
        let word = |n: usize| (n as u16).to_be_bytes();
        let mut names = vec![0, 0];
        names.extend(word(5 + name.len()));
        names.extend(word(3 + name.len()));
        names.push(0);
        names.extend(word(name.len()));
        names.extend(name.bytes());
        names.extend([0, 21]);
        names.extend(word(padding));
        names.resize(names.len() + padding, 0);
        let mut body = vec![3, 3];
        body.extend([23; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        body.extend(word(names.len()));
        body.extend(names);
        let mut record = vec![22, 3, 1];
        record.extend(word(body.len() + 4));
        record.extend([1, 0]);
        record.extend(word(body.len()));
        record.extend(body);
        record
    }
    fn frame(seq: u32, src_port: u16, bytes: &[u8]) -> Vec<u8> {
        let (_, mut frame) = packet(false, 80);
        frame.truncate(54);
        frame[16..18].copy_from_slice(&((40 + bytes.len()) as u16).to_be_bytes());
        frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        frame[38..42].copy_from_slice(&seq.to_be_bytes());
        frame.extend(bytes);
        frame
    }
    #[test]
    fn explicit_capture_reassembles_only_complete_records_and_keeps_stable_indices() {
        let mut s = Summary::new("192.0.2.4".parse().unwrap());
        let large = tls("large.example", 1800);
        let small = tls("small.example", 2);
        let seq = u32::MAX - 99;
        s.observe(&frame(seq, 8111, &large[..500]));
        s.observe(&frame(seq, 8111, &large[..500]));
        s.observe(&frame(seq.wrapping_add(400), 8111, &large[400..]));
        // Retransmission and separate connection to the same SNI.
        s.observe(&frame(seq, 8111, &large));
        s.observe(&frame(5, 8112, &large));
        let mut joined = small.clone();
        joined.extend([23, 3, 3, 0, 2, 42, 43]);
        s.observe(&frame(7, 8113, &joined));
        let truncated = tls("cut.example", 200);
        s.observe(&frame(19, 8114, &truncated[..100]));
        s.observe(&frame(19 + 105, 8114, &truncated[105..]));
        let other = tls("wrong.example", 300);
        let mut wrong = frame(0, 8115, &other);
        wrong[26] = 203;
        s.observe(&wrong);
        let mut malformed = frame(0, 8115, &other);
        malformed[54 + 8] ^= 1;
        s.observe(&malformed);
        let rows = s.finish();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bytes, small);
        assert_eq!(rows[1].bytes, large);
        let metadata = serde_json::to_value(&rows).unwrap();
        assert_eq!(metadata[0]["sni"], "small.example");
        assert_eq!(metadata[1]["sni"], "large.example");
        assert!(metadata[1].get("bytes").is_none());
    }
    #[test]
    fn scoped_sni_observes_one_ipv4_hello_and_never_uses_continuations_or_other_ports() {
        let record = tls("Front.Example", 600);
        let good = frame(0, 39712, &record);
        assert_eq!(
            single_ipv4_sni(&good),
            Some((Ipv4Addr::new(198, 51, 100, 80), "Front.Example"))
        );
        let sni_end = frame(0, 39712, &tls("Front.Example", 0)).len() - 4;
        assert_eq!(single_ipv4_sni(&good[..sni_end]), single_ipv4_sni(&good));
        for truncated in 0..sni_end {
            assert!(single_ipv4_sni(&good[..truncated]).is_none());
        }
        for (offset, value) in [(20, 0x20), (23, 17), (36, 0), (12, 0x81)] {
            let mut wrong = good.clone();
            wrong[offset] = value;
            assert!(single_ipv4_sni(&wrong).is_none());
        }
        assert!(single_ipv4_sni(&frame(30, 39712, &record[30..])).is_none());
        assert!(single_ipv4_sni(&frame(0, 39712, &tls("weird\nname", 20))).is_none());
    }
    #[test]
    fn incomplete_streams_and_archive_size_have_independent_budgets() {
        let mut s = Summary::new("192.0.2.4".parse().unwrap());
        for i in 0..16 {
            s.observe(&frame(5, i, &tls("pending.example", 900)[..90]));
        }
        for i in 0..55 {
            let record = tls(&format!("{i}.example"), 14_500);
            s.observe(&frame(6, i + 20, &record));
        }
        let rows = s.finish();
        assert!(s.overflow);
        assert!(rows.len() > 1 && rows.len() < 50);
        assert!(rows.iter().map(|r| r.bytes.len()).sum::<usize>() <= 256 * 1024);
    }
}
