//! Interpret network and transport headers only. Never retain packet bodies.
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct Key {
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    echo_id: u16,
}
struct Packet {
    key: Key,
    size: u32,
    reset: bool,
}
fn parse(buf: &[u8]) -> Option<Packet> {
    let word = |i| Some(u16::from_be_bytes(buf.get(i..i + 2)?.try_into().ok()?));
    let version = buf.first()? >> 4;
    let (mut i, mut proto, src, dst, size) = match version {
        4 => {
            let h = (buf[0] & 15) as usize * 4;
            let total = u32::from(word(2)?);
            if h < 20 || h > buf.len() || total < h as u32 || word(6)? & 0x1fff != 0 {
                return None;
            }
            (
                h,
                buf[9],
                IpAddr::from(Ipv4Addr::from(<[u8; 4]>::try_from(buf.get(12..16)?).ok()?)),
                IpAddr::from(Ipv4Addr::from(<[u8; 4]>::try_from(buf.get(16..20)?).ok()?)),
                total,
            )
        }
        6 => (
            40,
            *buf.get(6)?,
            IpAddr::from(Ipv6Addr::from(<[u8; 16]>::try_from(buf.get(8..24)?).ok()?)),
            IpAddr::from(Ipv6Addr::from(<[u8; 16]>::try_from(buf.get(24..40)?).ok()?)),
            40 + u32::from(word(4)?),
        ),
        _ => return None,
    };
    if version == 6 {
        for _ in 0..4 {
            match proto {
                0 | 43 | 60 => {
                    let next = *buf.get(i)?;
                    i += 8 * (1 + usize::from(*buf.get(i + 1)?));
                    proto = next;
                }
                44 => {
                    if word(i + 2)? & 0xfff8 != 0 {
                        return None;
                    }
                    proto = *buf.get(i)?;
                    i += 8;
                }
                _ => break,
            }
        }
    }
    let (sport, dport, echo_id, reset) = match proto {
        6 | 17 => {
            let min = if proto == 6 { 20 } else { 8 };
            if i + min > size as usize || i + min > buf.len() {
                return None;
            }
            if proto == 6 {
                let header = usize::from(buf[i + 12] >> 4) * 4;
                if header < min || i + header > size as usize {
                    return None;
                }
            } else if word(i + 4)? < 8 {
                return None;
            }
            (
                word(i)?,
                word(i + 2)?,
                0,
                proto == 6 && buf[i + 13] & 4 != 0,
            )
        }
        1 | 58
            if i + 8 <= size as usize
                && i + 8 <= buf.len()
                && matches!((version, proto, buf[i]), (4, 1, 0 | 8) | (6, 58, 128 | 129))
                && buf[i + 1] == 0 =>
        {
            (0, 0, word(i + 4)?, false)
        }
        _ => return None,
    };
    Some(Packet {
        key: Key {
            proto,
            src,
            dst,
            sport,
            dport,
            echo_id,
        },
        size,
        reset,
    })
}
#[derive(Default)]
struct Count {
    packets: u64,
    bytes: u64,
    replies: u64,
    last: u64,
}
#[derive(Serialize)]
pub(super) struct Event {
    pub(super) src: IpAddr,
    pub(super) dst: IpAddr,
    proto: &'static str,
    sport: u16,
    dport: u16,
    event: &'static str,
    packets: u64,
    bytes: u64,
    reply_bytes: u64,
}
#[derive(Default)]
pub(super) struct Tracker {
    flows: HashMap<Key, Count>,
    pub(super) limited: bool,
}
impl Tracker {
    pub(super) fn prune(&mut self, sec: u64) {
        self.flows.retain(|_, v| sec.saturating_sub(v.last) < 60);
    }
    pub(super) fn observe(&mut self, buf: &[u8], out: bool, now: u64) -> Option<Event> {
        let packet = parse(buf)?;
        let mut k = packet.key;
        if !out {
            std::mem::swap(&mut k.src, &mut k.dst);
            std::mem::swap(&mut k.sport, &mut k.dport);
        }
        let new = !self.flows.contains_key(&k);
        if new && !out {
            return None;
        }
        if new && self.flows.len() >= 256 {
            self.limited = true;
            return None;
        }
        let count = self.flows.entry(k).or_default();
        let reply = !out && count.replies == 0;
        if out {
            count.packets += 1;
            count.bytes += u64::from(packet.size);
        } else {
            count.replies += u64::from(packet.size);
        }
        count.last = now;
        if !new && !reply && !packet.reset {
            return None;
        }
        let e = Event {
            src: k.src,
            dst: k.dst,
            sport: k.sport,
            dport: k.dport,
            proto: match k.proto {
                6 => "tcp",
                17 => "udp",
                58 => "icmpv6",
                _ => "icmp",
            },
            event: if packet.reset {
                "gone"
            } else if new {
                "new"
            } else {
                "replied"
            },
            packets: count.packets,
            bytes: count.bytes,
            reply_bytes: count.replies,
        };
        if packet.reset {
            self.flows.remove(&k);
        }
        Some(e)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ip(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut b = vec![0; 40];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&40u16.to_be_bytes());
        b[9] = 6;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b[20..22].copy_from_slice(&src_port.to_be_bytes());
        b[22..24].copy_from_slice(&dst_port.to_be_bytes());
        b[32] = 5 << 4;
        b
    }
    #[test]
    fn only_observed_tunnel_transitions_are_reported() {
        let a = [10, 0, 0, 2];
        let b = [192, 0, 2, 1];
        let out = ip(a, b, 12345, 443);
        let mut back = ip(b, a, 443, 12345);
        let mut t = Tracker::default();
        assert!(t.observe(&back, false, 1).is_none());
        assert_eq!(t.observe(&out, true, 2).unwrap().event, "new");
        assert!(t.observe(&out, true, 3).is_none());
        let e = t.observe(&back, false, 4).unwrap();
        assert_eq!(e.event, "replied");
        assert_eq!((e.packets, e.bytes, e.reply_bytes), (2, 80, 40));
        back[33] = 4;
        assert_eq!(t.observe(&back, false, 5).unwrap().event, "gone");
        assert!(t.observe(&out[..13], true, 6).is_none());
        let mut frag = out.clone();
        frag[7] = 1;
        assert!(t.observe(&frag, true, 6).is_none());
        assert_eq!(t.observe(&out, true, 7).unwrap().event, "new");
        t.prune(67);
        assert!(t.flows.is_empty());
    }
    #[test]
    fn parses_bounded_ipv6_extensions_and_caps_distinct_flows() {
        let mut b = vec![0; 56];
        b[0] = 0x60;
        b[5] = 16;
        b[6] = 0;
        b[40] = 17;
        b[48..50].copy_from_slice(&55u16.to_be_bytes());
        b[50..52].copy_from_slice(&53u16.to_be_bytes());
        b[52..54].copy_from_slice(&8u16.to_be_bytes());
        let mut t = Tracker::default();
        let e = t.observe(&b, true, 2).unwrap();
        assert_eq!((e.proto, e.dport), ("udp", 53));
        b[41] = 9;
        assert!(t.observe(&b, true, 2).is_none());
        for n in 0..300 {
            t.observe(&ip([10, 0, 0, 2], [192, 0, 2, 1], n, 443), true, 2);
        }
        assert_eq!(t.flows.len(), 256);
        assert!(t.limited);
    }
    #[test]
    fn echo_identifiers_disambiguate_replies_and_invalid_headers_are_ignored() {
        let mut req = ip([10, 0, 0, 2], [192, 0, 2, 5], 0, 0);
        req[9] = 1;
        req[20] = 8;
        req[25] = 1;
        let mut t = Tracker::default();
        assert_eq!(t.observe(&req, true, 0).unwrap().proto, "icmp");
        let mut reply = req.clone();
        reply[12..16].copy_from_slice(&req[16..20]);
        reply[16..20].copy_from_slice(&req[12..16]);
        reply[20] = 0;
        reply[25] = 2;
        assert!(t.observe(&reply, false, 1).is_none());
        reply[25] = 1;
        assert_eq!(t.observe(&reply, false, 2).unwrap().event, "replied");
        req[20] = 3;
        assert!(t.observe(&req, true, 3).is_none());
        req[9] = 6;
        req[32] = 0;
        assert!(t.observe(&req, true, 3).is_none());
    }
}
