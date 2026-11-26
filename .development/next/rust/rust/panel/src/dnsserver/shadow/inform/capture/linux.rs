use super::super::{wire, Identity, Target, Trace};
use crate::dnsserver::shadow::renew::capture::{open_packet_receiver, read_packet};
use std::{
    ffi::CStr,
    io,
    mem::size_of_val,
    os::fd::{AsRawFd, OwnedFd},
    time::Instant,
};

const MAX_READS: u8 = 32;
const MAX_EVENTS: u8 = 8;
const BUFFER: usize = 1536;

pub(in crate::dnsserver::shadow::inform) struct Capture {
    fd: OwnedFd,
    index: i32,
    identity: Identity,
    started: Instant,
}

impl Capture {
    pub(in crate::dnsserver::shadow::inform) fn open(
        name: &CStr,
        target: Target<'_>,
        identity: Identity,
    ) -> io::Result<Self> {
        let index = i32::try_from(target.index).map_err(|_| io::ErrorKind::InvalidInput)?;
        let fd = open_packet_receiver(name, target.index, identity.mac, Some(identity.xid))?;
        Ok(Self {
            fd,
            index,
            identity,
            started: Instant::now(),
        })
    }

    pub(in crate::dnsserver::shadow::inform) fn finish(
        self,
        trace: &Trace,
        scope: &tokio::sync::watch::Receiver<()>,
    ) {
        let mut buffer = [0; BUFFER];
        let mut counters = Counts::default();
        for _ in 0..MAX_READS {
            if scope.has_changed().is_err() {
                return;
            }
            let frame = match read_packet(&self.fd, self.index, &mut buffer) {
                Ok(frame) => frame,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    trace.step("wire.error", "Не удалось прочитать захват DHCP на WAN");
                    break;
                }
            };
            let observed = frame.and_then(|(len, outgoing)| {
                wire::observation(&buffer[..len], self.identity, outgoing)
            });
            counters.observe(observed, trace);
        }
        if scope.has_changed().is_ok() {
            counters.finish(trace, self.started, self.statistics());
        }
    }

    fn statistics(&self) -> Option<(u32, u32)> {
        let mut stats: libc::tpacket_stats = unsafe { std::mem::zeroed() };
        let mut size = size_of_val(&stats) as libc::socklen_t;
        // The kernel writes only the supplied bounded ABI struct, synchronously.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&mut stats as *mut libc::tpacket_stats).cast(),
                &mut size,
            )
        };
        (rc == 0 && size as usize == size_of_val(&stats))
            .then_some((stats.tp_packets, stats.tp_drops))
    }
}

#[derive(Default)]
struct Counts {
    outgoing: u8,
    incoming: u8,
    incomplete: u8,
}

impl Counts {
    fn observe(&mut self, observed: Option<wire::Observation>, trace: &Trace) {
        let Some(observed) = observed else {
            self.incomplete += 1;
            return;
        };
        if observed.outgoing {
            self.outgoing += 1;
        } else {
            self.incoming += 1;
        }
        if self.outgoing + self.incoming <= MAX_EVENTS {
            trace.step("wire.packet", &observed.summary());
        }
    }

    fn finish(self, trace: &Trace, started: Instant, stats: Option<(u32, u32)>) {
        let reached = self.outgoing + self.incoming + self.incomplete == MAX_READS;
        let mut text = format!(
            "DHCP текущей транзакции на WAN: исходящих={}, входящих={}; посторонних/неполных={}; предел чтения={reached}",
            self.outgoing, self.incoming, self.incomplete,
        );
        if let Some((packets, dropped)) = stats {
            text.push_str(&format!("; в сокет захвата={packets}, потеряно={dropped}"));
        }
        text.push_str(". Нулевой счётчик не доказывает отсутствие пакета вне окна захвата.");
        trace.timed("wire.finish", &text, started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsserver::shadow::Diagnostics;
    use std::net::Ipv4Addr;

    #[test]
    fn shadow_wire_bounded_summary_caps_details_and_preserves_receive_totals() {
        let id = Identity {
            client: Ipv4Addr::new(192, 0, 2, 5),
            server: None,
            mac: [2, 1, 2, 3, 4, 5],
            xid: [9, 8, 7, 6],
        };
        let request = wire::request(id);
        let mut frame = vec![0; 20 + request.len()];
        frame[0] = 0x45;
        frame[9] = 17;
        let total = (frame.len() as u16).to_be_bytes();
        frame[2..4].copy_from_slice(&total);
        frame[12..16].copy_from_slice(&id.client.octets());
        frame[16..20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());
        frame[20..].copy_from_slice(&request);
        let diagnostics = Diagnostics::default();
        diagnostics.set(true);
        let event = diagnostics.begin("dhcp.start", "fixture");
        let trace = event.trace();
        let mut counts = Counts::default();
        for _ in 0..31 {
            counts.observe(wire::observation(&frame, id, true), &trace);
        }
        counts.observe(None, &trace);
        counts.finish(&trace, Instant::now(), Some((34, 2)));
        let report = diagnostics.read();
        let rows = report["attempts"][0]["events"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row["stage"] == "wire.packet")
                .count(),
            8
        );
        let summary = rows.last().unwrap()["message"].as_str().unwrap();
        assert!(summary
            .contains("исходящих=31, входящих=0; посторонних/неполных=1; предел чтения=true"));
        assert!(summary.contains("в сокет захвата=34, потеряно=2"));
    }
}
