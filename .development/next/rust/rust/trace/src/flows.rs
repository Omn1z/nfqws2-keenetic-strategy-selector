use nfqws2_monitor::Conn;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

const MAX_FLOWS: usize = 512;
const MAX_EVENTS: usize = 2048;
#[derive(Serialize)]
pub struct Event {
    at_ms: u64,
    kind: &'static str,
    proto: String,
    dst: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    note: String,
}
#[derive(Serialize)]
pub struct Flow {
    proto: String,
    dst: String,
    state: String,
    first_ms: u64,
    last_ms: u64,
    samples: u64,
    max_packets: u64,
    max_bytes: u64,
    unreplied: bool,
    gone: bool,
    #[serde(skip)]
    last_unreplied: bool,
    #[serde(skip)]
    generation: u32,
}
impl Flow {
    fn event(&self, at_ms: u64, kind: &'static str, note: &str) -> Event {
        Event {
            at_ms,
            kind,
            note: note.into(),
            proto: self.proto.clone(),
            dst: self.dst.clone(),
        }
    }
}
#[derive(Default)]
pub struct Tracker {
    flows: BTreeMap<(String, IpAddr, u64, u64), Flow>,
    events: usize,
    generation: u32,
    pub limited: bool,
}
impl Tracker {
    pub fn sample(
        &mut self,
        path: &std::path::Path,
        ip: IpAddr,
        ms: u64,
    ) -> std::io::Result<Vec<Event>> {
        self.generation += 1;
        let mut batch = Vec::new();
        let mut append = |e: Event| {
            if self.events < MAX_EVENTS {
                batch.push(e);
                self.events += 1;
            } else {
                self.limited = true;
            }
        };
        nfqws2_monitor::device_flows(path, ip, |c: Conn| {
            let Some(dst) = c.dst else {
                return;
            };
            let key = (c.proto.to_string(), dst, c.dport, c.sport);
            if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
                return;
            }
            let flow = self.flows.entry(key).or_insert_with(|| {
                let dst = if c.dport == 0 {
                    dst.to_string()
                } else {
                    SocketAddr::new(dst, c.dport as u16).to_string()
                };
                let f = Flow {
                    proto: c.proto.to_string(),
                    dst,
                    state: String::new(),
                    first_ms: ms,
                    last_ms: ms,
                    samples: 0,
                    max_packets: 0,
                    max_bytes: 0,
                    unreplied: false,
                    gone: false,
                    last_unreplied: false,
                    generation: 0,
                };
                append(f.event(ms, "new", &c.state));
                f
            });
            if flow.generation == self.generation {
                return;
            }
            if flow.gone {
                append(flow.event(ms, "new", &c.state));
                flow.gone = false;
                flow.last_unreplied = false;
            }
            flow.generation = self.generation;
            flow.last_ms = ms;
            flow.samples += 1;
            flow.state = c.state.into_owned();
            flow.max_packets = flow.max_packets.max(c.packets);
            flow.max_bytes = flow.max_bytes.max(c.bytes.saturating_add(c.reply_bytes));
            if c.unreplied && !flow.last_unreplied {
                flow.unreplied = true;
                append(flow.event(ms, "unreplied", "нет ответа от назначения"));
            }
            if !c.unreplied && flow.last_unreplied {
                append(flow.event(ms, "replied", "ответ появился"));
            }
            flow.last_unreplied = c.unreplied;
        })?;
        for f in self
            .flows
            .values_mut()
            .filter(|f| f.generation != self.generation && !f.gone)
        {
            f.gone = true;
            append(f.event(ms, "gone", "соединение закрыто/сброшено"));
        }
        if self.flows.len() >= MAX_FLOWS {
            self.limited = true;
        }
        Ok(batch)
    }
    pub fn finish(self) -> Vec<Flow> {
        let mut flows: Vec<_> = self.flows.into_values().collect();
        flows.sort_by_key(|f| f.first_ms);
        flows
    }
}
