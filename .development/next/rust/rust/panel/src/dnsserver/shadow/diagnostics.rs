//! Bounded telemetry for Shadow discovery. Producers provide fixed summaries
//! and typed values. Command output and packet bytes stay in their parsers.

use super::{now, Log};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const MAX_EVENTS: usize = 48;
const MAX_MESSAGE: usize = 512;

pub(super) fn text(value: &str, max: usize) -> String {
    let end = value.floor_char_boundary(value.len().min(max));
    value[..end]
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_owned()
}

pub(super) fn message(value: &str) -> String {
    text(value, MAX_MESSAGE)
}

pub(super) fn row(stage: &str, summary: &str, duration: Duration) -> Value {
    let mut event = json!({"at":now(), "stage":text(stage, 64), "message":message(summary)});
    let ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    if ms != 0 {
        event["duration_ms"] = json!(ms);
    }
    event
}

/// A worker can append while firmware discovery is running. A detached worker
/// loses its destination when the attempt finishes or diagnostics are disabled.
#[derive(Clone, Default)]
pub(super) struct Trace(Option<(Arc<Mutex<Log>>, u64)>);

impl Trace {
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn active(&self) -> bool {
        self.0.is_some()
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn wire_scope(&self) -> Option<tokio::sync::watch::Receiver<()>> {
        let (log, id) = self.0.as_ref()?;
        let log = log.lock().unwrap();
        log.entries
            .iter()
            .find(|row| row["id"] == *id && row.get("finished_at").is_none())?;
        log.scope
            .as_ref()
            .map(tokio::sync::watch::Sender::subscribe)
    }

    pub(super) fn new(log: &Arc<Mutex<Log>>, id: Option<u64>) -> Self {
        Self(id.map(|id| (log.clone(), id)))
    }

    pub(super) fn step(&self, stage: &str, summary: &str) {
        self.timed(stage, summary, Duration::ZERO);
    }

    pub(super) fn timed(&self, stage: &str, summary: &str, duration: Duration) {
        let Some((log, id)) = &self.0 else { return };
        let mut log = log.lock().unwrap();
        let Some(attempt) = log
            .entries
            .iter_mut()
            .find(|row| row["id"] == *id && row.get("finished_at").is_none())
        else {
            return;
        };
        let events = attempt["events"].as_array_mut().unwrap();
        if events.len() == MAX_EVENTS {
            events.remove(0);
        }
        events.push(row(stage, summary, duration));
    }

    pub(super) fn native_command(&self, operation: &str, ok: bool, elapsed: Duration) {
        let expected = matches!(
            operation,
            "show ip name-server" | "show interface" | "show log"
        ) || operation
            .strip_prefix("show interface ")
            .is_some_and(super::discovery::native);
        if expected {
            let outcome = if ok {
                "прочитано"
            } else {
                "ошибка чтения"
            };
            self.timed(
                "native.command",
                &format!("{operation}: {outcome}"),
                elapsed,
            );
        }
    }

    pub(super) fn wan_verified(&self, iface: &str, verified: bool) {
        if super::discovery::native(iface) {
            self.step(
                "wan.verify",
                &format!("{iface}: принадлежность адресу активного WAN подтверждена={verified}"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Diagnostics;
    use super::*;

    #[test]
    fn shadow_diagnostics_bound_events_and_utf8_and_omit_zero_duration() {
        let log = Diagnostics::default();
        log.set(true);
        let mut event = log.begin("discovery.start", "fixture");
        let trace = event.trace();
        for _ in 0..50 {
            trace.step("old", "fixture");
        }
        trace.native_command("show interface ISP", false, Duration::from_millis(17));
        trace.native_command("show interface ISP\nraw", true, Duration::from_millis(20));
        trace.step("unicode", &format!("Ж\r\n{}", "界".repeat(200)));
        event.record(
            vec!["192.0.2.53:53".into(), "name.example".into()],
            "ошибка\n",
            None,
        );
        trace.step("late", "closed");
        let log = log.read();
        let attempt = &log["attempts"][0];
        let events = attempt["events"].as_array().unwrap();
        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(events[46]["stage"], "native.command");
        assert_eq!(events[46]["duration_ms"], 17);
        let last = &events[47];
        assert_eq!(last["stage"], "unicode");
        assert!(last.get("duration_ms").is_none());
        let summary = last["message"].as_str().unwrap();
        assert!(summary.len() <= MAX_MESSAGE);
        assert!(!summary.chars().any(char::is_control));
        assert_eq!(attempt["servers"], json!(["192.0.2.53:53"]));
        assert_eq!(attempt["error"], "ошибка");
    }

    #[test]
    fn shadow_diagnostics_disabled_worker_does_not_write_to_new_attempt() {
        let log = Diagnostics::default();
        log.set(true);
        let old = log.begin("old", "fixture");
        let trace = old.trace();
        log.set(false);
        log.set(true);
        let new = log.begin("new", "fixture");
        trace.native_command("show log", true, Duration::from_millis(17));
        drop(old);
        let snapshot = log.read();
        let attempt = &snapshot["attempts"][0];
        assert_eq!(snapshot["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(attempt["events"].as_array().unwrap().len(), 1);
        assert_eq!(attempt["events"][0]["stage"], "new");
        assert!(attempt.get("finished_at").is_none());
        drop(new);
    }
}
