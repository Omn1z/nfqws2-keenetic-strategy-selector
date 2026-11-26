use nfqws2_awg_rules::kernel::{FlowRoute, FlowSnapshot};
use nfqws2_store::Store;
use std::{io, net::IpAddr};

#[derive(Default)]
pub(super) struct Decisions(FlowSnapshot);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Decision {
    pub(super) kind: &'static str,
    pub(super) rule: Option<usize>,
    pub(super) reason: String,
    pub(super) tunnel_id: String,
    pub(super) tunnel_iface: String,
}

impl Decisions {
    pub(super) fn read(db: &Store, boot: &str) -> io::Result<Self> {
        FlowSnapshot::read(db, boot).map(Self)
    }

    pub(super) fn classify(&self, source: IpAddr, destination: IpAddr) -> Decision {
        let policy = self.0.classify(source, destination);
        let (kind, detail, id, iface) = match policy.route {
            FlowRoute::Unknown => ("unknown", "", "", ""),
            FlowRoute::Direct => ("direct", "direct", policy.rule_owner.unwrap_or(""), ""),
            FlowRoute::Blocked => ("blocked", "blocked", policy.rule_owner.unwrap_or(""), ""),
            FlowRoute::Tunnel { id, iface } => ("tunnel", iface, id, iface),
        };
        let reason = if let Some((rule, name)) = policy.rule.zip(policy.name) {
            format!("flow: rule #{rule} {name:?} -> {detail}")
        } else {
            match kind {
                "direct" => "flow: no AWG2 rule matched".into(),
                "blocked" => "flow: protected AWG route unavailable".into(),
                "tunnel" => format!("flow: applied AWG route -> {iface}"),
                _ => String::new(),
            }
        };
        Decision {
            kind,
            rule: policy.rule,
            reason,
            tunnel_id: id.into(),
            tunnel_iface: iface.into(),
        }
    }
}
