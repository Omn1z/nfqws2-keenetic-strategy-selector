mod hook;
mod presets;
mod wan;
use self::presets::PRESETS;
use crate::{
    data::or_default,
    http::{blocking, ApiError, ApiJson, Shared},
};
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Serialize, Deserialize)]
struct PortRange {
    start: u16,
    end: u16,
}
impl PortRange {
    const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }
}
#[derive(Serialize)]
struct Profile {
    id: &'static str,
    name: &'static str,
    tcp: &'static [PortRange],
    udp: &'static [PortRange],
}
#[derive(Serialize)]
struct Preset {
    id: &'static str,
    name: &'static str,
    source: &'static str,
    profiles: &'static [Profile],
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Rule {
    id: String,
    name: String,
    preset_id: String,
    profile_id: String,
    device_ip: String,
    device_name: String,
    device_mac: String,
    device_iface: String,
    enabled: bool,
    #[serde(default, deserialize_with = "preset_ports")]
    tcp: Vec<PortRange>,
    #[serde(default, deserialize_with = "preset_ports")]
    udp: Vec<PortRange>,
    created_at: i64,
    updated_at: i64,
}
// Go decodes null slices in old JSON. The preset supplies the actual ports.
fn preset_ports<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<PortRange>, D::Error> {
    Option::<Vec<PortRange>>::deserialize(d).map(Option::unwrap_or_default)
}

pub(crate) fn print_wan(mut args: impl Iterator<Item = String>) -> io::Result<()> {
    let conf = args
        .next()
        .ok_or_else(|| invalid("missing ISP interface configuration"))?;
    let saved: Vec<_> = args.collect();
    if saved.iter().any(|s| !wan::wildcard(s)) {
        return Err(invalid("invalid WAN selector"));
    }
    for name in wan::live(&conf, &saved)? {
        println!("{name}");
    }
    Ok(())
}
#[derive(Serialize, Deserialize, Default)]
struct Saved {
    rules: Option<Vec<Rule>>,
}
#[derive(Serialize)]
struct View {
    presets: &'static [Preset],
    rules: Vec<Rule>,
    wan_ifaces: Vec<String>,
    hook_path: String,
}
const FILE: &str = "port_forwarding.json";
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
impl Rule {
    fn normalize(mut self) -> io::Result<Self> {
        let preset = PRESETS
            .iter()
            .find(|p| p.id == self.preset_id.trim())
            .ok_or_else(|| invalid("unknown preset profile"))?;
        let profile = preset
            .profiles
            .iter()
            .find(|p| p.id == self.profile_id.trim())
            .ok_or_else(|| invalid("unknown preset profile"))?;
        let ip = self
            .device_ip
            .trim()
            .parse::<IpAddr>()
            .ok()
            .and_then(|v| match v {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(ip) => ip.to_ipv4_mapped(),
            })
            .ok_or_else(|| invalid("select a LAN device with an IPv4 address"))?;
        self.preset_id = preset.id.into();
        self.profile_id = profile.id.into();
        self.device_ip = ip.to_string();
        self.id = self.id.trim().into();
        self.name = self.name.trim().into();
        if self.name.is_empty() {
            self.name = format!("{} - {}", preset.name, profile.name);
        }
        self.device_name = self.device_name.trim().into();
        self.device_mac = self.device_mac.trim().into();
        self.device_iface = self.device_iface.trim().into();
        self.tcp = profile.tcp.to_vec();
        self.udp = profile.udp.to_vec();
        Ok(self)
    }
}
fn rules(s: &Shared) -> io::Result<Vec<Rule>> {
    let saved: Saved = or_default(&s.store, FILE)?;
    Ok(saved
        .rules
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.normalize().ok())
        .collect())
}
fn view(s: &Shared, rules: Vec<Rule>) -> View {
    let configured = &s.config.wan_ifaces;
    let names: Vec<_> = configured
        .iter()
        .filter(|s| wan::literal(s))
        .cloned()
        .collect();
    View {
        presets: PRESETS,
        rules,
        wan_ifaces: if names.is_empty() {
            wan::live(&s.config.nfqws2_conf, configured).unwrap_or_default()
        } else {
            names
        },
        hook_path: if cfg!(target_os = "linux") {
            s.port_hook.display().to_string()
        } else {
            String::new()
        },
    }
}
fn edit(s: &Shared, change: impl FnOnce(&mut Vec<Rule>) -> io::Result<()>) -> io::Result<View> {
    s.store.transaction(|tx| {
        let old = rules(s)?;
        let mut next = old.clone();
        change(&mut next)?;
        if let Err(err) = tx.save(FILE, &serde_json::json!({"rules":next})) {
            // A directory-sync failure can occur after rename. Reconcile the hook
            // with the version that actually reached the primary.
            let current = rules(s)?;
            hook::apply(&s.port_hook, &s.config, &current)?;
            return Err(err);
        }
        if let Err(err) = hook::apply(&s.port_hook, &s.config, &next) {
            tx.save(FILE, &serde_json::json!({"rules":old}))
                .map_err(|rollback| {
                    io::Error::other(format!("{err}; restore saved forwarding rules: {rollback}"))
                })?;
            hook::apply(&s.port_hook, &s.config, &old).map_err(|rollback| {
                io::Error::other(format!("{err}; restore firewall: {rollback}"))
            })?;
            return Err(err);
        }
        Ok(view(s, next))
    })
}
pub fn restore(s: &Shared) -> io::Result<()> {
    if !std::path::Path::new(&s.config.data_dir)
        .join(FILE)
        .try_exists()?
    {
        return Ok(());
    }
    let all = rules(s)?;
    if !all.is_empty() || s.port_hook.exists() {
        hook::apply(&s.port_hook, &s.config, &all)?;
    }
    Ok(())
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/port-forwarding", get(get_view))
        .route("/api/port-forwarding/rules", post(save))
        .route("/api/port-forwarding/rules/{id}/enabled", post(enable))
        .route("/api/port-forwarding/rules/{id}", delete(remove))
}
async fn get_view(State(s): State<Shared>) -> Result<Json<View>, ApiError> {
    blocking(move || Ok(Json(view(&s, rules(&s)?)))).await
}
async fn save(
    State(s): State<Shared>,
    ApiJson(rule): ApiJson<Rule>,
) -> Result<Json<View>, ApiError> {
    blocking(move || {
        let mut r = rule.normalize()?;
        edit(&s, |rules| {
            let now = now();
            r.updated_at = now;
            if r.id.is_empty() {
                r.id = nfqws2_store::new_id()?;
                r.created_at = now;
                rules.push(r);
            } else {
                let old = rules
                    .iter_mut()
                    .find(|v| v.id == r.id)
                    .ok_or_else(|| invalid("rule not found"))?;
                r.created_at = old.created_at;
                *old = r;
            }
            Ok(())
        })
        .map(Json)
    })
    .await
}
#[derive(Deserialize)]
struct Toggle {
    enabled: bool,
}
async fn enable(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(t): ApiJson<Toggle>,
) -> Result<Json<View>, ApiError> {
    blocking(move || {
        edit(&s, |rules| {
            let rule = rules
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| invalid("rule not found"))?;
            rule.enabled = t.enabled;
            rule.updated_at = now();
            Ok(())
        })
        .map(Json)
    })
    .await
}
async fn remove(State(s): State<Shared>, Path(id): Path<String>) -> Result<Json<View>, ApiError> {
    blocking(move || {
        edit(&s, |rules| {
            let index = rules
                .iter()
                .position(|r| r.id == id.trim())
                .ok_or_else(|| invalid("rule not found"))?;
            rules.remove(index);
            Ok(())
        })
        .map(Json)
    })
    .await
}
