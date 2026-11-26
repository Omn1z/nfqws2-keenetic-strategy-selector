//! Own Keenetic running PPE preferences only while an AWG forwarding policy needs them.
use super::{boot_id, boot_valid, err, kernel, plan::Backend, Journal, Kernel, Plan};
use nfqws2_router_command::Runner;
use nfqws2_store::{Store, Transaction};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{collections::BTreeMap, io};
mod evidence;
mod guards;
mod hook;
#[cfg(test)]
mod tests;
static ENGINE_CHANGES: AtomicUsize = AtomicUsize::new(0);
// DNS may add many addresses between watchdog audits. A process restart or a
// new ownership receipt always requires a fresh read of the vendor settings.
static CONSERVATIVE: Mutex<Option<(String, Instant)>> = Mutex::new(None);

const RECEIPT: &str = "awg-native-acceleration.json";
const LANDMARK: &str = "awg-acceleration-state.json";
const OWNER: &str = "nfqws2-strategy/rust-awg-ppe-v1";
const LIMIT: u64 = 16384;
const FLAGS: [&str; 7] = [
    "net.netfilter.nf_conntrack_fastnat",
    "net.netfilter.nf_conntrack_fastroute",
    "net.netfilter.nf_conntrack_fastnat_xfrm",
    "net.netfilter.nf_conntrack_fastpath_esp",
    "net.core.swnat",
    "net.hwnat.extif_offload",
    "net.hwnat.ppe_enabled",
];
const SNAPSHOT: &str = include_str!("acceleration/snapshot.sh");
const ORPHANS: &str = include_str!("acceleration/orphans.sh");

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Values {
    native: BTreeMap<String, bool>,
    flags: BTreeMap<String, u32>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    owner: String,
    boot: String,
    original: Values,
    id: String,
    guarded: bool,
    hook: bool,
    #[serde(default)]
    retry_after: u64,
}
impl Values {
    fn off(&self) -> Self {
        Self {
            native: self.native.keys().map(|k| (k.clone(), false)).collect(),
            flags: FLAGS.into_iter().map(|k| (k.into(), 0)).collect(),
        }
    }
    fn matches(&self, requested: &Self) -> bool {
        requested
            .native
            .iter()
            .all(|(k, v)| self.native.get(k) == Some(v))
            && requested
                .flags
                .iter()
                .all(|(k, v)| self.flags.get(k).copied().unwrap_or(0) == *v)
    }
}
fn read(k: &Kernel<'_>) -> io::Result<Option<Values>> {
    let script = k.call("sh", &["-c", SNAPSHOT])?;
    if script.is_empty() {
        return Ok(None);
    }
    let mut rows = script.lines();
    if rows.next() != Some("keenetic") {
        return Err(err("не удалось определить платформу PPE"));
    }
    let mut values = Values::default();
    for row in rows {
        let fields: Vec<_> = row.split_whitespace().collect();
        match fields.as_slice() {
            ["ppe", key @ ("hardware" | "software"), state @ ("on" | "off")]
                if values
                    .native
                    .insert((*key).into(), *state == "on")
                    .is_none() => {}
            [name, value] if FLAGS.contains(name) => {
                let value = value
                    .parse()
                    .map_err(|_| err("неизвестное значение sysctl PPE"))?;
                if values.flags.insert((*name).into(), value).is_some() {
                    return Err(err("повтор sysctl PPE"));
                }
            }
            _ => return Err(err("неоднозначное состояние ускорения Keenetic")),
        }
    }
    Ok(Some(values))
}
fn current(k: &Kernel<'_>) -> io::Result<Values> {
    read(k)?.ok_or_else(|| err("недоступно управление PPE Keenetic"))
}
fn saved(db: &Store) -> io::Result<Option<Saved>> {
    let record: Saved = match db.read_runtime(RECEIPT, LIMIT) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if record.owner != OWNER
        || !boot_valid(&record.boot)
        || record.id.len() != 12
        || !record.id.bytes().all(|b| b.is_ascii_hexdigit())
        || record
            .original
            .flags
            .keys()
            .any(|v| !FLAGS.contains(&v.as_str()))
        || record
            .original
            .native
            .keys()
            .any(|v| !matches!(v.as_str(), "hardware" | "software"))
    {
        return Err(err("повреждена запись владения ускорением"));
    }
    Ok(Some(record))
}
pub(super) fn pending(db: &Store) -> io::Result<bool> {
    Ok(saved(db)?.is_some())
}
fn needs(plan: &Plan) -> bool {
    plan.firewall == Backend::Legacy && !plan.empty() && !plan.targets.is_empty()
}
pub(super) fn preflight(k: &Kernel<'_>, plan: &Plan) -> io::Result<()> {
    if needs(plan) {
        read(k)?;
    }
    Ok(())
}

/// Go may restore its original settings after the replacement is armed.
/// This interval can rely on the kernel guard only if both snapshots are off.
pub(super) fn check_parked_handoff(db: &Store, k: &Kernel<'_>, running_go: bool) -> io::Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoPreferences {
        owner: String,
        version: u8,
        boot_id: String,
        sysctls: BTreeMap<String, String>,
        #[serde(default)]
        native_ppe: BTreeMap<String, bool>,
        #[serde(default, rename = "guards_owned")]
        _guards_owned: bool,
    }
    let unsafe_offload = || err("исходное ускорение Go может обойти защиту во время обновления");
    let unknown_restore = || err("не подтверждены исходные настройки ускорения работающей Go-панели");
    let firmware = read(k)?;
    if let Some(values) = &firmware {
        if !values.native.keys().any(|name| name == "hardware")
            || !values.native.keys().any(|name| name == "software")
            || values.native.values().any(|enabled| *enabled)
            || values.flags.values().any(|flag| *flag != 0)
        {
            return Err(unsafe_offload());
        }
    }
    let needs_restore_proof = running_go && firmware.is_some();
    let old: GoPreferences = match db.read_limited(LANDMARK, LIMIT) {
        Ok(old) => old,
        // The stopped process legitimately removes its file; the running Go
        // controller can still restore its in-memory snapshot if it is missing.
        Err(error) if error.kind() == io::ErrorKind::NotFound && needs_restore_proof => {
            return Err(unknown_restore());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if needs_restore_proof && old.native_ppe.len() != 2 {
        return Err(unknown_restore());
    }
    if old.owner != "nfqws2-strategy/awg-acceleration"
        || old.version != 1
        || old.boot_id != boot_id(k)?
        || old.sysctls.iter().any(|(key, value)| {
            !FLAGS.contains(&key.as_str()) || value.parse::<u32>() != Ok(0)
        })
        || old.native_ppe.iter().any(|(key, enabled)| {
            !matches!(key.as_str(), "hardware" | "software") || *enabled
        })
    {
        return Err(unsafe_offload());
    }
    Ok(())
}
fn write(k: &Kernel<'_>, want: &Values, mut got: Values) -> io::Result<()> {
    if got.matches(want) {
        return Ok(());
    }
    let mut switched = false;
    for key in ["hardware", "software"] {
        let Some(&on) = want.native.get(key) else {
            continue;
        };
        if got.native.get(key) != Some(&on) {
            let request = format!("{}ppe {key}", if on { "" } else { "no " });
            k.call(
                "sh",
                &[
                    "-c",
                    r#"LD_PRELOAD= LD_LIBRARY_PATH=/lib:/usr/lib ndmc -c "$1" >/dev/null"#,
                    "awg-accel",
                    &request,
                ],
            )?;
            switched = true;
        }
    }
    if switched {
        if want
            .flags
            .iter()
            .any(|(key, val)| key.starts_with("net.hwnat.") && *val != 0)
        {
            k.call("sleep", &["1"])?;
        }
        for attempt in 0..6 {
            got = current(k)?;
            if want
                .flags
                .iter()
                .all(|(key, value)| *value == 0 || got.flags.contains_key(key))
            {
                break;
            }
            if attempt < 5 {
                k.call("sleep", &["1"])?;
            }
        }
    }
    let mut changed = false;
    for (key, val) in &want.flags {
        if got.flags.get(key).copied().unwrap_or(0) != *val {
            k.call("sysctl", &["-w", &format!("{key}={val}")])?;
            changed = true;
        }
    }
    if changed || switched {
        k.call("sh",&["-c","if test -e /proc/sys/net/core/swnat_reset; then sysctl -w net.core.swnat_reset=1 >/dev/null; fi"])?;
    }
    if !current(k)?.matches(want) {
        return Err(err("ядро не подтвердило состояние PPE"));
    }
    Ok(())
}
fn begin(
    db: &Store,
    tx: &Transaction<'_>,
    k: &Kernel<'_>,
    plan: &Plan,
) -> io::Result<Option<Saved>> {
    let old = saved(db)?;
    if let Some(r) = old.as_ref() {
        if r.boot == boot_id(k)? {
            if needs(plan) {
                if let Err(error) = hook::set(k, r, true) {
                    conservative(k)?;
                    return Err(error);
                }
            }
            return Ok(old);
        }
    }
    if old.is_none() && !needs(plan) {
        return Ok(None);
    }
    let Some(live) = read(k)? else {
        return if old.is_some() {
            Err(err("платформа сохранённого состояния PPE недоступна"))
        } else {
            Ok(None)
        };
    };
    let boot = boot_id(k)?;
    if let Some(record) = old {
        remove_guards(k, &record)?;
        tx.delete_runtime(RECEIPT)?;
        if !needs(plan) {
            return Ok(None);
        }
    }
    match db.read_limited::<serde::de::IgnoredAny>(LANDMARK, 65536) {
        Ok(_) => return Err(err("ускорение уже принадлежит работающему контроллеру Go")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if !k.call("sh", &["-c", ORPHANS])?.is_empty() {
        return Err(err("обнаружена защита PPE без действующей записи владения"));
    }
    let record = Saved {
        owner: OWNER.into(),
        boot,
        original: live,
        id: nfqws2_store::new_id()?,
        hook: true,
        guarded: false,
        retry_after: 0,
    };
    save(tx, &record)?;
    hook::set(k, &record, true)?;
    Ok(Some(record))
}
fn save(tx: &Transaction<'_>, r: &Saved) -> io::Result<()> {
    tx.save_runtime_bounded(RECEIPT, r, LIMIT)
}
fn remove_guards(k: &Kernel<'_>, r: &Saved) -> io::Result<()> {
    if r.hook {
        hook::set(k, r, false)?;
    }
    if r.guarded {
        guards::synchronize(k, r, None)?;
    }
    Ok(())
}
fn flush(k: &Kernel<'_>) -> io::Result<()> {
    k.call(
        "sh",
        &[
            "-c",
            "test -w /proc/sys/net/hwnat/ppe_flush && sysctl -w net.hwnat.ppe_flush=1 >/dev/null",
        ],
    )
    .map(drop)
}
fn conservative(k: &Kernel<'_>) -> io::Result<()> {
    let live = current(k)?;
    write(k, &live.off(), live)
}
fn pause(k: &Kernel<'_>, record: &Saved) -> io::Result<()> {
    let live = current(k)?;
    if record.guarded
        && live.native.values().any(|on| *on)
        && live.flags.contains_key("net.hwnat.ppe_enabled")
    {
        let mut off = live.off();
        off.native.clone_from(&live.native);
        if write(k, &off, live).and_then(|()| flush(k)).is_ok() {
            return Ok(());
        }
    }
    conservative(k)
}
fn permitted(db: &Store, k: &Kernel<'_>, r: &Saved) -> bool {
    std::env::var_os("N2S_AWG_SELECTIVE_ACCEL").as_deref() == Some(std::ffi::OsStr::new("1"))
        && ENGINE_CHANGES.load(Ordering::Acquire) == 0
        && r.original.native.len() == 2
        // The installer's temporary guard is attested only while both PPE
        // paths are off. Ordinary selective mode resumes after acceptance.
        && super::handoff::parked_guard::Armed::read(db).is_ok_and(|hold| hold.is_none())
        && guards::capable(k).unwrap_or(false)
}
fn selective(k: &Kernel<'_>, r: &Saved, ifaces: &[String]) -> io::Result<()> {
    guards::synchronize(k, r, Some(ifaces))?;
    if !guards::intact(k, r, ifaces)? {
        return Err(err("невозможно подтвердить защиту NFQUEUE и AWG"));
    }
    let live = current(k)?;
    let mut on = live.off();
    for key in ["hardware", "software"] {
        on.native.insert(key.into(), true);
    }
    for key in [
        "net.core.swnat",
        "net.hwnat.extif_offload",
        "net.hwnat.ppe_enabled",
    ] {
        on.flags.insert(key.into(), 1);
    }
    if !live.matches(&on) {
        // Load the vendor module with its datapath paused. NDMC can queue a
        // firewall rebuild asynchronously when native preferences change.
        let mut loaded = live.off();
        loaded.native.clone_from(&on.native);
        let switched = !live.matches(&Values {
            native: on.native.clone(),
            ..Default::default()
        });
        write(k, &loaded, live)?;
        if switched {
            k.call("sleep", &["1"])?;
        }
        let mut ready = false;
        for attempt in 0..6 {
            let probes = current(k)?;
            if probes.flags.contains_key("net.hwnat.extif_offload")
                && probes.flags.contains_key("net.hwnat.ppe_enabled")
                && flush(k).is_ok()
            {
                ready = true;
                break;
            }
            if attempt < 5 {
                k.call("sleep", &["1"])?;
            }
        }
        if !ready || !guards::intact(k, r, ifaces)? {
            return Err(err("аппаратный datapath или защита PPE недоступны"));
        }
        write(k, &on, current(k)?)?;
    }
    if !guards::intact(k, r, ifaces)? {
        return Err(err("правила PPE изменились после включения"));
    }
    Ok(())
}
fn finish(
    db: &Store,
    tx: &Transaction<'_>,
    k: &Kernel<'_>,
    r: &mut Saved,
    plan: &Plan,
) -> io::Result<()> {
    let now = nfqws2_awg_profile::now();
    if r.retry_after <= now && permitted(db, k, r) {
        let available = r.guarded || guards::available(k, r).unwrap_or(false);
        if available && !r.guarded {
            r.guarded = true;
            save(tx, r)?;
        }
        let ifaces: Vec<_> = plan.targets.keys().cloned().collect();
        CONSERVATIVE.lock().unwrap().take();
        if available && selective(k, r, &ifaces).is_ok() {
            if r.retry_after != 0 {
                r.retry_after = 0;
                save(tx, r)?;
            }
            return Ok(());
        }
        conservative(k)?;
        r.retry_after = now.saturating_add(300);
        save(tx, r)?;
    } else {
        conservative(k)?;
    }
    *CONSERVATIVE.lock().unwrap() = Some((r.id.clone(), Instant::now()));
    Ok(())
}
pub(super) fn learning_paused(db: &Store) -> io::Result<bool> {
    let Some(r) = saved(db)? else {
        return Ok(false);
    };
    Ok(CONSERVATIVE
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|(id, at)| id == &r.id && at.elapsed() < Duration::from_secs(30)))
}
pub(super) fn restore(db: &Store, tx: &Transaction<'_>, k: &Kernel<'_>) -> io::Result<()> {
    let Some(record) = saved(db)? else {
        return Ok(());
    };
    let same = record.boot == boot_id(k)?;
    CONSERVATIVE.lock().unwrap().take();
    if same && record.guarded {
        conservative(k)?;
    }
    remove_guards(k, &record)?;
    if same {
        write(k, &record.original, current(k)?)?;
    }
    tx.delete_runtime(RECEIPT)
}
pub(super) fn verify_released(k: &Kernel<'_>) -> io::Result<()> {
    const RUST_ORPHANS: &str = concat!("set -- rust\n", include_str!("acceleration/orphans.sh"));
    if !k.call("sh", &["-c", RUST_ORPHANS])?.is_empty() {
        return Err(err(
            "после остановки Rust остались цепочки или обработчик PPE",
        ));
    }
    Ok(())
}
pub(super) fn audit(
    db: &Store,
    tx: &Transaction<'_>,
    k: &Kernel<'_>,
    plan: &Plan,
) -> io::Result<()> {
    if !needs(plan) {
        return restore(db, tx, k);
    }
    let record = begin(db, tx, k, plan)?;
    if let Some(mut r) = record {
        finish(db, tx, k, &mut r, plan)?;
    }
    Ok(())
}
pub(super) fn transition(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    old: &Journal,
    new: &Journal,
    work: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let k = kernel(run);
    let record = begin(db, tx, &k, &new.installed).and_then(|record| {
        if let Some(r) = &record {
            pause(&k, r)?;
        }
        Ok(record)
    });
    if let Err(error) = record {
        if !needs(&old.installed) && old.preparing.is_empty() {
            restore(db, tx, &kernel(run))?;
        }
        return Err(error);
    }
    let result = work();
    if let Some(mut record) = record? {
        let current = Journal::read(db)?;
        if current.preparing.is_empty() {
            if !needs(&current.installed) {
                restore(db, tx, &kernel(run))?;
            } else {
                finish(db, tx, &kernel(run), &mut record, &current.installed)?;
            }
        }
    }
    result
}
pub struct EngineChange(());
impl Drop for EngineChange {
    fn drop(&mut self) {
        ENGINE_CHANGES.fetch_sub(1, Ordering::AcqRel);
    }
}
pub fn pause_for_engine(db: &Store, run: &dyn Runner) -> io::Result<EngineChange> {
    ENGINE_CHANGES.fetch_add(1, Ordering::AcqRel);
    let guard = EngineChange(());
    db.transaction(|_| {
        if saved(db)?.is_some() {
            conservative(&kernel(run))?;
        }
        Ok(())
    })?;
    Ok(guard)
}
