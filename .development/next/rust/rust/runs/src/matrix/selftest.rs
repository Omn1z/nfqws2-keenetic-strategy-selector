use super::{
    lock, measure, sandbox, test_strategy, Config, Control, ProbeTarget, Sandbox, Strategy,
};
use serde_json::{json, Value};
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::{io, sync::Arc};

/// Run one entry from the installed package's built-in catalog on router slot zero.
pub fn run(
    cfg: &nfqws2_config::Config,
    catalog: &[u8],
    index: usize,
    targets: Vec<String>,
) -> io::Result<Value> {
    let entries: Vec<Value> = serde_json::from_slice(catalog)?;
    let entry = entries
        .get(index)
        .filter(|v| v["source"] == "builtin")
        .ok_or_else(|| crate::invalid("индекс стратегии вне встроенного каталога"))?;
    let strategy: Strategy = serde_json::from_value(entry.clone())?;
    let targets = measure::selftest_targets(targets)?;
    let hosts: Vec<_> = targets
        .iter()
        .map(|target| ProbeTarget {
            label: &target.label,
            authority: &target.authority,
        })
        .collect();
    let curl = measure::curl()?;
    let config = Config {
        nfqws_bin: cfg.nfqws_bin.clone(),
        wan_ifaces: cfg.wan_ifaces.clone(),
        base_args: cfg.base_args.clone(),
        first_queue: cfg.first_queue,
        main_queue: cfg.main_queue,
        port_base: cfg.port_base,
        ports_per_worker: cfg.ports_per_worker,
    };
    let control = Arc::new(Control::new(1, false));
    #[cfg(unix)]
    let _signals = Signals::register(&control)?;
    let _owner = lock()?;
    sandbox::recover()?;
    let mut slot = Sandbox::new(&config, 0)?;
    let ports = slot.port_range();
    let result = test_strategy(
        &mut slot,
        &strategy,
        &hosts,
        &curl,
        &control,
        &super::dns::Resolver::new(None),
        None,
    );
    slot.cleanup()?;
    let row = result?.ok_or(io::ErrorKind::Interrupted)?;
    if let Some(error) = row["error"].as_str() {
        return Err(io::Error::other(error));
    }
    Ok(
        json!({"strategy":entry, "queue":cfg.first_queue, "ports":format!("{}-{}",ports.0,ports.1),"results":row["per_target"]}),
    )
}

#[cfg(unix)]
struct Signals(Vec<signal_hook_registry::SigId>);
#[cfg(unix)]
impl Signals {
    fn register(control: &Arc<Control>) -> io::Result<Self> {
        let mut ids = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let control = control.clone();
            // The signal handler only sets the cancellation flag. The worker
            // reaps the engine and removes its own rules on the normal path.
            ids.0.push(unsafe {
                signal_hook_registry::register(signal, move || {
                    control.cancel.store(true, Ordering::Release)
                })?
            });
        }
        Ok(ids)
    }
}
#[cfg(unix)]
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook_registry::unregister(id);
        }
    }
}
