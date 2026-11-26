use super::*;
use crate::{
    uci::{self, Section},
    Endpoint,
};
use std::{collections::BTreeMap, sync::Arc};
use tempfile::tempdir;

#[derive(Default)]
struct Uci {
    packages: BTreeMap<String, Vec<Section>>,
    changes: BTreeMap<String, Vec<String>>,
    writes: Vec<String>,
    calls: usize,
    fail: Option<String>,
    foreign_after: Option<String>,
    generation: usize,
}
#[derive(Clone)]
struct Fake(Arc<Mutex<Uci>>);
impl Uci {
    fn export(&self, pkg: &str) -> String {
        let mut out = format!("package {pkg}\n");
        for s in &self.packages[pkg] {
            out.push_str(&format!("config {}", s.kind));
            if !s.id.starts_with('@') {
                out.push_str(&format!(" '{}'", s.id));
            }
            out.push('\n');
            for (key, val) in &s.options {
                for v in &val.values {
                    out.push_str(&format!(
                        " {} {key} '{}'\n",
                        val.kind,
                        v.replace('\'', "'\\''")
                    ));
                }
            }
        }
        out.trim_end().into()
    }
    fn sections(&self) -> (String, String) {
        (self.export("network"), self.export("dhcp"))
    }
    fn applied_network(&self) -> &Section {
        &self.packages["network"][1]
    }
}
impl Runner for Fake {
    fn run(&self, name: &str, args: &[&str], _: Instant) -> io::Result<String> {
        let mut u = self.0.lock().unwrap();
        u.calls += 1;
        let call = format!("{name} {}", args.join(" "));
        if u.fail.as_deref() == Some(&call) {
            u.fail = None;
            return Err(err("simulated command failure"));
        }
        match (name,args){
            ("uci",["-q","changes",pkg])=>return Ok(u.changes.get(*pkg).map(|v|v.join("\n")).unwrap_or_default()),
            ("uci",["-q","-N","export",pkg])=>return Ok(u.export(pkg)),
            ("uci",["-q","-X","show",q])=>{
                let index=q.trim_start_matches("dhcp.@dnsmasq[").trim_end_matches(']');
                return Ok(format!("dhcp.cfg{}_{}=dnsmasq",u.generation,index));
            }
            ("ubus",["call","network.interface","dump"])=>return Ok(r#"{"interface":[{"interface":"wan","l3_device":"eth1","up":true,"route":[{"target":"0.0.0.0","mask":0}]}]}"#.into()),
            ("uci",["-q",op @ ("delete"|"set"|"add_list"),arg])=>{
                let (key,value)=arg.split_once('=').unwrap_or((arg,""));
                let names:Vec<_>=key.split('.').collect();let [pkg,id,field]=names.as_slice()else{return Err(err("invalid test UCI key"));};
                let section=u.packages.get_mut(*pkg).unwrap().iter_mut().find(|s|s.id==*id).unwrap();
                match *op{
                    "delete"=>{section.options.remove(*field);},
                    "set"=>{section.options.insert(field.to_string(),OptionValue::scalar(value));},
                    _=>section.options.entry(field.to_string()).or_insert_with(||OptionValue::list(vec![])).values.push(value.into()),
                }
                u.changes.entry(pkg.to_string()).or_default().push(format!("{key}={value}"));
            }
            ("uci",["-q","commit",pkg])=>{u.changes.remove(*pkg);if *pkg=="dhcp"{u.generation+=1;}}
            ("ubus",["call","network","reload"])|("/etc/init.d/dnsmasq",["reload",_])=>(),
            _=>return Err(err(format!("unexpected mock command {call}"))),
        }
        if u.foreign_after.as_deref() == Some(&call) {
            u.foreign_after = None;
            u.changes
                .entry("dhcp".into())
                .or_default()
                .push("dhcp.lan.start=80".into());
        }
        u.writes.push(call);
        Ok(String::new())
    }
}
fn fixture(root: &Path) -> (Manager, Fake, Binding) {
    let network=Configuration::parse("package network\nconfig interface 'lan'\noption proto static\nconfig interface 'wan'\n option proto dhcp\n list dns '192.0.2.1'\n list dns '192.0.2.2'","network").unwrap();
    let dhcp=Configuration::parse("package dhcp\nconfig dnsmasq\n option cachesize '1000'\n list interface 'lan'\n list server '/corp.example/192.0.2.5'\n list server '/#/#'\n list server '192.0.2.10'\nconfig dhcp lan\n option start 100","dhcp").unwrap();
    let u = Uci {
        packages: BTreeMap::from([
            ("dhcp".into(), dhcp.sections),
            ("network".into(), network.sections),
        ]),
        ..Uci::default()
    };
    let fake = Fake(Arc::new(Mutex::new(u)));
    let manager = Manager {
        root: root.into(),
        supported: true,
        runner: Box::new(fake.clone()),
        mutex: Mutex::new(()),
    };
    let binding = Binding {
        interface: "wan".into(),
        instance: "@dnsmasq[0]".into(),
        endpoint: Endpoint {
            host: "192.168.1.1".into(),
            port: 5356,
        },
    };
    (manager, fake, binding)
}
#[test]
fn parses_quotes_and_rejects_ambiguous_input_or_selectors() {
    let c = Configuration::parse(
        "package dhcp\nconfig dnsmasq named\n option x 'a'\\''b'\nconfig dnsmasq\n option empty ''",
        "dhcp",
    )
    .unwrap();
    assert_eq!(c.sections[0].scalar("x"), "a'b");
    assert_eq!(c.sections[1].id, "@dnsmasq[1]");
    assert_eq!(c.sections[1].options["empty"], OptionValue::scalar(""));
    for input in [
        "package other",
        "config dnsmasq x\n option y 1\nlist y 2",
        "config dnsmasq\n option x '",
        "config dnsmasq x\nconfig dnsmasq x",
    ] {
        assert!(Configuration::parse(input, "dhcp").is_err());
    }
    for s in [
        "@dnsmasq[-1]",
        "@dnsmasq[00]",
        "@dnsmasq[1024]",
        "@interface[0]",
        "x.server",
        "",
    ] {
        assert!(!uci::valid_instance(s));
    }
    for s in ["/corp/192.0.2.10", "/lan/", "//192.0.2.1"] {
        assert!(conditional(s));
    }
    for s in ["192.0.2.1", "/corp/#/8.8.8.8", "/"] {
        assert!(!conditional(s));
    }
}
#[test]
fn apply_inspect_noop_reapply_and_restore_exact_original() {
    let dir = tempdir().unwrap();
    let (m, f, b) = fixture(dir.path());
    let original = f.0.lock().unwrap().sections();
    let state = m.status().unwrap();
    assert_eq!(state.interfaces[0]["id"], "wan");
    assert_eq!(state.interfaces[0]["default"], true);
    assert_eq!(state.instances[0]["id"], "@dnsmasq[0]");
    assert_eq!(state.revision.len(), 64);
    m.apply(b.clone(), &state.revision).unwrap();
    assert_eq!(m.current_binding().unwrap(), Some(b.clone()));
    let count = {
        let f = f.0.lock().unwrap();
        assert_eq!(f.applied_network().values("dns"), ["192.168.1.1"]);
        assert_eq!(
            f.packages["dhcp"][0].values("server"),
            ["192.168.1.1#5356", "/corp.example/192.0.2.5"]
        );
        assert!(f
            .writes
            .iter()
            .any(|s| s == "/etc/init.d/dnsmasq reload cfg1_0"));
        f.writes.len()
    };
    m.apply(b.clone(), "").unwrap();
    assert_eq!(f.0.lock().unwrap().writes.len(), count);
    let mut moved = b;
    moved.endpoint.port = 5357;
    m.apply(moved, "").unwrap();
    m.restore("").unwrap();
    assert_eq!(f.0.lock().unwrap().sections(), original);
    assert!(!dir.path().join(SNAP).exists());
    assert!(dir.path().join(format!("{SNAP}.lock")).exists());
    let calls = f.0.lock().unwrap().calls;
    m.restore("").unwrap();
    assert_eq!(f.0.lock().unwrap().calls, calls);
}

#[test]
fn disabled_dnsmasq_uses_openwrt_config_get_bool_values() {
    for (val, enabled) in [
        ("1", false),
        ("on", false),
        ("yes", false),
        ("true", false),
        ("enabled", false),
        ("off", true),
        ("0", true),
    ] {
        let c = Configuration::parse(
            &format!("config dnsmasq lan\n option disabled '{val}'"),
            "dhcp",
        )
        .unwrap();
        assert_eq!(c.sections[0].enabled(), enabled, "disabled={val}");
    }
}
#[test]
fn stale_revisions_and_external_changes_preserve_user_data() {
    let dir = tempdir().unwrap();
    let (m, f, b) = fixture(dir.path());
    assert!(m.apply(b.clone(), "stale").is_err());
    assert!(f.0.lock().unwrap().writes.is_empty());
    m.apply(b, "").unwrap();
    {
        let mut u = f.0.lock().unwrap();
        u.packages.get_mut("network").unwrap()[1]
            .options
            .insert("dns".into(), OptionValue::list(vec!["203.0.113.5".into()]));
    }
    let n = f.0.lock().unwrap().writes.len();
    assert!(!m.status().unwrap().conflict.is_empty());
    assert!(m.restore("").is_err());
    assert_eq!(f.0.lock().unwrap().writes.len(), n);
    assert!(dir.path().join(SNAP).exists());
    assert_eq!(
        f.0.lock().unwrap().applied_network().values("dns"),
        ["203.0.113.5"]
    );
}
#[test]
fn rollback_reloads_after_failure_and_retains_restorable_snapshot() {
    for failed in [
        "uci -q add_list dhcp.@dnsmasq[0].server=192.168.1.1#5356",
        "uci -q commit network",
        "uci -q commit dhcp",
        "ubus call network reload",
        "/etc/init.d/dnsmasq reload cfg1_0",
    ] {
        let dir = tempdir().unwrap();
        let (m, f, b) = fixture(dir.path());
        let orig = f.0.lock().unwrap().sections();
        f.0.lock().unwrap().fail = Some(failed.into());
        assert!(m.apply(b, "").is_err(), "{failed}");
        assert_eq!(f.0.lock().unwrap().sections(), orig);
        assert!(!dir.path().join(SNAP).exists(), "{failed}");
    }
    let dir = tempdir().unwrap();
    let (m, f, b) = fixture(dir.path());
    m.apply(b, "").unwrap();
    let applied = f.0.lock().unwrap().sections();
    f.0.lock().unwrap().fail = Some("ubus call network reload".into());
    assert!(m.restore("").is_err());
    assert_eq!(f.0.lock().unwrap().sections(), applied);
    assert!(m.current_binding().unwrap().is_some());
    m.restore("").unwrap();
}
#[test]
fn foreign_staging_and_unidentified_instances_are_never_committed() {
    let dir = tempdir().unwrap();
    let (m, f, b) = fixture(dir.path());
    f.0.lock().unwrap().foreign_after = Some("uci -q set dhcp.@dnsmasq[0].noresolv=1".into());
    assert!(m.apply(b, "").is_err());
    assert!(f
        .0
        .lock()
        .unwrap()
        .writes
        .iter()
        .all(|line| !line.contains(" commit ")));
    assert!(m.status().unwrap().pending);
    assert!(m.restore("").is_err());
    {
        let mut u = f.0.lock().unwrap();
        u.changes
            .get_mut("dhcp")
            .unwrap()
            .retain(|l| !l.starts_with("dhcp.lan.start"));
    }
    m.restore("").unwrap();
}
#[test]
fn reordered_anonymous_sections_and_tuning_preserve_instance_ownership() {
    let dir = tempdir().unwrap();
    let (m, f, b) = fixture(dir.path());
    m.apply(b, "").unwrap();
    {
        let mut u = f.0.lock().unwrap();
        let dhcp = u.packages.get_mut("dhcp").unwrap();
        dhcp[0].id = "@dnsmasq[1]".into();
        dhcp[0]
            .options
            .insert("cachesize".into(), OptionValue::scalar("2000"));
        dhcp.insert(
            0,
            Section {
                id: "@dnsmasq[0]".into(),
                kind: "dnsmasq".into(),
                options: Options::from([("interface".into(), OptionValue::scalar("guest"))]),
            },
        );
    }
    assert_eq!(m.status().unwrap().binding.unwrap().instance, "@dnsmasq[1]");
    m.restore("").unwrap();
    let u = f.0.lock().unwrap();
    assert_eq!(u.packages["dhcp"][1].scalar("cachesize"), "2000");
    assert_eq!(u.packages["dhcp"][0].options.len(), 1);
}
#[test]
fn lock_snapshot_validation_and_legacy_rebind() {
    let dir = tempdir().unwrap();
    let (m, f, b) = fixture(dir.path());
    let lock = m.lock(Instant::now() + Duration::from_secs(1)).unwrap();
    assert!(m.lock(Instant::now()).is_err());
    drop(lock);
    m.apply(b, "").unwrap();
    let mut s = m.read().unwrap().unwrap();
    s.scope.clear();
    m.save(Some(&s)).unwrap();
    f.0.lock().unwrap().packages.get_mut("dhcp").unwrap()[0]
        .options
        .insert("cachesize".into(), OptionValue::scalar("5000"));
    let view = m.status().unwrap();
    assert_eq!(view.rebind_instance, "@dnsmasq[0]");
    assert!(m.restore("").is_err());
    assert!(m.rebind("@dnsmasq[0]", "stale").is_err());
    m.rebind("@dnsmasq[0]", &view.revision).unwrap();
    m.restore("").unwrap();
    s.original.insert(
        "network.wan.password".into(),
        OptionValue::scalar("invalid"),
    );
    fs::write(dir.path().join(SNAP), serde_json::to_vec(&s).unwrap()).unwrap();
    let n = f.0.lock().unwrap().writes.len();
    assert!(m.restore("").is_err());
    assert_eq!(f.0.lock().unwrap().writes.len(), n);
}

// Generated by the Go manager after applying its anonymous-dnsmasq test
// fixture, including characters Go escapes when computing the identity hash.
#[test]
fn restores_go_snapshot_with_identical_revision_and_identity() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("../tests/fixtures/go_binding.json")).unwrap();
    let dir = tempdir().unwrap();
    let (mut manager, f, _) = self::fixture(dir.path());
    let stored: Snapshot = serde_json::from_value(fixture["snapshot"].clone()).unwrap();
    fs::write(
        dir.path().join(SNAP),
        serde_json::to_vec(&fixture["snapshot"]).unwrap(),
    )
    .unwrap();
    struct OriginalExport(Fake, Value);
    impl Runner for OriginalExport {
        fn run(&self, p: &str, args: &[&str], t: Instant) -> io::Result<String> {
            // Keep byte-for-byte Go fixture formatting until the first mutation.
            if let ["-q", "-N", "export", pkg] = args {
                if self.0 .0.lock().unwrap().writes.is_empty() {
                    return Ok(self.1[*pkg].as_str().unwrap().into());
                }
            }
            self.0.run(p, args, t)
        }
    }
    for pkg in ["dhcp", "network"] {
        let c = Configuration::parse(fixture[pkg].as_str().unwrap(), pkg).unwrap();
        f.0.lock().unwrap().packages.insert(pkg.into(), c.sections);
    }
    manager.runner = Box::new(OriginalExport(f.clone(), fixture.clone()));
    let state = manager.status().unwrap();
    assert!(state.conflict.is_empty());
    assert_eq!(state.revision, fixture["revision"]);
    manager.restore(&state.revision).unwrap();
    let u = f.0.lock().unwrap();
    let dhcp = Configuration::parse(&u.export("dhcp"), "dhcp").unwrap();
    let net = Configuration::parse(&u.export("network"), "network").unwrap();
    assert_eq!(
        stored.binding.options(&net, &dhcp).unwrap(),
        stored.original
    );
    assert_eq!(dhcp.sections[0].scalar("filter"), "x<web>&\u{2028}");
}
