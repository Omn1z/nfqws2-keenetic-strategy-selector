use nfqws2_config::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static ID: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "n2s-config-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn write(&self, rel: &str, data: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn platform_paths_cache_native_and_legacy_layouts() {
    let tree = Fixture::new();
    let entware = Resolver::new_at(&tree.0);
    assert_eq!(entware.platform(), Platform::Entware);
    assert_eq!(
        entware.path(Key::ModuleDir),
        tree.0.join("opt/lib/nfqws2-strategy/modules")
    );
    assert_eq!(
        entware.path(Key::StrategyInit),
        tree.0.join("opt/etc/init.d/S52nfqws2-strategy")
    );
    assert_eq!(
        entware.join(Key::Nfqws2ListsDir, &["a", "../b.list"]),
        tree.0.join("opt/etc/nfqws2/lists/b.list")
    );
    assert!(entware
        .join(Key::NfqwsBypassFw4, &["unused"])
        .as_os_str()
        .is_empty());
    assert!(Key::from_name("unknown").is_none());
    assert_eq!(Key::from_name("awg_hook"), Some(Key::AwgHook));
    tree.write("etc/rc.common", "");
    tree.write("opt/usr/bin/amneziawg-go", "");
    tree.write("opt/etc/amnezia/amneziawg/example.conf", "");
    let legacy = Resolver::new_at(&tree.0);
    assert_eq!(legacy.platform(), Platform::OpenWrt);
    assert_eq!(
        legacy.path(Key::ModuleDir),
        tree.0.join("usr/lib/nfqws2-strategy/modules")
    );
    assert_eq!(
        legacy.path(Key::Nfqws2Conf),
        tree.0.join("etc/nfqws2/nfqws2.conf")
    );
    assert_eq!(legacy.path(Key::AwgEngineDir), tree.0.join("opt/usr/bin"));
    assert_eq!(
        legacy.path(Key::AwgConfigDir),
        tree.0.join("opt/etc/amnezia/amneziawg")
    );
    assert!(legacy.path(Key::AwgLegacyWatchdog).as_os_str().is_empty());
    tree.write("usr/bin/amneziawg-go", "");
    tree.write("etc/amnezia/amneziawg/example.conf", "");
    let native = Resolver::new_at(&tree.0);
    assert_eq!(native.path(Key::AwgEngineDir), tree.0.join("usr/bin"));
    assert_eq!(
        native.path(Key::AwgConfigDir),
        tree.0.join("etc/amnezia/amneziawg")
    );
    assert_eq!(legacy.path(Key::AwgEngineDir), tree.0.join("opt/usr/bin"));
    assert_eq!(entware.platform(), Platform::Entware);
}

#[test]
fn config_cli_matches_default_schema_and_override_precedence() {
    let tree = Fixture::new();
    tree.write("etc/openwrt_release", "");
    let paths = Resolver::new_at(&tree.0);
    let (base, warning) = Config::load_at(&paths, "dev", "owner/name", |_| None);
    assert_eq!(warning.unwrap().kind(), std::io::ErrorKind::NotFound);
    let json = serde_json::to_value(&base).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 18);
    assert!(json["base_args"].is_null());
    assert_eq!(json["wan_ifaces"], serde_json::json!(["eth3"]));
    assert!(base.awg_wan_ifaces().is_empty());
    assert_eq!(
        (
            base.first_queue,
            base.main_queue,
            base.port_base,
            base.ports_per_worker
        ),
        (200, 300, 50000, 200)
    );
    tree.write("etc/nfqws2/nfqws2.conf", "ISP_INTERFACE='wan1,wan0,wan1'\nNFQWS_BASE_ARGS=\"one two\n # comment\n\nthree # inline\"\n");
    let env = [
        ("N2S_NFQWS2_CONF", "/override/conf"),
        ("N2S_NFQWS_BIN", "/override/bin"),
        ("N2S_LUA_DIR", "/override/lua"),
        ("N2S_SYSTEM_BLOBS_DIR", "/override/blobs"),
        ("N2S_LISTEN", ""),
        ("N2S_DATA", "/override/data"),
        ("N2S_INIT", "/override/init"),
        ("N2S_NFQWS2_INIT", "/override/nfqws-init"),
    ];
    let (cfg, warning) = Config::load_at(&paths, "test", "owner/name", |name| {
        env.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.to_string())
    });
    assert!(warning.is_none());
    assert_eq!(cfg.wan_ifaces, ["wan1", "wan0"]);
    assert_eq!(cfg.awg_wan_ifaces(), ["wan1", "wan0"]);
    assert_eq!(
        cfg.base_args.unwrap(),
        ["one", "two", "three", "#", "inline"]
    );
    assert_eq!(cfg.nfqws2_conf, "/override/conf");
    assert_eq!(cfg.nfqws_bin, "/override/bin");
    assert_eq!(cfg.lua_dir, "/override/lua");
    assert_eq!(cfg.system_blobs_dir, "/override/blobs");
    assert_eq!(cfg.listen_addr, ":8090");
    assert_eq!(cfg.data_dir, "/override/data");
    assert_eq!(cfg.init_script, "/override/init");
    assert_eq!(cfg.nfqws2_init, "/override/nfqws-init");
    assert_eq!(
        (cfg.version.as_str(), cfg.repo.as_str()),
        ("test", "owner/name")
    );
}

#[test]
fn invalid_wan_preserves_existing_config_and_empty_args_serialize_as_null() {
    let mut cfg = Config::default();
    cfg.apply_nf_config("ISP_INTERFACE=wan0\nNFQWS_BASE_ARGS=\"abc\"")
        .unwrap();
    let baseline = cfg.clone();
    assert!(cfg
        .apply_nf_config("ISP_INTERFACE='bad/name'\nNFQWS_BASE_ARGS=\"bad\"")
        .is_err());
    assert_eq!(cfg, baseline);
    cfg.apply_nf_config("ISP_INTERFACE=\"$WAN\"\n").unwrap();
    assert_eq!(cfg, baseline);
    cfg.apply_nf_config("NFQWS_BASE_ARGS=\"\n# comment\n\"")
        .unwrap();
    assert!(cfg.base_args.is_none());
}

#[test]
fn normalized_shell_assignments_preserve_comments_order_quotes_and_crlf() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "ISP_INTERFACE=\" eth4, eth3\teth2.4,,eth4 \"\n",
            "ISP_INTERFACE=\"eth4 eth3 eth2.4\"\n",
            &["eth4", "eth3", "eth2.4"],
        ),
        (
            "  export ISP_INTERFACE='eth4,eth3' \t# eth4,eth3\r\n",
            "  export ISP_INTERFACE='eth4 eth3' \t# eth4,eth3\r\n",
            &["eth4", "eth3"],
        ),
        (
            "ISP_INTERFACE=eth4,\\\neth3\n",
            "ISP_INTERFACE=\"eth4 eth3\"\n",
            &["eth4", "eth3"],
        ),
        (
            "ISP_INTERFACE=eth4\\,eth3\n",
            "ISP_INTERFACE=\"eth4 eth3\"\n",
            &["eth4", "eth3"],
        ),
        (
            "ISP_INTERFACE=eth4\\ eth3",
            "ISP_INTERFACE=eth4\\ eth3",
            &["eth4", "eth3"],
        ),
        (
            "ISP_INTERFACE=\"eth4,\neth3\neth2.4\"\n",
            "ISP_INTERFACE=\"eth4 eth3 eth2.4\"\n",
            &["eth4", "eth3", "eth2.4"],
        ),
        (
            "ISP_INTERFACE=eth4,eth3\nISP_INTERFACE='eth+,br-wan,ppp0:1,+'\n",
            "ISP_INTERFACE=\"eth4 eth3\"\nISP_INTERFACE='eth+ br-wan ppp0:1 +'\n",
            &["eth+", "br-wan", "ppp0:1", "+"],
        ),
        ("ISP_INTERFACE=\"\"", "ISP_INTERFACE=\"\"", &[]),
    ];
    for (src, normalized, ifaces) in cases {
        assert_eq!(&*normalize_wan_interfaces(src).unwrap(), *normalized);
        assert_eq!(wan_interfaces_from_conf(src).unwrap().unwrap(), *ifaces);
    }
    let dynamic = "ISP_INTERFACE=eth4,eth3\nISP_INTERFACE=\"$WAN\"\n";
    assert_eq!(
        normalize_wan_interfaces(dynamic).unwrap(),
        "ISP_INTERFACE=\"eth4 eth3\"\nISP_INTERFACE=\"$WAN\"\n"
    );
    assert!(wan_interfaces_from_conf(dynamic).unwrap().is_none());
    for name in [
        "1234567890123456",
        "bad/name",
        "eth+bad",
        "eth*",
        "eth?",
        "ops#0",
        ".",
        "..",
        "eth\\0",
        "eth\"0",
        "$WAN",
        "интерфейс",
    ] {
        let source = format!("ISP_INTERFACE='eth0,{name}'");
        assert!(wan_interfaces_from_conf(&source).is_err(), "{name}");
        assert!(normalize_wan_interfaces(&source).is_err());
    }
}

#[test]
fn parser_never_evaluates_shell_or_rewrites_unsafe_files() {
    for source in [
        "# ISP_INTERFACE=eth4,eth3\nTCP_PORTS=80,443\n",
        "ISP_INTERFACE=\"$WAN,eth3\"",
        "ISP_INTERFACE=\"${WAN},eth3\"",
        "ISP_INTERFACE=\"${WAN:-eth4,eth3}\"",
        "ISP_INTERFACE=~root",
        "ISP_INTERFACE=`printf literal`",
        "ISP_INTERFACE=\"$(echo x)\"",
        "ISP_INTERFACE=eth4,eth3 # ok\nprintf x",
        "if true; then\nISP_INTERFACE=eth4,eth3\nfi",
        "cat <<'END'\nISP_INTERFACE=eth4,eth3\nEND\n",
        "ISP_INTERFACE=eth4,eth3; false",
        "ISP_INTERFACE=eth4,eth3 cmd",
        "ISP_INTERFACE=\"eth4,eth3\n",
        "NFQWS_ARGS=\"$(printf '\nISP_INTERFACE=eth4,eth3\n')\"",
    ] {
        assert!(
            wan_interfaces_from_conf(source).unwrap().is_none(),
            "{source}"
        );
        assert_eq!(normalize_wan_interfaces(source).unwrap(), source);
    }
    assert_eq!(
        literal_shell_config_value("X=80\nX=443\n", "X")
            .unwrap()
            .as_deref(),
        Some("443")
    );
    assert!(literal_shell_config_value("X=80\nY=$Z", "MISSING")
        .unwrap()
        .is_none());
    assert!(literal_shell_config_value("X=\"$OTHER\"", "X").is_err());
    assert!(literal_shell_config_value("X=443\nprintf x", "X").is_err());
}

const MANAGED: &str = "# BEGIN N2S SERVICE STRATEGIES\nNFQWS_ARGS_CUSTOM=\"profile${NFQWS_ARGS_CUSTOM:+ --new }${NFQWS_ARGS_CUSTOM}\"\nTCP_PORTS='80,443,8443'\n# END N2S SERVICE STRATEGIES\n";

#[test]
fn managed_block_range_selects_only_final_generated_assignments() {
    let base = "ISP_INTERFACE='eth4,eth3'\nTCP_PORTS=443\n";
    for block in [
        MANAGED.to_string(),
        MANAGED.trim_end().to_string(),
        MANAGED.replace('\n', "\r\n"),
    ] {
        let source = format!("{base}{block}");
        assert_eq!(
            managed_service_config_range(&source).unwrap(),
            Some(base.len()..source.len())
        );
        assert_eq!(
            literal_shell_config_value(&source, "TCP_PORTS")
                .unwrap()
                .as_deref(),
            Some("443")
        );
        assert_eq!(
            normalize_wan_interfaces(&source).unwrap(),
            format!("{}{block}", base.replace("eth4,eth3", "eth4 eth3"))
        );
    }
    for q in ['\'', '"'] {
        let s = format!("X={q}line\n# BEGIN N2S SERVICE STRATEGIES\n# END N2S SERVICE STRATEGIES\n{q}\nISP_INTERFACE=eth4,eth3");
        assert!(managed_service_config_range(&s).unwrap().is_none());
        assert_eq!(
            wan_interfaces_from_conf(&s).unwrap().unwrap(),
            ["eth4", "eth3"]
        );
    }
    let escaped = MANAGED.replace("profile", r#"ok\\path\"quote\$dollar\`cmd"#);
    assert!(managed_service_config_range(&escaped).unwrap().is_some());
    for bad in [
        MANAGED.repeat(2),
        MANAGED.replace("# END N2S SERVICE STRATEGIES", ""),
        MANAGED.replace("# BEGIN", " # BEGIN"),
        MANAGED.replace("TCP_PORTS='80,443,8443'", "ISP_INTERFACE=lan"),
        MANAGED.replace("TCP_PORTS='80,443,8443'", "UDP_PORTS=80\nUDP_PORTS=443"),
        MANAGED.replace("profile", "bad\\q"),
        MANAGED.replace("profile", "$VALUE"),
        MANAGED.replace("profile", r#"unescaped"quote"#),
        format!("{MANAGED}TCP_PORTS=999\n"),
    ] {
        assert!(managed_service_config_range(&bad).is_err());
        assert!(normalize_wan_interfaces(&bad).is_err());
        assert!(literal_shell_config_value(&bad, "TCP_PORTS").is_err());
    }
}

#[test]
fn firmware_environment_retains_order_and_filters_loader_duplicates() {
    let parent = [
        "PATH=/opt/bin:/bin",
        "LD_LIBRARY_PATH=/opt/lib",
        "HOME=/opt/root",
        "LD_PRELOAD=/opt/lib/u.so",
        "LD_LIBRARY_PATH=/usr/lib",
        "OTHER=a=b",
    ];
    assert_eq!(
        native_env(parent),
        [
            "PATH=/opt/bin:/bin",
            "HOME=/opt/root",
            "OTHER=a=b",
            "LD_LIBRARY_PATH=/lib:/usr/lib"
        ]
    );
    assert_eq!(native_env([]), ["LD_LIBRARY_PATH=/lib:/usr/lib"]);
}
