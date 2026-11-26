use super::*;
use nfqws2_config::Config;

const PPPOE: &str = r#"Interface, name = "PPPoE0"
               id: PPPoE0
             type: PPPoE
        connected: yes
          address: 192.0.2.5
           global: yes
        defaultgw: yes
   security-level: public
             ipv6:
                  address: 2001:db8::1
                defaultgw: no"#;

struct Fixture {
    native: String,
    routes: &'static str,
}
#[test]
fn replay_requires_current_literal_selector_after_a_wildcard_was_saved() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("nfqws2.conf");
    let path = conf.to_str().unwrap();
    let previous = ["ppp+".into()];
    assert_eq!(current_selectors(path, &[]).unwrap(), Some(vec![]));
    assert_eq!(current_selectors(path, &previous).unwrap(), None);
    for data in [
        "ISP_INTERFACE=\"$UPLINK\"\n",
        "ISP_INTERFACE=\"\"\n",
        "# removed\n",
    ] {
        std::fs::write(&conf, data).unwrap();
        assert_eq!(current_selectors(path, &previous).unwrap(), None);
    }
    std::fs::write(&conf, "ISP_INTERFACE=\"ppp1\"\n").unwrap();
    assert_eq!(
        current_selectors(path, &previous).unwrap(),
        Some(vec!["ppp1".into()])
    );
    std::fs::write(&conf, "ISP_INTERFACE=\"eth3 ppp+\"\n").unwrap();
    let current = current_selectors(path, &previous).unwrap().unwrap();
    assert_eq!(current, ["eth3"]);
    assert!(!selected(&current, "ppp1"));
}
impl Runner for Fixture {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        let answer = match (program, args) {
            ("ip", ["-4", "route", "show", "table", "main", "default"]) => self.routes,
            ("ndmc", ["-c", "show interface"]) => &self.native,
            ("fw4", ["-q", "network", "wan"]) | ("fw4", ["-q", "device", "ppp0"]) => "provider",
            ("fw4", ["-q", "network", "lan"]) | ("fw4", ["-q", "device", "eth1"]) => "home",
            _ => panic!("unexpected command {program} {args:?}"),
        };
        Ok(answer.into())
    }
}

#[test]
fn go_wildcard_conf_uses_only_matching_active_public_uplink() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = Config::from_resolver(&Resolver::new_at(tmp.path()));
    config.apply_nf_config("ISP_INTERFACE=\"\"\n").unwrap();
    assert_eq!(config.wan_ifaces, ["eth3"]);
    config.apply_nf_config("ISP_INTERFACE=\"ppp+\"\n").unwrap();
    assert_eq!(config.wan_ifaces, ["ppp+"]);

    let mut route = Fixture {
        native: PPPOE.into(),
        routes: "default dev ppp0 metric 10\ndefault via 192.0.2.1 dev br0\ndefault dev eth1 metric 20\ndefault dev awg0",
    };
    let hosts = vec![
        ("ppp0".into(), "192.0.2.5".parse().unwrap()),
        ("eth1".into(), "192.0.2.6".parse().unwrap()),
        ("br0".into(), "192.168.1.1".parse().unwrap()),
    ];
    let detect_host = |r: &Fixture, hosts: &[_], current: &[String]| {
        detect(r, Platform::Entware, hosts, &config.wan_ifaces, current).unwrap()
    };
    assert_eq!(detect_host(&route, &hosts, &[]), ["ppp0"]);
    assert!(detect_host(&route, &hosts, &["eth1".into()]).is_empty());
    assert_eq!(
        detect(&route, Platform::OpenWrt, &hosts, &[], &[]).unwrap(),
        ["ppp0"]
    );
    let mut duplicate = hosts.clone();
    duplicate.push(("br1".into(), "192.0.2.5".parse().unwrap()));
    assert!(detect_host(&route, &duplicate, &[]).is_empty());
    for (old, new) in [
        ("security-level: public", "security-level: private"),
        ("defaultgw: yes", "defaultgw: no"),
        ("connected: yes", "connected: no"),
        ("type: PPPoE", "type: Wireguard"),
        ("address: 192.0.2.5", "address: 192.0.2.10"),
    ] {
        route.native = PPPOE.replace(old, new);
        assert!(detect_host(&route, &hosts, &[]).is_empty());
    }
    route.native = PPPOE.into();
    route.routes = "default dev br0\nblackhole default";
    assert!(detect_host(&route, &hosts, &[]).is_empty());
}
