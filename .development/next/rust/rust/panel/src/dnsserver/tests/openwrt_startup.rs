use super::{autostart, state};
use nfqws2_openwrt_dns::{Binding, Endpoint};
use std::{env, fs, process::Command};

#[tokio::test]
#[ignore = "requires synthetic UCI configuration in an isolated OpenWrt guest"]
async fn disabled_startup_restores_only_owned_openwrt_dns_options() {
    assert_eq!(
        fs::read_to_string("/suite/dns-startup-fixture").unwrap(),
        "ea1-qemu-airgap"
    );
    for (kind, parent) in [("net", "N2S_PARENT_NET"), ("mnt", "N2S_PARENT_MNT")] {
        assert_ne!(
            fs::read_link(format!("/proc/self/ns/{kind}"))
                .unwrap()
                .as_os_str(),
            env::var_os(parent).unwrap()
        );
    }
    fn uci(args: &[&str]) -> String {
        let result = Command::new("/sbin/uci").args(args).output().unwrap();
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap().trim_end().into()
    }
    let fields = [
        "network.qa_wan.peerdns",
        "network.qa_wan.dns",
        "dhcp.qa_dns.noresolv",
        "dhcp.qa_dns.server",
        "dhcp.qa_dns.cachesize",
    ];
    let options = || fields.map(|field| uci(&["-q", "get", field]));
    let before = options();
    assert_eq!(
        before,
        ["1", "192.0.2.20", "0", "/corp.example/192.0.2.40", "97"]
    );
    let dir = tempfile::tempdir().unwrap();
    let s = state(&dir);
    let manager = s.dnsserver.openwrt.clone();
    let binding = Binding {
        interface: "qa_wan".into(),
        instance: "qa_dns".into(),
        endpoint: Endpoint {
            host: "192.168.203.1".into(),
            port: 5356,
        },
    };
    manager.apply(binding.clone(), "").unwrap();
    assert_eq!(
        options(),
        [
            "0",
            "192.168.203.1",
            "1",
            "192.168.203.1#5356 /corp.example/192.0.2.40",
            "97"
        ]
    );
    drop(s);

    let stopped = state(&dir);
    autostart(&stopped).await;
    let status = stopped.dnsserver.dashboard().await;
    assert_eq!(status["running"], false);
    assert_eq!(status["last_error"], "");
    assert_eq!(options(), before);
    assert!(manager.current_binding().unwrap().is_none());

    manager.apply(binding.clone(), "").unwrap();
    uci(&["set", "network.qa_wan.dns=192.0.2.71"]);
    uci(&["commit", "network"]);
    let foreign = options();
    autostart(&stopped).await;
    let status = stopped.dnsserver.dashboard().await;
    assert!(!status["last_error"].as_str().unwrap().is_empty());
    assert_eq!(status["running"], false);
    assert_eq!(manager.current_binding().unwrap(), Some(binding));
    assert_eq!(options(), foreign);
}
