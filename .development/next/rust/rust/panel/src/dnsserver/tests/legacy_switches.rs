use super::{config, request, state, Config};
use serde_json::{json, Value};
use std::fs;

#[tokio::test]
async fn old_dns_form_inherits_pools_by_the_rule_ids_seen_in_status() {
    let dir = tempfile::tempdir().unwrap();
    let mut saved = config::defaults();
    saved["listen_host"] = json!("127.0.0.1");
    let rule = |domain: &str, alternate: &str| json!({"enabled":true,"domain":domain,"upstream":{"address":"https://default.example/dns-query"},"pool":[{"address":alternate}]});
    let a = rule("a.example", "https://a-dns.example/dns-query");
    let mut b = rule("b.example", "https://b-dns.example/dns-query");
    b["id"] = json!("");
    b["enabled"] = json!(false);
    let mut c = rule("c.example", "https://c-dns.example/dns-query");
    c["id"] = json!("custom-id");
    saved["rules"] = json!([a, b, c]);
    fs::write(dir.path().join("dnsserver.json"), saved.to_string()).unwrap();

    let app = crate::http::router(state(&dir));
    let status = request(&app, "/api/dnsserver", None, 200).await;
    let before = status["config"]["rules"].as_array().unwrap();
    assert_eq!(before[0]["id"], "rule-1");
    assert_eq!(before[1]["id"], "rule-2");
    let mut form = status["config"].clone();
    form["base_hash"] = status["config_hash"].clone();
    let mut new_rule = before[0].clone();
    new_rule.as_object_mut().unwrap().remove("id");
    new_rule["domain"] = json!("new.example");
    form["rules"] = json!([before[1], before[2], before[0], new_rule]);
    for r in form["rules"].as_array_mut().unwrap() {
        r.as_object_mut().unwrap().remove("pool");
    }
    form["rules"][1]["pool"] = json!([]);

    let updated = request(&app, "/api/dnsserver/config", Some(form), 200).await;
    let after = &updated["config"]["rules"];
    assert_eq!(after[0], before[1]);
    assert_eq!(after[1]["id"], "custom-id");
    assert_eq!(after[1]["pool"], json!([]));
    assert_eq!(after[2], before[0]);
    assert_eq!(after[3]["id"], "rule-4");
    assert_eq!(after[3]["pool"], json!([]));
    assert_eq!(
        state(&dir).dnsserver.status().await["config"]["rules"],
        *after
    );
}

#[tokio::test]
async fn missing_legacy_dns_switches_load_disabled_and_keep_configured_rules() {
    for nulls in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut saved = config::defaults();
        saved["listen_host"] = json!("127.0.0.1");
        saved["rules"] = json!([{"id":"saved", "domain":"special.example", "upstream":{"address":"https://private.example/dns-query"}}]);
        saved["filtering"] =
            json!({"custom_rules":[{"domain":"blocked.example", "category":"ads"}]});
        saved["shadow_dns"] = json!({"domains":[{"domain":"corp.example"}]});
        if nulls {
            saved["filtering"]["enabled"] = Value::Null;
            saved["shadow_dns"]["enabled"] = Value::Null;
            saved["rules"][0]["enabled"] = Value::Null;
        }
        let path = dir.path().join("dnsserver.json");
        fs::write(&path, saved.to_string()).unwrap();
        let app = crate::http::router(state(&dir));
        let status = request(&app, "/api/dnsserver", None, 200).await;
        assert_eq!(status["config_error"], "");
        assert_eq!(status["running"], false);
        let cfg = &status["config"];
        for flag in [
            &cfg["rules"][0]["enabled"],
            &cfg["shadow_dns"]["enabled"],
            &cfg["filtering"]["enabled"],
        ] {
            assert_eq!(*flag, false);
        }
        assert_eq!(cfg["rules"][0]["domain"], "special.example");
        assert_eq!(
            cfg["filtering"]["custom_rules"],
            saved["filtering"]["custom_rules"]
        );
        assert_eq!(cfg["shadow_dns"]["domains"][0]["domain"], "corp.example");
        assert_eq!(
            Config::from_value(cfg)
                .unwrap()
                .servers("special.example")
                .0,
            "default"
        );

        let mut form = cfg.clone();
        form["base_hash"] = status["config_hash"].clone();
        form["cache_size"] = json!(19);
        let changed = request(&app, "/api/dnsserver/config", Some(form), 200).await;
        let restarted = state(&dir).dnsserver.status().await;
        assert_eq!(restarted["config"], changed["config"]);
        assert_eq!(restarted["config"]["cache_size"], 19);
        assert_eq!(restarted["config"]["rules"], cfg["rules"]);

        for field in ["filtering", "shadow_dns"] {
            let mut invalid = saved.clone();
            invalid[field]["enabled"] = json!("false");
            assert!(Config::from_value(&invalid).is_err());
        }
        saved["rules"][0]["enabled"] = json!("false");
        assert!(Config::from_value(&saved).is_err());
    }
}

#[tokio::test]
async fn a_legacy_dns_form_with_null_options_preserves_vpn_policy_filters_and_pools() {
    let dir = tempfile::tempdir().unwrap();
    let mut saved = config::defaults();
    saved["listen_host"] = json!("127.0.0.1");
    saved["route_mode"] = json!("vpn_only");
    saved["fast_dns"] = json!(false);
    saved["scheduler_enabled"] = json!(false);
    saved["cache_ttl_seconds"] = json!(97);
    saved["filtering"] = json!({"enabled":true,"custom_rules":[{"domain":"ads.example","category":"ads"}],"allowlist":["ok.ads.example"],"lists":[]});
    saved["shadow_dns"] = json!({"enabled":true,"domains":[{"domain":"corp.example","include_subdomains":true}],"servers":[]});
    saved["default_pool"] =
        json!([{"address":"https://second.example/dns-query","bootstrap_ips":[]}]);
    saved["rules"][0]["pool"] = saved["default_pool"].clone();
    fs::write(dir.path().join("dnsserver.json"), saved.to_string()).unwrap();
    let app = crate::http::router(state(&dir));
    let status = request(&app, "/api/dnsserver", None, 200).await;
    let mut form = status["config"].clone();
    let mut expected = form.clone();
    form["base_hash"] = status["config_hash"].clone();
    for field in [
        "route_mode",
        "fast_dns",
        "scheduler_enabled",
        "cache_ttl_seconds",
        "filtering",
        "shadow_dns",
        "default_pool",
    ] {
        form[field] = Value::Null;
    }
    form["rules"][0]["pool"] = Value::Null;
    form["cache_size"] = json!(31);
    expected["cache_size"] = json!(31);
    let changed = request(&app, "/api/dnsserver/config", Some(form), 200).await;
    assert_eq!(changed["config"], expected);
    assert_eq!(state(&dir).dnsserver.status().await["config"], expected);

    let mut explicit = expected;
    explicit["base_hash"] = changed["config_hash"].clone();
    explicit["default_pool"] = json!([]);
    explicit["rules"][0]["pool"] = json!([]);
    explicit["shadow_dns"]["enabled"] = json!(false);
    let changed = request(&app, "/api/dnsserver/config", Some(explicit), 200).await;
    assert_eq!(changed["config"]["default_pool"], json!([]));
    assert_eq!(changed["config"]["rules"][0]["pool"], json!([]));
    assert_eq!(changed["config"]["shadow_dns"]["enabled"], false);
    assert_eq!(changed["config"]["route_mode"], "vpn_only");
}
