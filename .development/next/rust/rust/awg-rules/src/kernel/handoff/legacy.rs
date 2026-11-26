//! The Go client watchdog restores the single-table path only for the selected
//! full-mode connection when the multi-policy builder has no usable rules.
use super::{err, io, plan::Family, BTreeSet, Plan, Prefix, Routing, Value};
use crate::kernel::{plan::LegacyFull, Kernel};

pub(super) fn standalone(r: &Routing, doc: &Value) -> bool {
    r.go_watchdog_full(doc)
}

const MARK: &str = "0x10000000/0x10000000";

fn mismatch() -> io::Error {
    err("не подтверждена живая одиночная политика Go AWG2_MARK/table 998")
}

const CHECK_DNS_OWNER: &str = r#"
test "$1" = "${1##*[!0-9]}" || exit 1
for proto in udp tcp; do
    case "$proto" in udp) state=07;; tcp) state=0A;; esac
    count=0
    for table in "/proc/$1/net/$proto" "/proc/$1/net/${proto}6"; do
        test -e "$table" || continue
        sockets=$(awk -v state="$state" '$4==state && toupper($2) ~ /:14EA$/ { print $2 ":" $10 }' "$table") || exit 1
        for item in $sockets; do
            case "$item" in 00000000:14[Ee][Aa]:*|00000000000000000000000000000000:14[Ee][Aa]:*) ;; *) exit 1;; esac
            inode=${item##*:}
            case "$inode" in ''|0|*[!0-9]*) exit 1;; esac
            own=0
            for fd in /proc/"$1"/fd/*; do
                if test "$(readlink "$fd" 2>/dev/null)" = "socket:[$inode]"; then own=1; break; fi
            done
            test "$own" = 1 || exit 1
            count=$((count + 1))
        done
    done
    test "$count" -gt 0 || exit 1
done
echo owned"#;

pub(super) fn dns_bridges(k: &Kernel<'_>, pid: u32) -> io::Result<Vec<String>> {
    let invalid = || err("не подтверждены DNS-сокеты Go и перенаправления на порт 5354");
    let names = k.call(
        "sh",
        &[
            "-c",
            "for d in /sys/class/net/br*; do test -e \"$d\" && echo \"${d##*/}\"; done; :",
        ],
    )?;
    let wanted: BTreeSet<_> = names.lines().collect();
    if wanted.is_empty()
        || wanted.len() > 128
        || !wanted.iter().all(|br| crate::kernel::valid_dns_bridge(br))
    {
        return Err(invalid());
    }
    let expected: BTreeSet<_> = wanted
        .iter()
        .flat_map(|&br| [(br, "udp"), (br, "tcp")])
        .collect();
    for family in [Family::V4, Family::V6] {
        if family == Family::V6 && !k.ipv6_stack()? {
            continue;
        }
        let rules = k.call(family.firewall(), &["-w", "-t", "nat", "-S", "PREROUTING"])?;
        let mut actual = BTreeSet::new();
        for line in rules.lines() {
            if let Some(binding) = super::go_dns_redirect(line) {
                if !actual.insert(binding) {
                    return Err(invalid());
                }
            }
        }
        if actual != expected {
            return Err(invalid());
        }
    }
    if k.call(
        "sh",
        &["-c", CHECK_DNS_OWNER, "dns-owner", &pid.to_string()],
    )?
    .trim()
        != "owned"
    {
        return Err(invalid());
    }
    Ok(wanted.into_iter().map(str::to_owned).collect())
}

fn chain(
    rows: &str,
    family: Family,
    exempt: &BTreeSet<Prefix>,
    scope: Option<&crate::kernel::legacy_scope::Scope>,
) -> io::Result<bool> {
    let name = if family == Family::V4 {
        "AWG2_MARK"
    } else {
        "AWG2_MARK6"
    };
    let rows: Vec<Vec<_>> = rows
        .lines()
        .map(|l| l.split_ascii_whitespace().collect())
        .collect();
    for parent in ["OUTPUT", "PREROUTING"] {
        if !super::go_jumps(&rows, parent, name, true) {
            return Err(mismatch());
        }
    }
    let mut rules = rows
        .iter()
        .filter(|r| r.starts_with(&["-A", name]))
        .map(|r| &r[2..]);
    for mark in ["0x20000000/0x20000000", MARK] {
        if rules.next() != Some(["-m", "mark", "--mark", mark, "-j", "RETURN"].as_slice()) {
            return Err(mismatch());
        }
    }
    let mut expected = exempt.clone();
    let source = scope.map(|s| s.go_rules(family)).unwrap_or_default();
    let mut source = source.into_iter().peekable();
    let mut marked = false;
    for rule in rules {
        if marked {
            return Err(mismatch());
        }
        match rule {
            ["-d", s, "-j", "RETURN"] if expected.remove(&s.parse()?) => (),
            ["-j", "MARK", "--set-xmark", MARK]
                if expected.is_empty() && source.peek().is_none() =>
            {
                marked = true
            }
            _ if expected.is_empty() => {
                let mut w: Vec<String> = rule.iter().map(|s| s.to_string()).collect();
                if w.first().is_some_and(|s| s == "-s") && w.len() > 1 {
                    w[1] = w[1].parse::<Prefix>()?.to_string();
                }
                if w.get(2).is_some_and(|s| s == "--mac-source") && w.len() > 3 {
                    w[3].make_ascii_lowercase();
                }
                if source.next().as_ref() != Some(&w) {
                    return Err(mismatch());
                }
            }
            _ => return Err(mismatch()),
        }
    }
    if !expected.is_empty() || source.peek().is_some() {
        return Err(mismatch());
    }
    Ok(marked)
}

fn rule_and_table(k: &Kernel<'_>, family: Family, iface: &str, blackhole: bool) -> io::Result<()> {
    let rules = k.listing(family, &["rule", "show"])?;
    let mut found = false;
    for row in rules.lines() {
        let w: Vec<_> = row.split_ascii_whitespace().collect();
        if !w
            .windows(2)
            .any(|p| p == ["lookup", "998"] || p == ["table", "998"])
        {
            continue;
        }
        if found
            || !matches!(w.as_slice(),[pref,"from","all","fwmark",MARK,"lookup","998"] if pref.trim_end_matches(':').parse::<u16>().is_ok())
        {
            return Err(mismatch());
        }
        found = true;
    }
    let rows = k.listing(family, &["route", "show", "table", "998"])?;
    let mut through = false;
    let mut fenced = false;
    for row in rows.lines() {
        let w: Vec<_> = row.split_ascii_whitespace().collect();
        let (attrs, guard) = match w.as_slice() {
            ["default", "dev", dev, rest @ ..] if *dev == iface && !through => {
                through = true;
                (rest, false)
            }
            ["blackhole" | "6", "default", rest @ ..] if !fenced => {
                fenced = true;
                (rest, true)
            }
            _ => return Err(mismatch()),
        };
        let mut labels = BTreeSet::new();
        let mut attrs = attrs.chunks_exact(2);
        if !attrs.all(|a| {
            labels.insert(a[0])
                && match a {
                    ["table", "998"] | ["proto", "boot" | "3"] => true,
                    ["scope", "link" | "253"] => !guard,
                    ["metric", "1000"] => guard && family == Family::V4,
                    ["metric", "32760"] => guard && family == Family::V6,
                    ["dev", "lo"] => guard && family == Family::V6,
                    ["metric", "1024"] => !guard && family == Family::V6,
                    ["pref", "medium" | "0"] => family == Family::V6,
                    _ => false,
                }
        }) || !attrs.remainder().is_empty()
            || guard && !labels.contains("metric")
        {
            return Err(mismatch());
        }
    }
    if !found || !through || fenced != blackhole {
        return Err(mismatch());
    }
    // An unrelated rule before Go's automatically allocated priority can
    // capture the mark even with the expected table and classifier in place.
    let probe = if family == Family::V4 {
        "9.9.9.9"
    } else {
        "2620:fe::fe"
    };
    let route = k.call(
        "ip",
        &[family.flag(), "route", "get", probe, "mark", "0x10000000"],
    )?;
    if !route
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|p| p == ["dev", iface])
    {
        return Err(mismatch());
    }
    Ok(())
}

fn global_reject(filters: &str) -> io::Result<Option<&str>> {
    let mut rules = filters
        .lines()
        .filter(|line| line.starts_with("-A FORWARD "));
    let first = rules.next();
    let tagged = |line: &str| line.contains("awg2-v6-noleak");
    if rules.any(tagged) {
        return Err(mismatch());
    }
    let Some(rule) = first.filter(|line| tagged(line)) else {
        return Ok(None);
    };
    match rule.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
        ["-A", "FORWARD", "-o", wan, "-m", "comment", "--comment", tag, "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"]
            if matches!(*tag, "awg2-v6-noleak" | "\"awg2-v6-noleak\"") && LegacyFull::valid_wan(wan) =>
        {
            Ok(Some(wan))
        }
        _ => Err(mismatch()),
    }
}

pub(super) fn multi_reject(k: &Kernel<'_>) -> io::Result<Option<String>> {
    if k.firewall_backend()? != super::plan::Backend::Legacy || !k.ipv6_stack()? {
        return Ok(None);
    }
    let filters = k.call("ip6tables", &["-w", "-t", "filter", "-S", "FORWARD"])?;
    global_reject(&filters)
        .map(|wan| wan.map(str::to_owned))
        .map_err(|_| err("не подтверждено действующее правило AWG2_MULTI для IPv6"))
}

pub(super) fn ipv6(k: &Kernel<'_>, doc: &Value) -> io::Result<LegacyFull> {
    if !k.ipv6_stack()? {
        return Ok(LegacyFull::Ipv4Only);
    }
    let classifier = k.call("ip6tables", &["-t", "mangle", "-S", "AWG2_MARK6"])?;
    let marks = classifier
        .lines()
        .filter(|l| {
            l.split_ascii_whitespace().collect::<Vec<_>>()
                == ["-A", "AWG2_MARK6", "-j", "MARK", "--set-xmark", MARK]
        })
        .count();
    let filters = k.call("ip6tables", &["-t", "filter", "-S", "FORWARD"])?;
    match (marks, global_reject(&filters)?) {
        (1, None) => Ok(LegacyFull::Dual),
        (0, Some(wan)) => {
            let active = doc["servers"]
                .as_array()
                .and_then(|s| s.iter().find(|r| r["id"] == doc["active_id"]))
                .ok_or_else(mismatch)?;
            // Only a literal IPv6 transport selects the IPv6 default gateway.
            let ipv6_endpoint = LegacyFull::ipv6_endpoint(&active["config"])?;
            Ok(LegacyFull::ForwardReject {
                wan: wan.into(),
                ipv6_endpoint,
            })
        }
        _ => Err(mismatch()),
    }
}

pub(super) fn verify(
    k: &Kernel<'_>,
    db: &nfqws2_store::Store,
    plan: &Plan,
    doc: &Value,
) -> io::Result<()> {
    let endpoints = plan.full_endpoints.as_ref().ok_or_else(mismatch)?;
    let active = doc["active_id"].as_str().ok_or_else(mismatch)?;
    let cfg = &doc["servers"]
        .as_array()
        .and_then(|s| s.iter().find(|r| r["id"] == active))
        .ok_or_else(mismatch)?["config"];
    if cfg["routing"]["active"] != true || cfg["routing"]["mode"] != "full" {
        return Err(mismatch());
    }
    let permanent = cfg["client"]["double_tunnel_mode"] == "permanent";
    let state = ipv6(k, doc)?;
    let (mut live, _) =
        crate::kernel::legacy_scope::capture(k, db, doc, &state, nfqws2_awg_profile::now())?;
    if let Some(s) = &mut live {
        s.tunnel_route = plan
            .legacy_scope
            .as_ref()
            .is_some_and(|scope| scope.tunnel_route);
    }
    if live != plan.legacy_scope {
        return Err(mismatch());
    }
    if plan.legacy_full.as_ref() != Some(&state) {
        return Err(mismatch());
    }
    for family in [Family::V4, Family::V6] {
        if family == Family::V6 && state == LegacyFull::Ipv4Only {
            continue;
        }
        let private: &[&str] = if family == Family::V4 {
            &[
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
            ]
        } else {
            &["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
        };
        let mut exempt = private
            .iter()
            .map(|p| p.parse())
            .collect::<io::Result<BTreeSet<_>>>()?;
        exempt.extend(
            endpoints
                .iter()
                .filter(|ip| Family::of(**ip) == family)
                .copied()
                .map(Prefix::host),
        );
        let rows = k.call(family.firewall(), &["-t", "mangle", "-S"])?;
        let marked = chain(&rows, family, &exempt, live.as_ref())?;
        if !marked && family == Family::V6 && matches!(state, LegacyFull::ForwardReject { .. }) {
            if live.as_ref().is_some_and(|s| s.needs_tunnel()) {
                let iface = plan.prefixes.get(&Family::V4.any()).ok_or_else(mismatch)?;
                rule_and_table(k, family, iface, permanent)?;
            }
            continue;
        }
        let (sel, iface) = plan
            .flows()
            .find(|(s, _)| s.dest.family() == family && s.dest.any())
            .ok_or_else(mismatch)?;
        let primary = plan.targets.get(iface).ok_or_else(mismatch)?;
        if !marked || primary.id != active || plan.effective(sel, iface) != Some(iface) {
            return Err(mismatch());
        }
        rule_and_table(
            k,
            family,
            iface,
            permanent || family == Family::V4 && plan.killswitch,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::kernel) mod tests {
    use super::*;
    use nfqws2_router_command::Runner;
    use serde_json::json;
    use std::time::Instant;

    pub(in crate::kernel) struct Go {
        pub(in crate::kernel) dual: bool,
        pub(in crate::kernel) wrong_table: bool,
        pub(in crate::kernel) stranger: bool,
    }
    impl Runner for Go {
        fn run(&self, cmd: &str, args: &[&str], _: Instant) -> io::Result<String> {
            match (cmd, args) {
                ("sh", ["-c", p]) if p.contains("/proc/net/if_inet6") => Ok("ipv6".into()),
                ("iptables" | "ip6tables", ["-t", "mangle", "-S", ..]) => {
                    let v6 = cmd == "ip6tables";
                    let name = if v6 { "AWG2_MARK6" } else { "AWG2_MARK" };
                    let mut rows=format!("-A OUTPUT -j {name}\n-A PREROUTING -j {name}\n-A {name} -m mark --mark 0x20000000/0x20000000 -j RETURN\n-A {name} -m mark --mark {MARK} -j RETURN\n");
                    let exempt = if v6 {
                        "::1/128 fc00::/7 fe80::/10 ff00::/8"
                    } else {
                        "127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 198.51.100.10/32"
                    };
                    for ex in exempt.split_whitespace() {
                        rows += &format!("-A {name} -d {ex} -j RETURN\n");
                    }
                    if !v6 || self.dual {
                        rows += &format!("-A {name} -j MARK --set-xmark {MARK}");
                    }
                    Ok(rows)
                }
                ("ip6tables", ["-t", "filter", "-S", "FORWARD"]) => Ok(if self.dual {
                    String::new()
                } else {
                    let mut s = if self.stranger {
                        "-A FORWARD -j ACCEPT\n".to_string()
                    } else {
                        String::new()
                    };
                    s+="-A FORWARD -o eth9 -m comment --comment \"awg2-v6-noleak\" -j REJECT --reject-with icmp6-adm-prohibited";
                    s
                }),
                ("ip", ["-o", "-N", "-4" | "-6", "rule", "show"]) => {
                    Ok(format!("32765: from all fwmark {MARK} lookup 998"))
                }
                ("ip", ["-o", "-N", "-4" | "-6", "route", "show", "table", "998"]) => {
                    Ok(if self.wrong_table {
                        "default dev awg1"
                    } else {
                        "default dev awg0"
                    }
                    .into())
                }
                ("ip", ["-4" | "-6", "route", "get", _, "mark", "0x10000000"]) => {
                    Ok("default dev awg0".into())
                }
                _ => panic!("unexpected legacy verifier operation"),
            }
        }
    }
    #[test]
    fn scoped_dns_requires_both_transports_on_every_bridge_and_the_same_process() {
        struct Dns {
            v6: bool,
            missing_tcp: bool,
            duplicate: bool,
            owner: bool,
        }
        impl Runner for Dns {
            fn run(&self, cmd: &str, args: &[&str], _: Instant) -> io::Result<String> {
                match (cmd, args) {
                    ("sh", ["-c", script]) if script.contains("/sys/class/net/br*") => {
                        Ok("br1\nbr0\n".into())
                    }
                    ("sh", ["-c", script]) if script.contains("/proc/net/if_inet6") => {
                        Ok(if self.v6 { "ipv6" } else { "ipv4-only" }.into())
                    }
                    ("sh", ["-c", CHECK_DNS_OWNER, "dns-owner", "213"]) => {
                        Ok(if self.owner { "owned" } else { "" }.into())
                    }
                    ("iptables" | "ip6tables", ["-w", "-t", "nat", "-S", "PREROUTING"]) => {
                        assert!(self.v6 || cmd == "iptables");
                        let mut out = String::new();
                        use std::fmt::Write;
                        for br in ["br0", "br1"] {
                            for proto in ["udp", "tcp"] {
                                if self.missing_tcp && br == "br1" && proto == "tcp" {
                                    continue;
                                }
                                let row = format!("-A PREROUTING -i {br} -p {proto} -m {proto} --dport 53 -j REDIRECT --to-ports 5354");
                                writeln!(out, "{row}").unwrap();
                                if self.duplicate && br == "br0" && proto == "udp" {
                                    writeln!(out, "{row}").unwrap();
                                }
                            }
                        }
                        Ok(out)
                    }
                    _ => panic!("unexpected scoped DNS handoff probe"),
                }
            }
        }
        for v6 in [false, true] {
            let expected = Dns {
                v6,
                missing_tcp: false,
                duplicate: false,
                owner: true,
            };
            let bridge = |r: &Dns| dns_bridges(&crate::kernel::kernel(r), 213);
            assert_eq!(bridge(&expected).unwrap(), ["br0", "br1"]);
            assert!(bridge(&Dns {
                missing_tcp: true,
                ..expected
            })
            .is_err());
            assert!(bridge(&Dns {
                duplicate: true,
                ..expected
            })
            .is_err());
            assert!(bridge(&Dns {
                owner: false,
                ..expected
            })
            .is_err());
        }
    }
    #[test]
    fn ipv4_only_requires_positive_stack_inventory_and_still_checks_the_ipv4_classifier() {
        struct Stack(&'static str);
        impl Runner for Stack {
            fn run(&self, cmd: &str, args: &[&str], end: Instant) -> io::Result<String> {
                if cmd == "sh" && args[1].contains("/proc/net/if_inet6") {
                    return Ok(self.0.into());
                }
                if cmd == "ip6tables" {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                assert!(!args.contains(&"-6"));
                Go {
                    dual: false,
                    wrong_table: false,
                    stranger: false,
                }
                .run(cmd, args, end)
            }
        }
        let doc = json!({"active_id":"s","servers":[{"id":"s","config":{"enabled":true,"public_key":"a".repeat(44),"endpoint":"198.51.100.10:443","client":{"enabled":true},"routing":{"mode":"full","active":true}}}],"routing":{"mode":"full"}});
        let old = Stack("ipv4-only");
        let k = crate::kernel::kernel(&old);
        let state = ipv6(&k, &doc).unwrap();
        assert_eq!(state, LegacyFull::Ipv4Only);
        let p = crate::kernel::plan::compile_with_layout(
            &doc,
            None,
            false,
            &[],
            crate::kernel::plan::Layout {
                legacy_full: Some(state),
                ..Default::default()
            },
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = nfqws2_store::Store::open(dir.path()).unwrap();
        verify(&k, &db, &p, &doc).unwrap();
        assert!(!p.uses_family(Family::V6));
        assert!(!crate::kernel::inventory::objects(&p)
            .iter()
            .any(|o| matches!(o, crate::kernel::inventory::Object::LegacyV6Reject(_))));
        for broken in [Stack("ipv6"), Stack("")] {
            assert!(ipv6(&crate::kernel::kernel(&broken), &doc).is_err());
        }
    }
    #[test]
    fn watchdog_requires_literal_ipv6_and_keeps_mapped_and_mixed_zones_out_of_blanket() {
        let applicable = |zone| {
            let r: Routing = serde_json::from_value(json!({"mode":"full","zones":[zone]})).unwrap();
            standalone(&r, &Value::Null)
        };
        assert!(applicable(
            json!({"enabled":true,"ips":["2001:db8:1::/48","2001:db8:3::1"]})
        ));
        for zone in [
            json!({"enabled":true,"ips":[]}),
            json!({"enabled":true,"ips":["::/0"]}),
            json!({"enabled":true,"ips":["::ffff:192.0.2.1/128"]}),
            json!({"enabled":true,"ips":["2001:db8::17","192.0.2.1"]}),
            json!({"enabled":true,"ips":["2001:db8::17"],"domains":["a.example"]}),
        ] {
            assert!(!applicable(zone.clone()), "{zone}");
        }
    }
    #[test]
    fn named_copy_requires_a_disabled_destination_without_tunnel_reserves() {
        let mut doc = json!({
            "active_id":"owner", "servers":[
                {"id":"owner","config":{"enabled":true,"client":{"enabled":true},"routing":{"mode":"full","active":true,"domain_source":"resolve"}}},
                {"id":"copied","config":{"enabled":false,"client":{"enabled":true}}}
            ]
        });
        let r: Routing = serde_json::from_value(json!({"mode":"full","zones":[
            {"enabled":true,"tunnel_id":"copied","route":"tunnel","domains":["office.test"]}
        ]}))
        .unwrap();
        assert!(standalone(&r, &doc));
        let mut scoped = r.clone();
        scoped.zones[0].source_ips = vec!["192.168.1.20".into()];
        assert!(standalone(&scoped, &doc));
        let mut reserved = r.clone();
        reserved.zones[0].fallback_tunnel_ids = vec!["owner".into()];
        assert!(!standalone(&reserved, &doc));
        doc["servers"][1]["config"]["client"]["fallback_tunnel_ids"] = json!(["owner"]);
        assert!(!standalone(&r, &doc));
        doc["servers"][1]["config"]["client"]["fallback_tunnel_ids"] = json!([]);
        doc["servers"][0]["config"]["routing"]["domain_source"] = json!("dnsproxy");
        assert!(standalone(&r, &doc));
        assert!(standalone(&scoped, &doc));
        doc["servers"][0]["config"]["routing"]["domain_source"] = json!("resolve");
        doc["servers"][1]["config"]["enabled"] = json!(true);
        assert!(!standalone(&r, &doc));
    }
    #[test]
    fn full_verifies_the_active_peer_exact_mark_table_and_forward_only_ipv6_guard() {
        let doc = json!({"active_id":"s","servers":[{"id":"s","config":{"enabled":true,"public_key":"a".repeat(44),"endpoint":"198.51.100.10:443","client":{"enabled":true},"routing":{"mode":"full","active":true}}}],"routing":{"mode":"full"}});
        let dir = tempfile::tempdir().unwrap();
        let db = nfqws2_store::Store::open(dir.path()).unwrap();
        for dual in [false, true] {
            for (wrong_table, stranger, ok) in [
                (false, false, true),
                (true, false, false),
                (false, true, dual),
            ] {
                let run = Go {
                    dual,
                    wrong_table,
                    stranger,
                };
                let k = crate::kernel::kernel(&run);
                let check = (|| {
                    let state = ipv6(&k, &doc)?;
                    let plan = crate::kernel::plan::compile_with_layout(
                        &doc,
                        None,
                        false,
                        &[],
                        crate::kernel::plan::Layout {
                            legacy_full: Some(state),
                            ..Default::default()
                        },
                    )?;
                    assert_eq!(plan.uses_family(Family::V6), dual);
                    assert_eq!(crate::kernel::inventory::objects(&plan).iter().any(|o|matches!(o,crate::kernel::inventory::Object::LegacyV6Reject(wan) if wan=="eth9")),!dual);
                    verify(&k, &db, &plan, &doc)
                })();
                assert_eq!(check.is_ok(), ok, "{check:?}");
            }
        }
    }
}
