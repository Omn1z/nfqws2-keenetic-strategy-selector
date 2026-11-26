//! Candidate profiles for automatic HTTPS selection. The broad automatic set
//! mirrors Go's catalog; installed and custom profiles extend that search space.
use crate::http::Shared;
use nfqws2_store::Store;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io};

const TLS_FILTER: &str = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello ";
const MAX_CANDIDATES: usize = 1024;
const MAX_BYTES: usize = 900 << 10;
// Keep the order in internal/services/strategy/core/catalog/strategy.go. Ties
// retain the first measured candidate, as in the original automatic selector.
const AUTOMATIC: &[(&str, &str, &str)] = &[
    ("ms-1", "multisplit pos=1", "--lua-desync=multisplit:pos=1"),
    ("ms-midsld", "multisplit midsld", "--lua-desync=multisplit:pos=1,midsld"),
    ("ms-midsld2", "multisplit 2,midsld-2", "--lua-desync=multisplit:pos=2,midsld-2"),
    ("ms-sniext", "multisplit sniext+1", "--lua-desync=multisplit:pos=1,sniext+1"),
    ("ms-host", "multisplit host+1", "--lua-desync=multisplit:pos=1,host+1"),
    ("ms-sld", "multisplit sld+1", "--lua-desync=multisplit:pos=sld+1"),
    ("ms-ovl1", "multisplit midsld seqovl1", "--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
    ("ms-ovl336", "multisplit midsld seqovl336", "--lua-desync=multisplit:pos=1,midsld:seqovl=336:seqovl_pattern=tls_clienthello"),
    ("ms-ovl681", "multisplit midsld seqovl681", "--lua-desync=multisplit:pos=1,midsld:seqovl=681:seqovl_pattern=tls_clienthello"),
    ("md-midsld", "multidisorder midsld", "--lua-desync=multidisorder:pos=1,midsld"),
    ("md-sniext", "multidisorder sniext+1", "--lua-desync=multidisorder:pos=1,sniext+1"),
    ("md-ovl1", "multidisorder midsld seqovl1", "--lua-desync=multidisorder:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
    ("md-multi", "multidisorder midsld+sniext", "--lua-desync=multidisorder:pos=1,midsld,sniext+1"),
    ("fds-midsld", "fakedsplit midsld seqovl1 fake seq-10000", "--lua-desync=fakedsplit:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_seq=-10000"),
    ("fdd-midsld", "fakeddisorder midsld seqovl1 fake seq-10000", "--lua-desync=fakeddisorder:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_seq=-10000"),
    ("fake-google-ms", "fake(google sni,seq-10000)+multisplit", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=-10000 --lua-desync=multisplit:pos=1,midsld"),
    ("fake-ack-ms", "fake(0x0,seq-10000,ack-66000)+multisplit", "--lua-desync=fake:blob=0x00000000:tcp_seq=-10000:tcp_ack=-66000:repeats=2 --lua-desync=multisplit:pos=1,midsld"),
    ("fake-badsum-ms", "fake(badsum)+multisplit ovl", "--lua-desync=fake:blob=tls_clienthello:badsum --lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
    ("fake-md5-ms", "fake(tcp_md5)+multisplit", "--lua-desync=fake:blob=tls_clienthello:tcp_md5 --lua-desync=multisplit:pos=1,midsld"),
    ("fake-rep-md", "fake(rep6,seq-10000,ack)+multidisorder", "--lua-desync=fake:blob=tls_clienthello:repeats=6:tcp_seq=-10000:tcp_ack=-66000 --lua-desync=multidisorder:pos=1,midsld"),
    ("fake-ttl-ms", "fake(ip_ttl=4)+multisplit", "--lua-desync=fake:blob=tls_clienthello:ip_ttl=4:ip6_ttl=4 --lua-desync=multisplit:pos=1,midsld"),
    ("fake-autottl-ms", "fake(autottl,seq-10000)+multisplit", "--lua-desync=fake:blob=tls_clienthello:ip_autottl=0,3-20:tcp_seq=-10000 --lua-desync=multisplit:pos=1,midsld"),
    ("fake-rep-fds", "fake(rep2,seq-10000)+fakedsplit(seq-10000)", "--lua-desync=fake:blob=tls_clienthello:repeats=2:tcp_seq=-10000 --lua-desync=fakedsplit:pos=midsld:tcp_seq=-10000"),
    ("fake-padencap-ms", "fake(padencap,seq-10000)+multisplit sniext", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,padencap:tcp_seq=-10000 --lua-desync=multisplit:pos=1,sniext+1"),
    ("fake-google", "fake(google sni,seq-10000) only", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=-10000"),
    ("ms-sld2", "multisplit sld+2", "--lua-desync=multisplit:pos=sld+2"),
    ("ms-multi3", "multisplit 1,sniext+1,host+1,midsld", "--lua-desync=multisplit:pos=1,sniext+1,host+1,midsld"),
    ("ms-tsup", "multisplit midsld tcp_ts_up", "--lua-desync=multisplit:pos=1,midsld:tcp_ts_up"),
    ("ms-ovl-tsup", "multisplit midsld seqovl tcp_ts_up", "--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"),
    ("md-host", "multidisorder host+1", "--lua-desync=multidisorder:pos=1,host+1"),
    ("md-tsup", "multidisorder midsld tcp_ts_up", "--lua-desync=multidisorder:pos=1,midsld:tcp_ts_up"),
    ("fake-fonts-ms", "fake(fonts.google sni,seq-10000,ts)+multisplit", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=-10000 --lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up"),
    ("fake-ack-sni-ms", "fake(0x0,seq-10000,ack,sni)+multisplit", "--lua-desync=fake:blob=0x00000000:tcp_seq=-10000:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:repeats=2 --lua-desync=multisplit:pos=1,midsld"),
    ("fake-sni-ts-ms", "fake(google sni,seq-10000,ts)+multisplit ovl", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=-10000:tcp_ts_up --lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
    ("fake-msft-md", "fake(microsoft sni,seq-10000)+multidisorder", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.microsoft.com:tcp_seq=-10000 --lua-desync=multidisorder:pos=1,midsld"),
    ("fake-md5-ts-ms", "fake(md5,ts)+multisplit", "--lua-desync=fake:blob=tls_clienthello:tcp_md5:tcp_ts_up --lua-desync=multisplit:pos=1,midsld"),
    ("fake-ttl2-md", "fake(ttl2)+multidisorder", "--lua-desync=fake:blob=tls_clienthello:ip_ttl=2:ip6_ttl=2 --lua-desync=multidisorder:pos=1,midsld"),
    ("fake-2x-ms", "fake x2 (rep+ack,seq-10000)+multisplit", "--lua-desync=fake:blob=tls_clienthello:repeats=2:tcp_seq=-10000 --lua-desync=fake:blob=tls_clienthello:tcp_ack=-66000:tcp_seq=-10000 --lua-desync=multisplit:pos=1,midsld"),
    ("fds-ts", "fakedsplit midsld seqovl tcp_ts_up fake seq-10000", "--lua-desync=fakedsplit:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up:tcp_seq=-10000"),
    ("fdd-sniext", "fakeddisorder sniext+1 seqovl fake seq-10000", "--lua-desync=fakeddisorder:pos=sniext+1:seqovl=1:seqovl_pattern=tls_clienthello:tcp_seq=-10000"),
    ("fdd-badsum-md5", "fakeddisorder midsld badsum md5", "--lua-desync=fakeddisorder:pos=midsld:badsum:tcp_md5"),
    ("hfs-sniext", "hostfakesplit midhost seqovl(sniext)", "--lua-desync=hostfakesplit:midhost=host-2:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum:tcp_md5:tcp_ts_up --lua-desync=hostfakesplit:tcp_md5:tcp_ts_up"),
    ("hfs-google", "hostfakesplit host=google badsum + fake seq-10000", "--lua-desync=hostfakesplit:host=www.google.com:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum --lua-desync=hostfakesplit:tcp_ts_up:tcp_seq=-10000"),
];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn domain(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
pub(crate) fn snis(db: &Store) -> io::Result<Vec<String>> {
    let values = match db.read_limited::<Option<Vec<String>>>("sni_domains.json", 64 << 10) {
        Ok(values) => values.unwrap_or_default(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let domains = crate::data::clean_lines(values);
    if domains.len() > 64 || domains.iter().any(|d| !domain(d)) {
        return Err(invalid(
            "Для подбора стратегии укажите до 64 корректных SNI-имён без URL, портов и пробелов.",
        ));
    }
    Ok(domains)
}
pub(crate) fn replace_sni(args: &str, domain: &str) -> Option<String> {
    let mut rest = args;
    let mut out = String::with_capacity(args.len());
    let mut changed = false;
    while let Some(offset) = rest.find("sni=") {
        let start = offset + 4;
        let end = rest[start..]
            .find(|c: char| c.is_whitespace() || c == ':')
            .map_or(rest.len(), |n| start + n);
        out.push_str(&rest[..start]);
        // Go's sni= expression requires a nonempty value.
        if end != start {
            out.push_str(domain);
            changed = true;
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    changed.then_some(out)
}
fn row(id: &str, name: &str, args: &str) -> Value {
    json!({"id":id,"strategy_id":id,"name":name,"args":args})
}
pub(crate) fn automatic() -> impl Iterator<Item = Value> {
    AUTOMATIC
        .iter()
        .map(|(id, name, args)| row(&format!("auto-{id}"), name, &format!("{TLS_FILTER}{args}")))
}
fn expand(db: &Store) -> io::Result<Vec<Value>> {
    let mut base: Vec<Value> = automatic().collect();
    // data::strategies loads the embedded catalog in the full panel and the
    // installed optional catalog in compact builds, followed by custom data.
    for strategy in crate::data::strategies(db)? {
        let strategy = serde_json::to_value(strategy)?;
        if let (Some(id), Some(name), Some(args)) = (
            strategy["id"].as_str(),
            strategy["name"].as_str(),
            strategy["args"].as_str(),
        ) {
            base.push(row(id, name, args));
        }
    }
    let domains = snis(db)?;
    let mut seen = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut result = Vec::new();
    let mut bytes = 0;
    let mut push = |mut candidate: Value| -> io::Result<()> {
        let args = candidate["args"].as_str().unwrap_or_default();
        if args.len() > 32 << 10
            || nfqws2_config::validate_https_strategy(args).is_err()
            || !seen.insert(args.to_owned())
        {
            return Ok(());
        }
        let original = candidate["id"].as_str().unwrap_or_default();
        if original.is_empty() || original.len() > 256 || !seen_ids.insert(original.to_owned()) {
            // SNI variants can exceed the matrix's ID limit, and saved custom
            // profiles can reuse a built-in ID. Keep ordinary IDs unchanged;
            // derive a stable fallback from the distinct measured arguments.
            let digest: String = Sha256::digest(args.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let base = format!("auto-candidate-{digest}");
            let mut id = base.clone();
            let mut suffix = 0;
            while !seen_ids.insert(id.clone()) {
                suffix += 1;
                id = format!("{base}-{suffix}");
            }
            candidate["id"] = json!(id);
            candidate["strategy_id"] = candidate["id"].clone();
        }
        bytes += serde_json::to_vec(&candidate)?.len();
        if result.len() == MAX_CANDIDATES || bytes > MAX_BYTES {
            return Err(invalid("Слишком много вариантов для автоматического подбора. Сократите список SNI или пользовательских стратегий."));
        }
        result.push(candidate);
        Ok(())
    };
    for candidate in base {
        let args = candidate["args"].as_str().unwrap_or_default();
        let id = candidate["id"].as_str().unwrap_or_default();
        let name = candidate["name"].as_str().unwrap_or_default();
        // The user's SNI preferences precede the original profile's fallback.
        for domain in &domains {
            if let Some(args) = replace_sni(args, domain) {
                push(row(
                    &format!("{id}/sni={domain}"),
                    &format!("(sni {domain}) {name}"),
                    &args,
                ))?;
            }
        }
        push(candidate)?;
    }
    if result.is_empty() {
        return Err(invalid(
            "Не найдены стратегии для HTTPS (IPv4, TCP/443, TLS).",
        ));
    }
    Ok(result)
}
pub(super) fn load(s: &Shared) -> io::Result<Vec<Value>> {
    expand(&s.store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_candidates_match_the_go_tls_search_space() {
        // Parse only Go's literal tls(...) registrations, independent of Rust's
        // constant representation, so additions cannot silently go missing.
        let go = include_str!("../../../../../internal/services/strategy/core/catalog/strategy.go");
        let expected: Vec<_> = go
            .lines()
            .filter_map(|line| {
                let line = line.trim().strip_prefix("tls(\"")?;
                let (id, line) = line.split_once("\", \"")?;
                let (name, line) = line.split_once("\", \"")?;
                let args = line.strip_suffix("\"),")?;
                Some((id, name, args))
            })
            .collect();
        assert_eq!(AUTOMATIC, expected);
        assert_eq!(AUTOMATIC.len(), 43);
        for (_, _, args) in AUTOMATIC {
            nfqws2_config::validate_https_strategy(&format!("{TLS_FILTER}{args}")).unwrap();
        }
    }

    #[test]
    fn custom_candidates_are_validated_deduplicated_and_sni_expanded() {
        let directory = tempfile::tempdir().unwrap();
        let db = Store::open(directory.path()).unwrap();
        let repeated = format!("{TLS_FILTER}{}", AUTOMATIC[0].2);
        db.transaction(|tx| {
            tx.save("strategies_custom.json", &json!([
                {"id":"http-only","name":"HTTP","l7":"tls","args":"--filter-tcp=80 --lua-desync=multisplit:pos=1"},
                {"id":"duplicate","name":"Repeated","args":repeated},
                {"id":"own","name":"Own","l7":"http","args":"--filter-tcp=443 --lua-desync=multisplit:pos=7"}
            ]))?;
            tx.save("sni_domains.json", &json!(["fake.example", " fake.example "]))
        }).unwrap();
        let rows = expand(&db).unwrap();
        assert!(rows.iter().any(|r| r["id"] == "own"));
        assert!(!rows
            .iter()
            .any(|r| r["id"] == "http-only" || r["id"] == "duplicate"));
        let original = rows
            .iter()
            .position(|r| r["id"] == "auto-fake-google-ms")
            .unwrap();
        assert_eq!(
            rows[original - 1]["id"],
            "auto-fake-google-ms/sni=fake.example"
        );
        assert!(rows[original - 1]["args"]
            .as_str()
            .unwrap()
            .contains("sni=fake.example:"));
        for row in rows {
            assert_eq!(row["id"], row["strategy_id"]);
            nfqws2_config::validate_https_strategy(row["args"].as_str().unwrap()).unwrap();
        }
    }

    #[test]
    fn sni_changes_every_fake_without_creating_arguments() {
        assert_eq!(
            replace_sni(
                "--lua-desync=fake:sni=a.example:repeats=2 --lua-desync=fake:sni=b.example",
                "c.example"
            )
            .unwrap(),
            "--lua-desync=fake:sni=c.example:repeats=2 --lua-desync=fake:sni=c.example"
        );
        assert!(replace_sni("--lua-desync=multisplit:pos=1", "c.example").is_none());
        assert!(replace_sni("--lua-desync=fake:sni=:repeats=2", "c.example").is_none());
        let directory = tempfile::tempdir().unwrap();
        let db = Store::open(directory.path()).unwrap();
        db.transaction(|tx| tx.save("sni_domains.json", &json!(["x.example --qnum=300"])))
            .unwrap();
        assert!(expand(&db).is_err());
    }

    #[test]
    fn long_sni_and_colliding_saved_ids_keep_distinct_stable_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let db = Store::open(directory.path()).unwrap();
        let long_sni = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(long_sni.len(), 253);
        db.transaction(|tx| {
            tx.save("sni_domains.json", &json!([long_sni]))?;
            tx.save("strategies_custom.json", &json!([
                {"id":"auto-ms-1","name":"Custom collision","args":"--filter-tcp=443 --lua-desync=multisplit:pos=17"},
                {"id":"own","name":"Custom preserved","args":"--filter-tcp=443 --lua-desync=multisplit:pos=19"}
            ]))
        }).unwrap();
        let rows = expand(&db).unwrap();
        assert_eq!(rows, expand(&db).unwrap());
        let mut ids = HashSet::new();
        for row in &rows {
            let id = row["id"].as_str().unwrap();
            assert!(!id.is_empty() && id.len() <= 256 && ids.insert(id));
            assert_eq!(row["id"], row["strategy_id"]);
        }
        assert!(rows.iter().any(|row| row["id"] == "auto-ms-1"));
        assert!(rows.iter().any(|row| row["id"] == "own"));
        let collision = rows
            .iter()
            .find(|row| row["name"] == "Custom collision")
            .unwrap();
        assert!(collision["id"]
            .as_str()
            .unwrap()
            .starts_with("auto-candidate-"));
        assert!(rows.iter().any(|row| row["args"]
            .as_str()
            .unwrap()
            .contains(&format!("sni={long_sni}:"))));
    }
}
