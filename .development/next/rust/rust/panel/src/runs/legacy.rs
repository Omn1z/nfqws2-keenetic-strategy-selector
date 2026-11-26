use crate::{data, engine::automation::candidates, http::Shared};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, io, path::Path};

const MAX_JOBS: usize = 1024;

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Request {
    list_id: Option<String>,
    targets: Option<Vec<String>>,
    strategy_ids: Option<Vec<String>>,
    threads: Option<i64>,
    auto: Option<bool>,
    blobs: Option<Vec<String>>,
    dns: Option<Vec<String>>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Candidate {
    id: String,
    name: String,
    args: String,
    #[serde(default)]
    l7: String,
}

#[derive(Clone, Serialize)]
struct Resolver {
    id: String,
    name: String,
    transport: String,
    addr: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn resolver_choices(s: &Shared, selected: &[String]) -> io::Result<Vec<Option<Resolver>>> {
    let mut choices = Vec::new();
    if !selected.is_empty() {
        let servers = crate::dns::servers(&s.store)?;
        for id in selected {
            if id.is_empty() || id == "system" {
                choices.push(None);
            } else if let Some(server) = servers.iter().find(|server| &server.id == id) {
                choices.push(Some(Resolver {
                    id: id.clone(),
                    name: server.name.clone(),
                    transport: server.transport.clone(),
                    addr: server.addr.clone(),
                }));
            }
        }
    }
    if choices.is_empty() {
        choices.push(None);
    }
    Ok(choices)
}

fn blob_choices(s: &Shared, selected: Vec<String>) -> io::Result<Vec<(String, String)>> {
    let service = crate::blobs::service(s);
    let mut choices = Vec::new();
    for name in selected {
        let Some(alias) = Path::new(&name).file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if nfqws2_blobs::blob_name(&name).is_err()
            || !alias
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            continue;
        }
        let file = match service.resolve(&name) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let path = file
            .to_str()
            .filter(|p| !p.contains(char::is_whitespace))
            .ok_or_else(|| invalid("Путь к блобу нельзя передать в аргументах стратегии."))?;
        choices.push((alias.to_owned(), path.to_owned()));
    }
    Ok(choices)
}

fn replace_blob(args: &str, alias: &str, path: &str) -> Option<String> {
    let mut new = format!("--blob={alias}:@{path} ");
    let mut changed = false;
    for (i, token) in args.split_whitespace().enumerate() {
        if i != 0 {
            new.push(' ');
        }
        for (j, item) in token.split(':').enumerate() {
            if j != 0 {
                new.push(':');
            }
            if (i != 0 || j != 0) && item.strip_prefix("blob=").is_some_and(|v| !v.is_empty()) {
                new.push_str("blob=");
                new.push_str(alias);
                changed = true;
            } else {
                new.push_str(item);
            }
        }
    }
    changed.then_some(new)
}

pub(super) fn prepare(s: &Shared, req: Request) -> io::Result<Value> {
    let list_id = req.list_id.unwrap_or_default();
    let (targets, list_name) = if list_id.is_empty() {
        (
            data::clean_lines(req.targets.unwrap_or_default()),
            "произвольный набор".to_owned(),
        )
    } else {
        let list = data::list(&s.store, &list_id).map_err(|_| invalid("list not found"))?;
        let mut targets = list.domains.unwrap_or_default();
        targets.extend(list.ips.unwrap_or_default());
        (targets, list.name)
    };
    if targets.is_empty() {
        return Err(invalid("no targets"));
    }

    let auto = req.auto.unwrap_or(false);
    let base: Vec<Candidate> = if auto {
        candidates::automatic()
            .map(|v| {
                let mut candidate: Candidate = serde_json::from_value(v)?;
                candidate.l7 = "tls".to_owned();
                Ok(candidate)
            })
            .collect::<Result<_, serde_json::Error>>()?
    } else {
        let selection: HashSet<_> = req.strategy_ids.unwrap_or_default().into_iter().collect();
        let mut known = Vec::new();
        for strategy in data::strategies(&s.store)? {
            let candidate: Candidate = serde_json::from_value(serde_json::to_value(strategy)?)?;
            if selection.is_empty() || selection.contains(&candidate.id) {
                known.push(candidate);
            }
        }
        known
    };
    if base.is_empty() {
        return Err(invalid("no strategies selected"));
    }
    let choices = resolver_choices(s, &req.dns.unwrap_or_default())?;
    let blobs = blob_choices(s, req.blobs.unwrap_or_default())?;
    let domains = candidates::snis(&s.store)?;
    let mut strategies = Vec::new();
    let mut size = 0;
    let mut push = |candidate: Candidate| -> io::Result<()> {
        if nfqws2_config::validate_https_strategy(&candidate.args).is_ok() {
            size += candidate.args.len() + candidate.name.len() + candidate.id.len();
            if strategies.len() >= MAX_JOBS / choices.len() || size > 768 << 10 {
                return Err(invalid("Слишком много вариантов для одного прогона."));
            }
            strategies.push(candidate);
        }
        Ok(())
    };
    let mut expand_sni = |candidate: Candidate| -> io::Result<()> {
        for domain in &domains {
            if let Some(args) = candidates::replace_sni(&candidate.args, domain) {
                push(Candidate {
                    id: format!("{}/sni={domain}", candidate.id),
                    name: format!("(sni {domain}) {}", candidate.name),
                    args,
                    l7: candidate.l7.clone(),
                })?;
            }
        }
        push(candidate)
    };
    for candidate in base {
        for (alias, path) in &blobs {
            if let Some(args) = replace_blob(&candidate.args, alias, path) {
                expand_sni(Candidate {
                    id: format!("{}/{alias}", candidate.id),
                    name: format!("[{alias}] {}", candidate.name),
                    args,
                    l7: candidate.l7.clone(),
                })?;
            }
        }
        expand_sni(candidate)?;
    }
    if strategies.is_empty() {
        return Err(invalid(
            "нет стратегий для HTTPS (IPv4, TCP/443, TLS): текущая проверка не тестирует HTTP/QUIC",
        ));
    }
    let threads = req.threads.filter(|n| *n > 0).unwrap_or(4).min(8) as usize;
    let threads = threads.min(strategies.len() * choices.len());
    let mut config = s.config.clone();
    config.load_from_nfqws2_conf()?;
    Ok(
        json!({"legacy":true,"targets":targets,"threads":threads,"auto":auto,
        "strategies":strategies,"config":config,"list_id":list_id,"list_name":list_name,"dns":choices}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request as HttpRequest, StatusCode},
    };
    use std::fs;
    use tower::ServiceExt;

    const TLS: &str = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=tls_clienthello:sni=www.google.com";

    fn state() -> (tempfile::TempDir, Shared) {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("nfqws2.conf");
        fs::write(&conf, "NFQWS_BASE_ARGS=\"--lua-init=@/admin/config.lua\"\n").unwrap();
        let cfg = nfqws2_config::Config {
            data_dir: dir.path().join("data").display().to_string(),
            system_blobs_dir: dir.path().join("system").display().to_string(),
            nfqws2_conf: conf.display().to_string(),
            ..Default::default()
        };
        fs::create_dir_all(Path::new(&cfg.data_dir).join("blobs")).unwrap();
        fs::create_dir_all(&cfg.system_blobs_dir).unwrap();
        fs::write(
            Path::new(&cfg.system_blobs_dir).join("hello.bin"),
            b"system",
        )
        .unwrap();
        fs::write(Path::new(&cfg.data_dir).join("blobs/hello.bin"), b"custom").unwrap();
        let s = crate::http::AppState::open(cfg, dir.path(), true).unwrap();
        s.store.transaction(|tx| {
            tx.save("strategies_custom.json", &json!([
                {"id":"fixed-first","name":"First","l7":"tls","args":TLS},
                {"id":"fixed-http","name":"HTTP","l7":"http","args":"--filter-tcp=80 --lua-desync=fake"},
                {"id":"fixed-last","name":"Last","args":"--filter-tcp=443 --lua-desync=multisplit:pos=1"}
            ]))?;
            tx.save("lists/saved.json", &json!({"id":"saved","name":"Saved","domains":["saved.example"],"ips":["192.0.2.1"]}))?;
            tx.save("dns.json", &json!([
                {"id":"test-doh","name":"HTTPS","type":"doh","addr":"https://dns.example/dns-query"},
                {"id":"test-dot","name":"TLS","type":"dot","addr":"dns.example:8853"}
            ]))?;
            tx.save("sni_domains.json", &json!(["one.example", "two.example"]))
        }).unwrap();
        (dir, s)
    }

    #[test]
    fn legacy_run_loads_saved_targets_catalog_blobs_sni_dns_and_clamped_threads() {
        let (_dir, s) = state();
        let body = json!({"list_id":"saved","targets":["ignored.example"],
            "strategy_ids":["fixed-last","missing","fixed-http","fixed-first","fixed-first"],
            "threads":64,"blobs":["../hello.bin","missing.bin","hello.bin"],
            "dns":["unknown","test-dot","system","test-doh","", "test-dot"],
            "config":{"nfqws_conf":"/untrusted"},"strategies":[{"args":"--qnum=66"}]
        });
        let plan = prepare(&s, serde_json::from_value(body).unwrap()).unwrap();
        assert_eq!(plan["targets"], json!(["saved.example", "192.0.2.1"]));
        assert_eq!(plan["list_name"], "Saved");
        assert_eq!(plan["threads"], 8);
        assert_eq!(
            plan["config"]["base_args"],
            json!(["--lua-init=@/admin/config.lua"])
        );
        assert_eq!(
            plan["dns"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["id"].as_str())
                .collect::<Vec<_>>(),
            vec![
                Some("test-dot"),
                None,
                Some("test-doh"),
                None,
                Some("test-dot")
            ]
        );
        let variants = plan["strategies"].as_array().unwrap();
        assert_eq!(
            variants
                .iter()
                .map(|x| x["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "fixed-first/hello/sni=one.example",
                "fixed-first/hello/sni=two.example",
                "fixed-first/hello",
                "fixed-first/sni=one.example",
                "fixed-first/sni=two.example",
                "fixed-first",
                "fixed-last"
            ]
        );
        let first = variants[0]["args"].as_str().unwrap();
        let (path, _) = first
            .strip_prefix("--blob=hello:@")
            .unwrap()
            .split_once(' ')
            .unwrap();
        assert_eq!(
            Path::new(path),
            Path::new(&s.config.data_dir)
                .join("blobs")
                .join("hello.bin")
        );
        assert_eq!(fs::read(path).unwrap(), b"custom");
        assert!(first.ends_with(":blob=hello:sni=one.example"));
    }

    #[test]
    fn legacy_auto_ignores_manual_ids_and_defaults_to_four_threads_and_system_dns() {
        let (_dir, s) = state();
        let plan = prepare(
            &s,
            serde_json::from_value(json!({"targets":[" a.example ","a.example",""],
            "threads":-3,"strategy_ids":["fixed-last"],"dns":["unknown"],"auto":true}))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(plan["targets"], json!(["a.example"]));
        assert_eq!(plan["threads"], 4);
        assert_eq!(plan["dns"], json!([null]));
        assert!(plan["strategies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["id"].as_str().unwrap().starts_with("auto-")));
        let one = prepare(
            &s,
            serde_json::from_value(
                json!({"targets":["x.example"],"strategy_ids":["fixed-last"],"threads":null}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(one["threads"], 1);
    }

    #[tokio::test]
    async fn legacy_post_runs_dispatches_valid_prepared_requests_under_shared_exclusion() {
        let (_dir, s) = state();
        let _permit = crate::blockcheck::Permit::acquire(&s.active_test).unwrap();
        let app = crate::runs::routes().with_state(s);
        for (body, expected) in [
            (
                json!({"list_id":"saved","strategy_ids":["fixed-first"]}),
                "a run is already in progress",
            ),
            (
                json!({"targets":["target.example"],"auto":true,"threads":0}),
                "a run is already in progress",
            ),
            (
                json!({"targets":["target.example"],"strategy_ids":["fixed-http"]}),
                "нет стратегий для HTTPS",
            ),
            (
                json!({"targets":["target.example"],"strategy_ids":["missing"]}),
                "no strategies selected",
            ),
            (
                json!({"list_id":"missing","targets":["target.example"]}),
                "list not found",
            ),
            (
                json!({"mode":"strategy_matrix","targets":["target.example"]}),
                "Неизвестный режим",
            ),
            (
                json!({"targets":["target.example"],"threads":"4"}),
                "invalid type",
            ),
        ] {
            let req = HttpRequest::post("/api/runs")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
            let response: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert!(
                response["error"].as_str().unwrap().contains(expected),
                "{body}: {response}"
            );
        }
    }
}
