use super::{
    explorer,
    snapshots::{location, SERVICE},
};
use crate::http::{ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use nfqws2_config::{
    service_profiles::{Compiled, Document, Request, Service},
    Config,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    path::Path,
};

pub(super) fn compile(
    cfg: &Config,
    source: String,
    services: Vec<Service>,
) -> io::Result<Compiled> {
    let dir = Path::new(&cfg.nfqws2_conf)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("lists");
    let req = Request {
        source,
        lists_dir: dir.to_string_lossy().replace('\\', "/"),
        services,
    };
    #[cfg(all(feature = "embedded-strategies", not(feature = "compact")))]
    {
        nfqws2_strategies::compile(req)
    }
    #[cfg(any(not(feature = "embedded-strategies"), feature = "compact"))]
    {
        external(req)
    }
}
#[cfg(any(not(feature = "embedded-strategies"), feature = "compact"))]
fn external(req: Request) -> io::Result<Compiled> {
    use std::{
        io::{BufReader, BufWriter, Seek, Write},
        process::{Command, Stdio},
    };
    let path = crate::assets::module_dir()
        .join("strategies")
        .join(format!("nfqws2-strategies{}", std::env::consts::EXE_SUFFIX));
    let mut diagnostics = tempfile::tempfile()?;
    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(diagnostics.try_clone()?)
        .spawn()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "установите nfqws2-strategy-strategies",
                )
            } else {
                e
            }
        })?;
    let result = (|| -> io::Result<Compiled> {
        let mut input = BufWriter::new(child.stdin.take().expect("piped stdin"));
        serde_json::to_writer(&mut input, &req)?;
        input.flush()?;
        drop(input);
        let mut output =
            BufReader::new(child.stdout.take().expect("piped stdout")).take((96 << 20) + 1);
        let compiled = serde_json::from_reader(&mut output)?;
        if output.limit() == 0 {
            return Err(explorer::invalid("слишком большой ответ компилятора"));
        }
        Ok(compiled)
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    if !status.success() {
        diagnostics.rewind()?;
        let mut msg = String::new();
        diagnostics.take(4096).read_to_string(&mut msg)?;
        return Err(explorer::invalid(if msg.trim().is_empty() {
            "не удалось скомпилировать сервисы"
        } else {
            msg.trim()
        }));
    }
    result
}
fn read(cfg: &Config, name: &str) -> io::Result<Option<Vec<u8>>> {
    let mut input = match location(cfg, name)?.open() {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(explorer::FILE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > explorer::FILE_LIMIT {
        return Err(explorer::invalid("превышен размер файла"));
    }
    Ok(Some(bytes))
}
pub(super) fn encode(doc: &Document) -> io::Result<Vec<u8>> {
    let mut json = serde_json::to_vec_pretty(doc)?;
    json.push(b'\n');
    Ok(json)
}
fn revision(doc: &[u8], conf: &[u8]) -> String {
    super::import::digest_hex(
        Sha256::new()
            .chain_update(doc)
            .chain_update([0])
            .chain_update(conf),
    )
}
#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    services: Vec<Service>,
    #[serde(default)]
    revision: String,
}
enum Operation {
    Read,
    Preview(Input),
    Save(Input),
}
fn execute(cfg: &Config, op: Operation) -> io::Result<Value> {
    let saved = read(cfg, SERVICE)?;
    let mut doc: Document = if let Some(bytes) = saved.as_ref() {
        serde_json::from_slice(bytes)?
    } else {
        Default::default()
    };
    let conf = String::from_utf8(read(cfg, "nfqws2.conf")?.unwrap_or_default())
        .map_err(|_| explorer::invalid("ожидается UTF-8 в nfqws2.conf"))?;
    let mut rev = revision(saved.as_deref().unwrap_or_default(), conf.as_bytes());
    let mut saving = false;
    let mut preview = false;
    let services = match op {
        Operation::Read => std::mem::take(&mut doc.services),
        Operation::Preview(i) => {
            preview = true;
            i.services
        }
        Operation::Save(i) => {
            if i.revision != rev {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "настройки сервисов изменились",
                ));
            }
            saving = true;
            i.services
        }
    };
    let compiled = compile(cfg, conf.clone(), services)?;
    let mut state = json!({"tcp_ports":compiled.tcp_ports,"udp_ports":compiled.udp_ports,"warnings":compiled.warnings,"profiles":compiled.profiles});
    if preview {
        state["args"] = json!(compiled.args);
        return Ok(state);
    }
    doc.services = compiled.services;
    doc.restart_required |= compiled.config != conf;
    if saving {
        let mut created = vec![];
        let mut wrote_doc = false;
        let write = (|| -> io::Result<()> {
            for (name, value) in compiled.lists {
                let name = format!("lists/{name}");
                if let Some(previous) = read(cfg, &name)? {
                    if previous != value.as_bytes() {
                        return Err(explorer::invalid(
                            "содержимое управляемого списка изменилось",
                        ));
                    }
                } else {
                    location(cfg, &name)?.replace(cfg, value.as_bytes(), false, Some(0o644))?;
                    created.push(name);
                    doc.restart_required = true;
                }
            }
            let next = encode(&doc)?;
            location(cfg, SERVICE)?.replace(cfg, next.as_slice(), true, Some(0o600))?;
            wrote_doc = true;
            if compiled.config != conf {
                location(cfg, "nfqws2.conf")?.replace(
                    cfg,
                    compiled.config.as_bytes(),
                    true,
                    Some(0o644),
                )?;
            }
            rev = revision(&next, compiled.config.as_bytes());
            Ok(())
        })();
        if let Err(error) = write {
            let mut rollback = vec![];
            if wrote_doc {
                let file = location(cfg, SERVICE)?;
                let result = if let Some(bytes) = saved {
                    file.replace(cfg, bytes.as_slice(), true, Some(0o600))
                } else {
                    file.remove_file()
                };
                if let Err(e) = result {
                    rollback.push(e.to_string());
                }
            }
            for name in created {
                if let Err(e) = location(cfg, &name)?.remove_file() {
                    rollback.push(e.to_string());
                }
            }
            if rollback.is_empty() {
                return Err(error);
            }
            return Err(io::Error::other(format!(
                "{error}, восстановление: {}",
                rollback.join(", ")
            )));
        }
    }
    state["services"] = serde_json::to_value(doc.services)?;
    state["revision"] = json!(rev);
    state["restart_required"] = json!(doc.restart_required);
    Ok(state)
}
async fn request(s: Shared, op: Operation) -> Result<Json<Value>, ApiError> {
    tokio::task::spawn_blocking(move || s.store.transaction(|_| execute(&s.config, op)))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map(Json)
        .map_err(|e| {
            ApiError(
                match e.kind() {
                    io::ErrorKind::AlreadyExists => StatusCode::CONFLICT,
                    io::ErrorKind::Unsupported => StatusCode::SERVICE_UNAVAILABLE,
                    io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
                        StatusCode::BAD_REQUEST
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },
                e.to_string(),
            )
        })
}
async fn current(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    request(s, Operation::Read).await
}
async fn preview(
    State(s): State<Shared>,
    ApiJson(i): ApiJson<Input>,
) -> Result<Json<Value>, ApiError> {
    request(s, Operation::Preview(i)).await
}
async fn save(
    State(s): State<Shared>,
    ApiJson(i): ApiJson<Input>,
) -> Result<Json<Value>, ApiError> {
    request(s, Operation::Save(i)).await
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/nfqws2/service-strategies", get(current).post(save))
        .route("/api/nfqws2/service-strategies/preview", post(preview))
        .route(
            "/api/nfqws2/service-strategies/check",
            post(check::check).layer(DefaultBodyLimit::max(32 << 10)),
        )
        .layer(DefaultBodyLimit::max(2 << 20))
}
mod check;
mod lifecycle;
pub(crate) use lifecycle::{mark_engine_applied, normalize_wan, prepare_for_engine};
