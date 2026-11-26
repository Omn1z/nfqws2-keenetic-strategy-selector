use super::explorer::{self, Location};
use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use nfqws2_config::Config;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};

#[derive(Deserialize)]
struct Input {
    args: String,
    #[serde(default)]
    restart: bool,
}
pub(crate) fn save(cfg: &Config, args: &str) -> io::Result<()> {
    let current = explorer::locate(cfg, "nfqws2.conf")?;
    let mut source = String::new();
    current
        .open()?
        .take(explorer::FILE_LIMIT + 1)
        .read_to_string(&mut source)?;
    if source.len() as u64 > explorer::FILE_LIMIT {
        return Err(explorer::invalid("превышен размер конфигурации"));
    }
    let result = nfqws2_config::replace_nfqws_args(&source, args)?;
    if result.len() as u64 > explorer::FILE_LIMIT {
        return Err(explorer::invalid("превышен размер итоговой конфигурации"));
    }
    let mut filename = current.relative.as_os_str().to_owned();
    filename.push(".n2s.bak");
    let backup = Location {
        root: current.root.clone(),
        kind: "conf",
        relative: filename.into(),
    };
    backup.replace(cfg, source.as_bytes(), true, Some(0o600))?;
    current.replace(cfg, result.as_bytes(), true, Some(0o644))
}
async fn apply(
    State(s): State<Shared>,
    ApiJson(input): ApiJson<Input>,
) -> Result<Json<Value>, ApiError> {
    tokio::spawn(async move {
        let state = s.clone();
        blocking(move || {
            state
                .store
                .transaction(|_| save(&state.config, &input.args))
        })
        .await?;
        if input.restart {
            crate::engine::restart_after_config(s).await.map_err(|e| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("стратегия сохранена, перезапуск NFQWS2: {e}"),
                )
            })?;
        }
        Ok(Json(json!({"status":"applied"})))
    })
    .await
    .map_err(io::Error::other)?
}
pub(super) fn routes() -> Router<Shared> {
    Router::new().route(
        "/api/apply",
        post(apply).layer(DefaultBodyLimit::max(2 << 20)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn literal_arguments_exact_backup_and_unrelated_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nfqws2.conf");
        let cfg = Config {
            nfqws2_conf: path.display().to_string(),
            ..Config::default()
        };
        let old="# NFQWS_ARGS=\"comment\"\nNFQWS_ARGS=\"--filter-tcp=80\" # keep\nISP_INTERFACE='eth0,eth1'\nNFQWS_ARGS_UDP=\"u\"\n";
        fs::write(&path, old).unwrap();
        let next = "--filter-tcp=443 --name=literal$\"label";
        save(&cfg, next).unwrap();
        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.starts_with("# NFQWS_ARGS=\"comment\""));
        assert!(updated.contains("# keep\nISP_INTERFACE='eth0 eth1'\nNFQWS_ARGS_UDP=\"u\""));
        assert_eq!(
            nfqws2_config::literal_shell_config_value(&updated, "NFQWS_ARGS")
                .unwrap()
                .as_deref(),
            Some(next)
        );
        assert_eq!(
            fs::read_to_string(path.with_extension("conf.n2s.bak")).unwrap(),
            old
        );
        fs::write(&path, "# missing").unwrap();
        assert!(save(&cfg, next).is_err());
        assert_eq!(
            fs::read_to_string(path.with_extension("conf.n2s.bak")).unwrap(),
            old
        );
    }
}
