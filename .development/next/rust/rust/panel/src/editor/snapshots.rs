use super::explorer::{self, invalid, Location};
use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Response,
    routing::get,
    Json, Router,
};
use nfqws2_config::Config;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};
use tempfile::NamedTempFile;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

pub(super) const SERVICE: &str = "nfqws2-service-strategies.json";
pub(super) const ZIP_LIMIT: u64 = 32 << 20;
pub(super) const TOTAL: u64 = 64 << 20;
pub(super) fn location(cfg: &Config, name: &str) -> io::Result<Location> {
    if name == SERVICE {
        Ok(Location {
            root: cfg.data_dir.clone().into(),
            relative: name.into(),
            kind: "service",
        })
    } else {
        explorer::locate(cfg, name)
    }
}
fn names(cfg: &Config, require_main: bool) -> io::Result<Vec<String>> {
    let mut items: Vec<_> = explorer::inventory(cfg)?
        .files
        .into_iter()
        .map(|f| f.path)
        .collect();
    if require_main && !items.iter().any(|name| name == "nfqws2.conf") {
        return Err(invalid("активный nfqws2.conf не найден"));
    }
    match location(cfg, SERVICE)?.open() {
        Ok(_) => items.push(SERVICE.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if items.len() > 1024 {
        return Err(invalid("слишком много файлов в стратегии"));
    }
    items.sort_unstable();
    Ok(items)
}
fn encode(cfg: &Config, tmp: &mut File, require_main: bool) -> io::Result<()> {
    let mut remain = TOTAL;
    let mut writer = ZipWriter::new(tmp.try_clone()?);
    for name in names(cfg, require_main)? {
        let file = location(cfg, &name)?.open()?;
        let meta = file.metadata()?;
        let size = meta.len();
        if size > remain {
            return Err(invalid("стратегия превышает 64 МиБ"));
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = if meta.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        writer.start_file(
            name,
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(mode),
        )?;
        let n = io::copy(&mut file.take(size + 1), &mut writer)?;
        if n != size {
            return Err(invalid("файл изменился во время архивации"));
        }
        remain -= n;
        if tmp.metadata()?.len() > ZIP_LIMIT {
            return Err(invalid("ZIP превышает 32 МиБ"));
        }
    }
    writer.finish()?;
    if tmp.metadata()?.len() > ZIP_LIMIT {
        return Err(invalid("ZIP превышает 32 МиБ"));
    }
    tmp.rewind()
}
#[derive(Serialize, Deserialize, Clone)]
pub(super) struct Snapshot {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub created_at: String,
    pub automatic: bool,
}
fn directory(cfg: &Config) -> io::Result<PathBuf> {
    let path = Path::new(&cfg.data_dir).join("strategy-snapshots");
    match path.symlink_metadata() {
        Ok(m) if !m.is_dir() => Err(invalid("ожидался каталог снимков")),
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(path),
    }
}
fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 41
        || !s.is_ascii()
        || b[8] != b'T'
        || b[15] != b'Z'
        || b[16] != b'-'
        || !s.ends_with(".zip")
        || !b[17..37].iter().all(u8::is_ascii_hexdigit)
    {
        return false;
    }
    let part = |a: usize, z: usize| s[a..z].parse::<u8>().ok();
    let Some(date) = s[..4].parse::<i32>().ok().zip(part(4, 6)).zip(part(6, 8)) else {
        return false;
    };
    let ((year, month), day) = date;
    time::Month::try_from(month)
        .ok()
        .and_then(|m| time::Date::from_calendar_date(year, m, day).ok())
        .is_some()
        && part(9, 11).is_some_and(|v| v < 24)
        && part(11, 13).is_some_and(|v| v < 60)
        && part(13, 15).is_some_and(|v| v < 60)
}
fn open_nofollow(path: &Path, limit: u64) -> io::Result<File> {
    let m = path.symlink_metadata()?;
    if !m.is_file() || m.len() > limit {
        return Err(invalid("недопустимый файл снимка"));
    }
    let mut op = File::options();
    op.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        op.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = op.open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > limit {
        return Err(invalid("недопустимый файл снимка"));
    }
    Ok(f)
}
pub(super) fn snapshot_file(cfg: &Config, id: &str) -> io::Result<File> {
    if !valid_id(id) {
        return Err(invalid("недопустимый идентификатор снимка"));
    }
    open_nofollow(&directory(cfg)?.join(id), ZIP_LIMIT)
}
fn list(cfg: &Config) -> io::Result<Vec<Snapshot>> {
    let dir = directory(cfg)?;
    let entries = match dir.read_dir() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        r => r?,
    };
    let mut out = vec![];
    for e in entries {
        let e = e?;
        let Ok(id) = e.file_name().into_string() else {
            continue;
        };
        if !valid_id(&id) || !e.file_type()?.is_file() {
            continue;
        }
        let st = e.metadata()?;
        let meta: Option<Value> = open_nofollow(&dir.join(format!("{id}.json")), 4096)
            .ok()
            .and_then(|f| serde_json::from_reader(f.take(4096)).ok());
        let (name, automatic) = meta.as_ref().map_or(("Стратегия", false), |m| {
            (
                m["name"].as_str().unwrap_or("Стратегия"),
                m["automatic"].as_bool().unwrap_or(false),
            )
        });
        out.push(Snapshot {
            id,
            name: name.into(),
            size: st.len(),
            created_at: explorer::stamp(st.modified()?)?,
            automatic,
        });
    }
    out.sort_unstable_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(out)
}
fn remove(cfg: &Config, id: &str) -> io::Result<()> {
    drop(snapshot_file(cfg, id)?);
    let dir = directory(cfg)?;
    fs::remove_file(dir.join(id))?;
    match fs::remove_file(dir.join(format!("{id}.json"))) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    sync_dir(&dir)
}
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}
pub(super) fn snapshot(cfg: &Config, name: &str, automatic: bool) -> io::Result<Snapshot> {
    let name = name.trim();
    let name = if name.is_empty() {
        "Стратегия"
    } else {
        name
    };
    if name.len() > 160 || name.contains(['\r', '\n', '\0']) {
        return Err(invalid("недопустимое имя снимка"));
    }
    let existing = list(cfg)?;
    if !automatic && existing.iter().filter(|s| !s.automatic).count() >= 10 {
        return Err(invalid("уже сохранено 10 ручных снимков"));
    }
    let dir = directory(cfg)?;
    fs::create_dir_all(&dir)?;
    let mut archive = NamedTempFile::new_in(&dir)?;
    encode(cfg, archive.as_file_mut(), !automatic)?;
    archive.as_file().sync_all()?;
    let size = archive.as_file().metadata()?.len();
    if existing
        .iter()
        .try_fold(size, |total, s| total.checked_add(s.size))
        .is_none_or(|n| n > 128 << 20)
    {
        return Err(invalid("снимки занимают больше 128 МиБ"));
    }
    let now = time::OffsetDateTime::now_utc();
    let random = format!("{}{}", nfqws2_store::new_id()?, nfqws2_store::new_id()?);
    let id = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z-{}.zip",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        &random[..20]
    );
    let entry = Snapshot {
        id: id.clone(),
        name: name.into(),
        size,
        created_at: explorer::stamp(SystemTime::from(now))?,
        automatic,
    };
    let mut meta = NamedTempFile::new_in(&dir)?;
    serde_json::to_writer(&mut meta, &entry)?;
    meta.flush()?;
    meta.as_file().sync_all()?;
    let label = dir.join(format!("{id}.json"));
    meta.persist_noclobber(&label)?;
    if let Err(e) = archive.persist_noclobber(dir.join(id)) {
        let _ = fs::remove_file(label);
        return Err(e.into());
    }
    sync_dir(&dir)?;
    if automatic {
        for old in existing.iter().filter(|s| s.automatic).skip(2) {
            remove(cfg, &old.id)?;
        }
    }
    Ok(entry)
}
#[derive(Deserialize)]
struct Name {
    #[serde(default)]
    name: String,
}
#[derive(Deserialize)]
struct Select {
    id: String,
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/nfqws2/strategy/export", get(export))
        .route(
            "/api/nfqws2/strategy/snapshots",
            get(snapshots).post(create),
        )
        .route(
            "/api/nfqws2/strategy/snapshot",
            get(download).delete(delete),
        )
}
fn mapped(e: ApiError) -> ApiError {
    if e.0 == StatusCode::NOT_FOUND {
        e
    } else {
        super::bad(e.1)
    }
}
async fn export(State(s): State<Shared>) -> Result<Response, ApiError> {
    let f = blocking(move || {
        s.store.transaction(|_| {
            let mut tmp = tempfile::tempfile_in(Path::new(&s.config.data_dir).join(".store"))?;
            encode(&s.config, &mut tmp, true)?;
            Ok(tmp)
        })
    })
    .await
    .map_err(mapped)?;
    Ok(explorer::serve_file(
        f,
        "nfqws2-strategy.zip",
        "application/zip",
    )?)
}
async fn snapshots(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.store
            .transaction(|_| Ok(Json(json!({"snapshots":list(&s.config)?}))))
    })
    .await
    .map_err(mapped)
}
async fn create(
    State(s): State<Shared>,
    ApiJson(input): ApiJson<Name>,
) -> Result<Json<Snapshot>, ApiError> {
    blocking(move || {
        s.store
            .transaction(|_| snapshot(&s.config, &input.name, false).map(Json))
    })
    .await
    .map_err(mapped)
}
async fn download(State(s): State<Shared>, Query(q): Query<Select>) -> Result<Response, ApiError> {
    blocking(move || {
        explorer::serve_file(snapshot_file(&s.config, &q.id)?, &q.id, "application/zip")
    })
    .await
    .map_err(mapped)
}
async fn delete(State(s): State<Shared>, Query(q): Query<Select>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.store.transaction(|_| {
            remove(&s.config, &q.id)?;
            Ok(Json(json!({"status":"deleted"})))
        })
    })
    .await
    .map_err(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshots_roundtrip_stored_files_and_prune_only_automatic() {
        let d = tempfile::tempdir().unwrap();
        let main = d.path().join("engine.conf");
        fs::write(&main, b"X=1\n").unwrap();
        let cfg = Config {
            nfqws2_conf: main.display().to_string(),
            data_dir: d.path().join("state").display().to_string(),
            lua_dir: d.path().join("lua").display().to_string(),
            system_blobs_dir: d.path().join("blobs").display().to_string(),
            ..Config::default()
        };
        let keep = snapshot(&cfg, "clipboard", false).unwrap();
        let zip = snapshot_file(&cfg, &keep.id).unwrap();
        let mut reader = zip::ZipArchive::new(zip).unwrap();
        let mut text = String::new();
        reader
            .by_name("nfqws2.conf")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "X=1\n");
        for _ in 0..5 {
            snapshot(&cfg, "rollback", true).unwrap();
        }
        let found = list(&cfg).unwrap();
        assert_eq!(found.len(), 4);
        assert!(found.iter().any(|x| x.id == keep.id && !x.automatic));
        assert!(!valid_id("../outside.zip"));
        remove(&cfg, &keep.id).unwrap();
        assert_eq!(list(&cfg).unwrap().len(), 3);
    }
}
