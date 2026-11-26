use super::{
    explorer::{self, invalid},
    snapshots::{self, location, SERVICE, TOTAL, ZIP_LIMIT},
};
use crate::http::{blocking, ApiError, Shared};
use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use nfqws2_config::Config;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use zip::ZipArchive;

struct Entry {
    path: PathBuf,
    mode: u32,
    size: u64,
    hash: String,
    normalized: bool,
}
type Entries = BTreeMap<String, Entry>;
pub(super) fn digest_hex(hash: Sha256) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(text, "{byte:02x}").expect("string writer");
    }
    text
}
struct Copy {
    _dir: TempDir,
    entries: Entries,
    next_file: usize,
}
impl Copy {
    fn new(cfg: &Config) -> io::Result<Self> {
        Ok(Self {
            _dir: tempfile::tempdir_in(Path::new(&cfg.data_dir).join(".store"))?,
            entries: Entries::new(),
            next_file: 0,
        })
    }
    fn add(
        &mut self,
        name: String,
        mut source: impl Read,
        mode: u32,
        normalized: bool,
        remaining: &mut u64,
    ) -> io::Result<()> {
        let path = self._dir.path().join(self.next_file.to_string());
        self.next_file += 1;
        let mut file = File::create(&path)?;
        let limit = (*remaining).min(explorer::FILE_LIMIT);
        let mut out = [0; 16 << 10];
        let mut hash = Sha256::new();
        let mut size = 0;
        loop {
            let n = source.read(&mut out)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > limit {
                return Err(invalid("превышен лимит распакованного архива"));
            }
            file.write_all(&out[..n])?;
            hash.update(&out[..n]);
        }
        *remaining -= size;
        self.entries.insert(
            name,
            Entry {
                path,
                mode,
                size,
                hash: digest_hex(hash),
                normalized,
            },
        );
        Ok(())
    }
}
fn current(cfg: &Config) -> io::Result<Copy> {
    let mut set = Copy::new(cfg)?;
    let mut remaining = TOTAL;
    let mut names: Vec<_> = explorer::inventory(cfg)?
        .files
        .into_iter()
        .map(|f| f.path)
        .collect();
    match location(cfg, SERVICE)?.open() {
        Ok(_) => names.push(SERVICE.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    for name in names {
        let f = location(cfg, &name)?.open()?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            f.metadata()?.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = if f.metadata()?.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        set.add(name, f, mode, false, &mut remaining)?;
    }
    Ok(set)
}
fn canonical(name: &str) -> String {
    if let Some(tail) = name.strip_prefix("lits/") {
        return format!("lists/{tail}");
    }
    if !name.contains('/') {
        if name.ends_with(".sh") {
            return format!("scripts/{name}");
        }
        if name.ends_with(".lua") || name.ends_with(".lua.gz") {
            return format!("lua/{name}");
        }
    }
    name.to_owned()
}
fn read_zip(cfg: &Config, f: File) -> io::Result<Copy> {
    if f.metadata()?.len() > ZIP_LIMIT {
        return Err(invalid("ZIP превышает 32 МиБ"));
    }
    let mut zip = ZipArchive::new(f)?;
    if zip.len() > 2048 {
        return Err(invalid("слишком много записей в ZIP"));
    }
    let mut seen = HashSet::new();
    let mut out = Copy::new(cfg)?;
    let mut remaining = TOTAL;
    let mut source_total = 0;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let raw = entry.name()?.into_owned();
        let dir = entry.is_dir();
        let raw = if dir { raw.trim_end_matches('/') } else { &raw };
        if !explorer::clean(raw) {
            return Err(invalid("недопустимый путь в архиве"));
        }
        if dir {
            continue;
        }
        let name = canonical(raw);
        let dest = location(cfg, &name)?;
        if entry
            .unix_mode()
            .is_some_and(|m| !matches!(m & 0o170000, 0 | 0o100000))
            || !seen.insert(name.to_ascii_lowercase())
        {
            return Err(invalid("повтор, ссылка или специальный файл в архиве"));
        }
        let size = entry.size();
        if out.entries.len() >= 1024 || size > explorer::FILE_LIMIT || size > TOTAL - source_total {
            return Err(invalid("слишком большой архив"));
        }
        source_total += size;
        let mode = match dest.kind {
            "script" => 0o755,
            "service" => 0o600,
            _ => 0o644,
        };
        if dest.kind == "blob" || name.to_ascii_lowercase().ends_with(".gz") {
            let before = remaining;
            out.add(name, entry, mode, false, &mut remaining)?;
            if before - remaining != size {
                return Err(invalid("не совпал размер записи ZIP"));
            }
        } else {
            let mut text = String::new();
            entry.by_ref().take(size + 1).read_to_string(&mut text)?;
            if text.len() as u64 != size || text.contains('\0') {
                return Err(invalid("ожидается текст UTF-8"));
            }
            let norm = if dest.kind == "lua" {
                std::borrow::Cow::Borrowed(text.as_str())
            } else {
                let clean = text.strip_prefix('\u{feff}').unwrap_or(&text);
                if clean.contains("\r\n") {
                    std::borrow::Cow::Owned(clean.replace("\r\n", "\n"))
                } else {
                    std::borrow::Cow::Borrowed(clean)
                }
            };
            let data = if dest.kind == "conf" {
                nfqws2_config::normalize_wan_interfaces(&norm)?
            } else {
                norm.as_ref().into()
            };
            out.add(name, data.as_bytes(), mode, data != text, &mut remaining)?;
        }
    }
    let engine = out
        .entries
        .get("nfqws2.conf")
        .ok_or_else(|| invalid("в архиве отсутствует nfqws2.conf"))?;
    if nfqws2_config::managed_service_config_range(&fs::read_to_string(&engine.path)?)?.is_some()
        && !out.entries.contains_key(SERVICE)
    {
        return Err(invalid("в архиве отсутствуют настройки сервисных профилей"));
    }
    if let Some(doc) = out.entries.get(SERVICE) {
        let saved: nfqws2_config::service_profiles::Document =
            serde_json::from_reader(File::open(&doc.path)?).map_err(|e| invalid(&e.to_string()))?;
        let content = fs::read_to_string(&engine.path)?;
        let mode = engine.mode;
        let was_normalized = engine.normalized;
        let (config, lists, services) = if saved.services.is_empty() {
            let mut source = content.clone();
            if let Some(range) = nfqws2_config::managed_service_config_range(&source)? {
                source.replace_range(range, "");
            }
            (source, BTreeMap::new(), Vec::new())
        } else {
            let result = super::services::compile(cfg, content.clone(), saved.services)?;
            (result.config, result.lists, result.services)
        };
        let encoded = super::services::encode(&nfqws2_config::service_profiles::Document {
            services,
            restart_required: true,
        })?;
        remaining += out.entries[SERVICE].size;
        out.add(
            SERVICE.into(),
            encoded.as_slice(),
            0o600,
            false,
            &mut remaining,
        )?;
        if config != content {
            remaining += out.entries["nfqws2.conf"].size;
            out.add(
                "nfqws2.conf".into(),
                config.as_bytes(),
                mode,
                was_normalized,
                &mut remaining,
            )?;
        }
        for (name, text) in lists {
            let path = format!("lists/{name}");
            if let Some(previous) = out.entries.get_mut(&path) {
                if digest_hex(Sha256::new().chain_update(text.as_bytes())) != previous.hash {
                    return Err(invalid(
                        "управляемый список не соответствует сервисным профилям",
                    ));
                }
                previous.mode = 0o644;
            } else {
                if out.entries.len() >= 1024 {
                    return Err(invalid("слишком много файлов в архиве"));
                }
                out.add(path, text.as_bytes(), 0o644, false, &mut remaining)?;
            }
        }
    }
    Ok(out)
}
fn personal(name: &str) -> bool {
    if !name.starts_with("lists/") {
        return false;
    }
    let name = name.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    let plain = name.strip_suffix(".gz").unwrap_or(&name);
    let s = plain.rsplit_once('.').map_or(plain, |(base, _)| base);
    matches!(
        s,
        "user" | "auto" | "userlist" | "autolist" | "hostlist-auto"
    ) || s.starts_with("userlist-")
        || s.starts_with("autolist-")
}
fn keep(name: &str, policy: &str, now: &Entries) -> bool {
    policy == "keep"
        && personal(name)
        && (now.contains_key(name)
            || name.strip_suffix(".gz").map_or_else(
                || now.contains_key(&format!("{name}.gz")),
                |n| now.contains_key(n),
            ))
}
fn managed(name: &str) -> bool {
    name.starts_with("lists/")
        && name
            .rsplit('/')
            .next()
            .is_some_and(|n| super::files::managed(n.strip_suffix(".gz").unwrap_or(n)))
}
#[derive(Serialize)]
struct Item<'a> {
    path: &'a str,
    size: u64,
    exists: bool,
    protected_list: bool,
}
#[derive(Serialize)]
struct Preview<'a> {
    digest: String,
    files: Vec<Item<'a>>,
    conflicts: Vec<&'a str>,
    protected_lists: Vec<&'a str>,
    removed: Vec<&'a str>,
    warnings: Vec<&'static str>,
}
fn preview<'a>(input: &'a Entries, now: &'a Entries, restore: bool) -> Preview<'a> {
    let mut hash = Sha256::new();
    hash.update(if restore {
        b"restore\0".as_slice()
    } else {
        b"import\0".as_slice()
    });
    for (index, group) in [input, now].iter().enumerate() {
        for (name, entry) in group.iter() {
            hash.update(name.as_bytes());
            hash.update([0]);
            if index == 1 && personal(name) {
                hash.update(b"personal-list\n");
            } else {
                hash.update(format!("{:o}\0{}\n", entry.mode, entry.hash).as_bytes());
            }
        }
        hash.update([0]);
    }
    let mut p = Preview {
        digest: digest_hex(hash),
        files: vec![],
        conflicts: vec![],
        protected_lists: vec![],
        removed: vec![],
        warnings: vec![],
    };
    for (name, entry) in input {
        let exists = now.contains_key(name);
        let protected_list = personal(name);
        p.files.push(Item {
            path: name,
            size: entry.size,
            exists,
            protected_list,
        });
        if exists {
            p.conflicts.push(name);
        }
        if protected_list {
            p.protected_lists.push(name);
        }
    }
    if !p.protected_lists.is_empty() {
        p.warnings
            .push("Можно сохранить существующие личные списки.");
    }
    if input.values().any(|v| v.normalized) {
        p.warnings
            .push("В текстовых файлах нормализованы окончания строк или пути.");
    }
    if restore {
        p.removed = now
            .keys()
            .filter(|k| !input.contains_key(*k) && !managed(k))
            .map(String::as_str)
            .collect();
    }
    p.warnings
        .push("Для запуска стратегии примените конфиг отдельно.");
    p
}
fn apply(
    cfg: &Config,
    input: &Entries,
    now: &Entries,
    p: &Preview<'_>,
    fields: &BTreeMap<String, String>,
) -> io::Result<Value> {
    if fields.get("digest") != Some(&p.digest) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "файлы изменились после предварительного просмотра",
        ));
    }
    let policy = fields.get("lists").map_or("", String::as_str);
    if !matches!(policy, "keep" | "replace")
        && (!policy.is_empty() || !p.protected_lists.is_empty())
    {
        return Err(invalid("выберите действие для личных списков"));
    }
    if !fields.get("overwrite").is_some_and(|v| v == "true")
        && (!p.removed.is_empty() || p.conflicts.iter().any(|n| !keep(n, policy, now)))
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "подтвердите замену файлов",
        ));
    }
    let point = snapshots::snapshot(cfg, "Перед импортом стратегии", true)?;
    let mut changed = Vec::new();
    let mut kept = vec![];
    let mut removed = vec![];
    let mut imported = vec![];
    let result = (|| -> io::Result<()> {
        for (name, entry) in input {
            if keep(name, policy, now)
                || managed(name) && now.get(name).is_some_and(|e| e.hash == entry.hash)
            {
                kept.push(name);
                continue;
            }
            let loc = location(cfg, name)?;
            changed.push(name.as_str());
            loc.replace(cfg, File::open(&entry.path)?, true, Some(entry.mode))?;
            imported.push(name);
        }
        for name in &p.removed {
            if personal(name) && policy == "keep" {
                kept.push(now.get_key_value(*name).unwrap().0);
                continue;
            }
            changed.push(name);
            location(cfg, name)?.remove_file()?;
            removed.push(name);
        }
        Ok(())
    })();
    if let Err(e) = result {
        let mut failures = vec![];
        for name in changed.into_iter().rev() {
            let restore = (|| -> io::Result<()> {
                let loc = location(cfg, name)?;
                if let Some(prior) = now.get(name) {
                    loc.replace(cfg, File::open(&prior.path)?, true, Some(prior.mode))
                } else {
                    match loc.remove_file() {
                        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                        r => r,
                    }
                }
            })();
            if let Err(err) = restore {
                failures.push(format!("{name}: {err}"));
            }
        }
        return Err(if failures.is_empty() {
            e
        } else {
            io::Error::other(format!("{e}; откат: {}", failures.join(", ")))
        });
    }
    Ok(json!({"snapshot":point,"kept":kept,"imported":imported,"removed":removed}))
}
async fn process(s: Shared, form: Multipart, commit: bool) -> Result<Json<Value>, ApiError> {
    let (fields, upload) = explorer::multipart(form, &s.config.data_dir, ZIP_LIMIT).await?;
    let id = fields.get("snapshot").cloned().unwrap_or_default();
    let restore = !id.is_empty();
    if restore == upload.is_some() {
        return Err(super::bad("выберите один файл или снимок"));
    }
    blocking(move || {
        s.store.transaction(|_| {
            let file = if let Some(temp) = upload {
                temp.reopen()?
            } else {
                snapshots::snapshot_file(&s.config, &id)?
            };
            let mut input = read_zip(&s.config, file)?;
            let now = current(&s.config)?;
            if now.entries.contains_key(SERVICE) && !input.entries.contains_key(SERVICE) {
                let mut remaining = TOTAL - input.entries.values().map(|e| e.size).sum::<u64>();
                input.add(
                    SERVICE.into(),
                    b"{\"services\":[],\"restart_required\":true}\n".as_slice(),
                    0o600,
                    false,
                    &mut remaining,
                )?;
            }
            for (n, e) in &input.entries {
                if managed(n) && now.entries.get(n).is_some_and(|old| old.hash != e.hash) {
                    return Err(invalid("управляемый список сервисов изменён"));
                }
            }
            let p = preview(&input.entries, &now.entries, restore);
            if commit {
                apply(&s.config, &input.entries, &now.entries, &p, &fields).map(Json)
            } else {
                Ok(Json(serde_json::to_value(p)?))
            }
        })
    })
    .await
    .map_err(|e| {
        if e.0 == StatusCode::CONFLICT
            || [
                "файлы изменились после предварительного просмотра",
                "подтвердите замену файлов",
            ]
            .contains(&e.1.as_str())
        {
            ApiError(StatusCode::CONFLICT, e.1)
        } else {
            super::bad(e.1)
        }
    })
}
async fn inspect(State(s): State<Shared>, m: Multipart) -> Result<Json<Value>, ApiError> {
    process(s, m, false).await
}
async fn import(State(s): State<Shared>, m: Multipart) -> Result<Json<Value>, ApiError> {
    process(s, m, true).await
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/nfqws2/strategy/preview", post(inspect))
        .route("/api/nfqws2/strategy/import", post(import))
        .layer(DefaultBodyLimit::max(33 << 20))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;
    fn archive(files: &[(&str, &[u8])]) -> File {
        let f = tempfile::tempfile().unwrap();
        let mut zip = zip::ZipWriter::new(f);
        for (name, b) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b).unwrap();
        }
        let mut f = zip.finish().unwrap();
        f.rewind().unwrap();
        f
    }
    fn config(dir: &Path) -> Config {
        let state = dir.join("data");
        fs::create_dir_all(state.join(".store")).unwrap();
        Config {
            data_dir: state.display().to_string(),
            nfqws2_conf: dir.join("nfqws2.conf").display().to_string(),
            system_blobs_dir: dir.join("blobs").display().to_string(),
            lua_dir: dir.join("lua").display().to_string(),
            ..Config::default()
        }
    }
    #[test]
    fn import_requires_current_revision_and_respects_live_personal_lists() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path());
        fs::write(&cfg.nfqws2_conf, b"X=old\n").unwrap();
        fs::create_dir(tmp.path().join("lists")).unwrap();
        let list = tmp.path().join("lists/user.list");
        fs::write(&list, b"keep\n").unwrap();
        let input = read_zip(
            &cfg,
            archive(&[
                ("nfqws2.conf", b"X=new\r\n"),
                ("lits/user.list", b"replace\n"),
                ("test.lua", b"-- unchanged\r\n"),
            ]),
        )
        .unwrap();
        let now = current(&cfg).unwrap();
        let p = preview(&input.entries, &now.entries, false);
        assert!(p.protected_lists.contains(&"lists/user.list"));
        assert!(p.files.iter().any(|f| f.path == "lua/test.lua"));
        let mut options = BTreeMap::from([
            ("lists".into(), "keep".into()),
            ("overwrite".into(), "true".into()),
            ("digest".into(), "old".into()),
        ]);
        assert_eq!(
            apply(&cfg, &input.entries, &now.entries, &p, &options)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::write(&list, b"keep latest\n").unwrap();
        let fresh = current(&cfg).unwrap();
        let preview2 = preview(&input.entries, &fresh.entries, false);
        assert_eq!(p.digest, preview2.digest);
        options.insert("digest".into(), p.digest);
        let result = apply(&cfg, &input.entries, &fresh.entries, &preview2, &options).unwrap();
        assert_eq!(result["kept"], json!(["lists/user.list"]));
        assert_eq!(fs::read(&cfg.nfqws2_conf).unwrap(), b"X=new\n");
        assert_eq!(fs::read(list).unwrap(), b"keep latest\n");
        assert_eq!(
            fs::read(tmp.path().join("lua/test.lua")).unwrap(),
            b"-- unchanged\r\n"
        );
        assert!(snapshots::snapshot_file(&cfg, result["snapshot"]["id"].as_str().unwrap()).is_ok());
    }
    #[test]
    fn bad_paths_aliases_and_unbounded_archives_fail_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path());
        for name in ["lists/../../wrong", "/etc/shadow", "unknown/file"] {
            assert!(read_zip(&cfg, archive(&[("nfqws2.conf", b""), (name, b"bad")])).is_err());
        }
        assert!(read_zip(
            &cfg,
            archive(&[("nfqws2.conf", b""), ("lists/A", b"a"), ("lits/a", b"b")])
        )
        .is_err());
        assert!(!Path::new(&cfg.nfqws2_conf).exists());
    }
    #[cfg(all(feature = "embedded-strategies", not(feature = "compact")))]
    #[test]
    fn archive_rebuilds_service_lists_for_this_router_and_rejects_conflicting_content() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path());
        let doc = br#"{"services":[{"id":"main","name":"Service","enabled":true,"groups":[{"id":"web","name":"WWW","kind":"domains","entries":["example.test"],"strategy":"--filter-tcp=443"}]}]}"#;
        let base = b"TCP_PORTS='80'\n";
        let incoming = read_zip(&cfg, archive(&[("nfqws2.conf", base), (SERVICE, doc)])).unwrap();
        let list = incoming
            .entries
            .keys()
            .find(|k| k.starts_with("lists/"))
            .unwrap();
        assert_eq!(
            fs::read(&incoming.entries[list].path).unwrap(),
            b"example.test\n"
        );
        let conf = fs::read_to_string(&incoming.entries["nfqws2.conf"].path).unwrap();
        assert!(conf.contains(&tmp.path().join(list).to_string_lossy().replace('\\', "/")));
        assert!(conf.contains("TCP_PORTS='80,443'"));
        assert!(
            serde_json::from_reader::<_, Value>(
                File::open(&incoming.entries[SERVICE].path).unwrap()
            )
            .unwrap()["restart_required"]
                == true
        );
        assert!(read_zip(
            &cfg,
            archive(&[("nfqws2.conf", base), (SERVICE, doc), (list, b"altered\n")])
        )
        .is_err());
        assert!(!Path::new(&cfg.nfqws2_conf).exists());
    }
}
