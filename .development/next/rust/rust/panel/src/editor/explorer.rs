use super::{files::READ_LIMIT, owner};
use crate::http::{blocking, ApiError, Shared};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Query, State},
    http::{header, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use nfqws2_config::Config;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;

pub(super) const FILE_LIMIT: u64 = 16 << 20;
pub(super) fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
fn map_error(e: ApiError) -> ApiError {
    match e.0 {
        StatusCode::NOT_FOUND => e,
        _ if e.1 == "файл уже существует" => ApiError(StatusCode::CONFLICT, e.1),
        _ => ApiError(StatusCode::BAD_REQUEST, e.1),
    }
}
pub(super) fn clean(name: &str) -> bool {
    name.len() <= 512
        && name.split('/').count() <= 10
        && name.split('/').all(|s| {
            !s.is_empty()
                && s.len() <= 180
                && !s.starts_with('.')
                && !s.ends_with('.')
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
pub(super) fn roots(cfg: &Config) -> BTreeMap<&'static str, PathBuf> {
    let conf = Path::new(&cfg.nfqws2_conf)
        .parent()
        .unwrap_or(Path::new("."));
    let fallback = |s: &str, leaf: &str| {
        if s.is_empty() {
            conf.join(leaf)
        } else {
            PathBuf::from(s)
        }
    };
    BTreeMap::from([
        ("conf", conf.into()),
        ("script", conf.into()),
        ("list", conf.join("lists")),
        ("lua", fallback(&cfg.lua_dir, "lua")),
        ("blob", fallback(&cfg.system_blobs_dir, "blobs")),
    ])
}
pub(super) struct Location {
    pub root: PathBuf,
    pub relative: PathBuf,
    pub kind: &'static str,
}
pub(super) fn locate(cfg: &Config, name: &str) -> io::Result<Location> {
    if !clean(name) {
        return Err(invalid("недопустимый путь"));
    }
    let base = Path::new(&cfg.nfqws2_conf)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("nfqws2.conf");
    let (kind, rel) = if name == "nfqws2.conf" {
        ("conf", base)
    } else {
        let (prefix, tail) = name
            .split_once('/')
            .ok_or_else(|| invalid("неизвестный каталог"))?;
        let k = match prefix {
            "lists" => "list",
            "blobs" => "blob",
            "lua" => "lua",
            "scripts" if !tail.contains('/') && tail.ends_with(".sh") => "script",
            "configs"
                if !tail.contains('/')
                    && tail != base
                    && tail != "nfqws2.conf"
                    && [".conf", ".conf-old", ".conf-opkg", ".apk-new"]
                        .iter()
                        .any(|ext| tail.ends_with(ext)) =>
            {
                "conf"
            }
            _ => return Err(invalid("неподдерживаемое имя файла")),
        };
        (k, tail)
    };
    Ok(Location {
        root: roots(cfg).remove(kind).unwrap(),
        relative: rel.into(),
        kind,
    })
}
// Anchor every descendant operation in an opened directory. Entware itself may
// be a symlink to removable storage. Only the server-selected root may resolve it.
struct Directory {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    _fd: File,
}
impl Directory {
    fn open(root: &Path, rel: &Path, create: bool) -> io::Result<Self> {
        if create {
            fs::create_dir_all(root)?;
        }
        #[cfg(target_os = "linux")]
        let mut dir = {
            use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
            let f = File::options()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(root)?;
            Self {
                path: PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd())),
                _fd: f,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let mut dir = Self {
            path: root.canonicalize()?,
        };
        for entry in rel.components() {
            let std::path::Component::Normal(name) = entry else {
                return Err(invalid("недопустимый каталог"));
            };
            let p = dir.path.join(name);
            if create {
                match fs::create_dir(&p) {
                    Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                    _ => {}
                }
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
                let f = File::options()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    .open(p)?;
                dir = Self {
                    path: PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd())),
                    _fd: f,
                };
            }
            #[cfg(not(target_os = "linux"))]
            {
                if !p.symlink_metadata()?.is_dir() {
                    return Err(invalid("ожидается обычный каталог"));
                }
                dir.path = p;
            }
        }
        Ok(dir)
    }
}
impl Location {
    fn parent(&self, create: bool) -> io::Result<(Directory, PathBuf)> {
        let d = Directory::open(
            &self.root,
            self.relative.parent().unwrap_or(Path::new("")),
            create,
        )?;
        let p = d.path.join(
            self.relative
                .file_name()
                .ok_or_else(|| invalid("отсутствует имя файла"))?,
        );
        Ok((d, p))
    }
    pub fn open(&self) -> io::Result<File> {
        let (_parent, p) = self.parent(false)?;
        if !p.symlink_metadata()?.is_file() {
            return Err(invalid("ожидается обычный файл"));
        }
        let mut opt = File::options();
        opt.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opt.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let f = opt.open(p)?;
        let meta = f.metadata()?;
        if !meta.is_file() || meta.len() > FILE_LIMIT {
            return Err(invalid("ожидается обычный файл до 16 МиБ"));
        }
        Ok(f)
    }
    fn managed(&self) -> bool {
        self.kind == "list"
            && self
                .relative
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| super::files::managed(n.strip_suffix(".gz").unwrap_or(n)))
    }
    fn save(&self, cfg: &Config, file: File, overwrite: bool) -> io::Result<()> {
        if self.managed() {
            return Err(invalid("список управляется вкладкой «Сервисы»"));
        }
        self.replace(cfg, file, overwrite, None)
    }
    pub(super) fn replace(
        &self,
        cfg: &Config,
        file: impl Read,
        overwrite: bool,
        prepared_mode: Option<u32>,
    ) -> io::Result<()> {
        let (d, p) = self.parent(true)?;
        let prior = super::files::regular(&p)?;
        if prior.is_some() && !overwrite {
            return Err(invalid("файл уже существует"));
        }
        let mut temp = NamedTempFile::new_in(&d.path)?;
        let name = p.file_name().unwrap().to_str().unwrap();
        if prepared_mode.is_some()
            || self.kind == "blob"
            || name.to_ascii_lowercase().ends_with(".gz")
        {
            if io::copy(&mut file.take(FILE_LIMIT + 1), &mut temp)? > FILE_LIMIT {
                return Err(invalid("файл больше 16 МиБ"));
            }
        } else {
            let mut s = String::new();
            file.take(FILE_LIMIT + 1).read_to_string(&mut s)?;
            if s.len() as u64 > FILE_LIMIT || s.contains('\0') {
                return Err(invalid("ожидается текст UTF-8 до 16 МиБ"));
            }
            if self.kind != "lua" {
                s = s
                    .strip_prefix('\u{feff}')
                    .unwrap_or(&s)
                    .replace("\r\n", "\n");
            }
            if self.kind == "conf" {
                temp.write_all(nfqws2_config::normalize_wan_interfaces(&s)?.as_bytes())?;
            } else {
                temp.write_all(s.as_bytes())?;
            }
        }
        owner::apply(temp.as_file(), prior.as_ref(), cfg, self.kind, name)?;
        #[cfg(unix)]
        if prior.is_none() {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file().set_permissions(fs::Permissions::from_mode(
                prepared_mode.unwrap_or(if self.kind == "script" { 0o755 } else { 0o644 }) & 0o777,
            ))?;
        }
        temp.as_file().sync_all()?;
        if overwrite {
            temp.persist(p)?;
        } else {
            temp.persist_noclobber(p)?;
        }
        #[cfg(unix)]
        File::open(&d.path)?.sync_all()?;
        Ok(())
    }
    fn delete(&self) -> io::Result<()> {
        if self.managed() {
            return Err(invalid("список управляется вкладкой «Сервисы»"));
        }
        self.remove_file()
    }
    pub(super) fn remove_file(&self) -> io::Result<()> {
        let (d, p) = self.parent(false)?;
        if !p.symlink_metadata()?.is_file() {
            return Err(invalid("ожидается обычный файл"));
        }
        fs::remove_file(p)?;
        #[cfg(unix)]
        File::open(d.path)?.sync_all()?;
        #[cfg(not(unix))]
        drop(d);
        Ok(())
    }
}
pub(super) fn stamp(t: SystemTime) -> io::Result<String> {
    time::OffsetDateTime::from(t)
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(io::Error::other)
}
#[derive(Serialize)]
pub(super) struct Asset {
    pub path: String,
    kind: &'static str,
    size: u64,
    editable: bool,
    protected: bool,
    modified_at: String,
}
#[derive(Serialize)]
pub(super) struct Inventory {
    pub files: Vec<Asset>,
    directories: Vec<String>,
    directory_modified: BTreeMap<String, String>,
    roots: BTreeMap<&'static str, PathBuf>,
}
pub(super) fn inventory(cfg: &Config) -> io::Result<Inventory> {
    let mut out = Inventory {
        files: vec![],
        directories: vec![],
        directory_modified: Default::default(),
        roots: roots(cfg),
    };
    for (kind, prefix) in [
        ("conf", ""),
        ("list", "lists"),
        ("blob", "blobs"),
        ("lua", "lua"),
    ] {
        let root = out.roots[kind].clone();
        let mut pending = vec![(PathBuf::new(), prefix.to_owned())];
        while let Some((rel, label)) = pending.pop() {
            let dir = match Directory::open(&root, &rel, false) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                d => d?,
            };
            let when = stamp(fs::metadata(&dir.path)?.modified()?)?;
            if label.is_empty() {
                out.directory_modified
                    .insert("configs".into(), when.clone());
                out.directory_modified.insert("scripts".into(), when);
            } else {
                out.directory_modified.insert(label.clone(), when);
            }
            for entry in dir.path.read_dir()? {
                let entry = entry?;
                let Ok(n) = entry.file_name().into_string() else {
                    continue;
                };
                let ty = entry.file_type()?;
                if ty.is_symlink() {
                    continue;
                }
                let name = if label.is_empty() {
                    if ty.is_dir() {
                        continue;
                    }
                    if Some(n.as_str())
                        == Path::new(&cfg.nfqws2_conf)
                            .file_name()
                            .and_then(|v| v.to_str())
                    {
                        "nfqws2.conf".into()
                    } else if n.ends_with(".sh") {
                        format!("scripts/{n}")
                    } else {
                        format!("configs/{n}")
                    }
                } else {
                    format!("{label}/{n}")
                };
                if ty.is_dir() {
                    if clean(&format!("{name}/x")) {
                        if out.directories.len() >= 8192 {
                            return Err(invalid("слишком много каталогов"));
                        }
                        out.directories.push(name.clone());
                        pending.push((rel.join(n), name));
                    }
                } else if ty.is_file() {
                    let Ok(loc) = locate(cfg, &name) else {
                        continue;
                    };
                    let m = entry.metadata()?;
                    if out.files.len() >= 1024 {
                        return Err(invalid("слишком много файлов"));
                    }
                    let managed = loc.managed();
                    out.files.push(Asset {
                        editable: loc.kind != "blob"
                            && !n.ends_with(".gz")
                            && m.len() <= READ_LIMIT
                            && !managed,
                        protected: name == "nfqws2.conf" || managed,
                        path: name,
                        kind: loc.kind,
                        size: m.len(),
                        modified_at: stamp(m.modified()?)?,
                    });
                }
            }
        }
    }
    out.files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    out.directories.sort_unstable();
    Ok(out)
}
#[derive(Deserialize)]
struct Select {
    path: String,
}
pub(super) fn routes() -> Router<Shared> {
    Router::new().route("/api/nfqws2/assets", get(index)).route(
        "/api/nfqws2/assets/file",
        get(download)
            .post(upload)
            .delete(remove)
            .layer(DefaultBodyLimit::max(17 << 20)),
    )
}
async fn index(State(s): State<Shared>) -> Result<Json<Inventory>, ApiError> {
    blocking(move || inventory(&s.config).map(Json))
        .await
        .map_err(map_error)
}
pub(super) fn serve_file(file: File, name: &str, mime: &str) -> io::Result<Response> {
    use tokio::io::AsyncReadExt;
    let len = file.metadata()?.len();
    let stream = futures_util::stream::try_unfold(
        tokio::fs::File::from_std(file).take(len),
        |mut f| async move {
            let mut data = vec![0; 32 << 10];
            let n = f.read(&mut data).await?;
            data.truncate(n);
            Ok::<_, io::Error>((n > 0).then_some((data, f)))
        },
    );
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, len)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        )
        .body(Body::from_stream(stream))
        .map_err(io::Error::other)
}
async fn download(State(s): State<Shared>, Query(q): Query<Select>) -> Result<Response, ApiError> {
    blocking(move || {
        let loc = locate(&s.config, &q.path)?;
        serve_file(
            loc.open()?,
            q.path.rsplit('/').next().unwrap(),
            "application/octet-stream",
        )
    })
    .await
    .map_err(map_error)
}
async fn remove(State(s): State<Shared>, Query(q): Query<Select>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        s.store.transaction(|_| {
            if q.path == "nfqws2.conf" {
                return Err(invalid("активный конфиг нельзя удалить"));
            }
            locate(&s.config, &q.path)?.delete()?;
            Ok(Json(json!({"status":"deleted"})))
        })
    })
    .await
    .map_err(map_error)
}
pub(super) async fn multipart(
    mut form: Multipart,
    data_dir: &str,
    limit: u64,
) -> Result<(BTreeMap<String, String>, Option<NamedTempFile>), ApiError> {
    let mut fields = BTreeMap::new();
    let mut upload = None;
    while let Some(mut part) = form.next_field().await.map_err(super::bad)? {
        let name = part.name().unwrap_or("").to_owned();
        if name == "file" && upload.is_none() {
            let temp = NamedTempFile::new_in(Path::new(data_dir).join(".store"))?;
            let mut out = tokio::fs::File::from_std(temp.reopen()?);
            let mut len = 0;
            while let Some(chunk) = part.chunk().await.map_err(super::bad)? {
                len += chunk.len() as u64;
                if len > limit {
                    return Err(ApiError(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "слишком большой файл".into(),
                    ));
                }
                out.write_all(&chunk).await?;
            }
            out.flush().await?;
            upload = Some(temp);
        } else if ["path", "overwrite", "snapshot", "digest", "lists"].contains(&name.as_str()) {
            let mut b = Vec::new();
            while let Some(chunk) = part.chunk().await.map_err(super::bad)? {
                if b.len() + chunk.len() > 512 {
                    return Err(super::bad("слишком длинное поле"));
                }
                b.extend_from_slice(&chunk);
            }
            fields.insert(name, String::from_utf8(b).map_err(super::bad)?);
        } else if name == "file" {
            return Err(super::bad("повторное поле file"));
        }
    }
    Ok((fields, upload))
}
async fn upload(State(s): State<Shared>, form: Multipart) -> Result<Json<Value>, ApiError> {
    let (mut fields, file) = multipart(form, &s.config.data_dir, FILE_LIMIT).await?;
    let name = fields
        .remove("path")
        .ok_or_else(|| super::bad("не указан путь"))?;
    let file = file.ok_or_else(|| super::bad("не задан файл"))?;
    blocking(move || {
        s.store.transaction(|_| {
            locate(&s.config, &name)?.save(
                &s.config,
                file.reopen()?,
                fields.get("overwrite").is_some_and(|s| s == "true"),
            )?;
            Ok(Json(json!({"status":"saved","path":name})))
        })
    })
    .await
    .map_err(map_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(bytes: &[u8]) -> File {
        use std::io::Seek;
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f.rewind().unwrap();
        f
    }
    #[test]
    fn nested_binary_roundtrip_and_utf8_rules_keep_original_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            nfqws2_conf: dir.path().join("custom.conf").display().to_string(),
            system_blobs_dir: dir.path().join("binary").display().to_string(),
            lua_dir: dir.path().join("scripts").display().to_string(),
            ..Config::default()
        };
        let bin = locate(&cfg, "blobs/demo/sample.bin").unwrap();
        bin.save(&cfg, source(b"\0\xff"), false).unwrap();
        assert!(bin.save(&cfg, source(b"oops"), false).is_err());
        let mut buf = Vec::new();
        bin.open().unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"\0\xff");
        let conf = locate(&cfg, "nfqws2.conf").unwrap();
        conf.save(&cfg, source(b"X=1\r\n"), false).unwrap();
        assert!(conf.save(&cfg, source(b"binary\0file"), true).is_err());
        assert_eq!(fs::read_to_string(&cfg.nfqws2_conf).unwrap(), "X=1\n");
        let inv = inventory(&cfg).unwrap();
        assert_eq!(inv.directories, vec!["blobs/demo"]);
        assert_eq!(
            inv.files
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            vec!["blobs/demo/sample.bin", "nfqws2.conf"]
        );
        assert!(!inv.files[0].editable && inv.files[1].protected);
        for path in [
            "blobs/../../etc/shadow",
            "blobs/.hidden",
            "scripts/nested/a.sh",
            "configs/custom.conf",
            "lua/dir//item",
        ] {
            assert!(locate(&cfg, path).is_err());
        }
        bin.delete().unwrap();
        assert_eq!(bin.open().unwrap_err().kind(), io::ErrorKind::NotFound);
    }
    #[cfg(unix)]
    #[test]
    fn directory_links_never_escape_configured_asset_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let cfg = Config {
            system_blobs_dir: dir.path().display().to_string(),
            ..Config::default()
        };
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let loc = locate(&cfg, "blobs/link/x.bin").unwrap();
        assert!(loc.save(&cfg, source(b"x"), false).is_err());
        assert!(!outside.path().join("x.bin").exists());
    }
}
