use flate2::read::MultiGzDecoder;
use nfqws2_config::Config;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

pub(super) const READ_LIMIT: u64 = 8 << 20;
const BYPASS: [&str; 2] = ["nfqueue_bypass_domains.list", "nfqueue_bypass_ips.list"];
fn invalid(s: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s.into())
}
fn directory(cfg: &Config, kind: &str) -> io::Result<PathBuf> {
    let base = Path::new(&cfg.nfqws2_conf)
        .parent()
        .ok_or_else(|| invalid("не задан каталог NFQWS2"))?;
    match kind {
        "conf" => Ok(base.into()),
        "list" | "bypass" => Ok(base.join("lists")),
        "lua" => Ok(PathBuf::from(&cfg.lua_dir)),
        _ => Err(invalid("неизвестный тип файла")),
    }
}
fn valid(kind: &str, name: &str) -> bool {
    let Some((stem, ext)) = name.split_once('.') else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        && match kind {
            "conf" => matches!(
                ext,
                "conf" | "conf-opkg" | "conf-old" | "apk-new" | "conf.apk-new"
            ),
            "list" => {
                matches!(ext, "list" | "list-opkg" | "list-old" | "list.apk-new")
                    && !BYPASS.contains(&name)
            }
            "bypass" => BYPASS.contains(&name),
            "lua" => ext == "lua",
            _ => false,
        }
}
pub(super) fn managed(n: &str) -> bool {
    n.starts_with("n2s_service_") && n.ends_with(".list")
}
fn protected(kind: &str, n: &str) -> bool {
    match kind {
        "conf" => n == "nfqws2.conf",
        "list" => {
            managed(n)
                || matches!(
                    n,
                    "user.list"
                        | "auto.list"
                        | "exclude.list"
                        | "ipset.list"
                        | "ipset_exclude.list"
                )
        }
        "bypass" => true,
        _ => false,
    }
}
fn priority(n: &str) -> i8 {
    match n {
        "nfqws2.conf" => -81,
        "user.list" => -64,
        "exclude.list" => -63,
        "auto.list" => -62,
        "ipset.list" => -61,
        "ipset_exclude.list" => -60,
        "nfqueue_bypass_domains.list" => -59,
        "nfqueue_bypass_ips.list" => -58,
        _ if n.ends_with(".conf") => -70,
        _ if n.ends_with(".list") => -50,
        _ if n.ends_with(".lua") => -30,
        _ => 10,
    }
}
#[derive(Serialize)]
pub(super) struct Info {
    pub name: String,
    kind: String,
    size: u64,
    gz: bool,
    protected: bool,
}
pub(super) fn list(cfg: &Config, kind: &str) -> io::Result<Vec<Info>> {
    let mut found = BTreeMap::new();
    for entry in directory(cfg, kind)?.read_dir()? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Ok(raw) = entry.file_name().into_string() else {
            continue;
        };
        let base = raw.strip_suffix(".gz").unwrap_or(&raw);
        let gz = base != raw;
        if valid(kind, base) && (!gz || !found.contains_key(base)) {
            found.insert(base.to_owned(), (entry.metadata()?.len(), gz));
        }
    }
    if kind == "bypass" {
        for name in BYPASS {
            found.entry(name.into()).or_insert((0, false));
        }
    }
    let mut out: Vec<_> = found
        .into_iter()
        .map(|(name, (size, gz))| Info {
            protected: protected(kind, &name),
            name,
            kind: kind.to_owned(),
            size,
            gz,
        })
        .collect();
    out.sort_unstable_by(|a, b| {
        priority(&a.name)
            .cmp(&priority(&b.name))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(out)
}
pub(super) fn regular(p: &Path) -> io::Result<Option<Metadata>> {
    match p.symlink_metadata() {
        Ok(m) if m.is_file() => Ok(Some(m)),
        Ok(_) => Err(invalid("ожидался обычный файл")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
pub(super) struct Entry<'a> {
    cfg: &'a Config,
    kind: &'a str,
    name: &'a str,
    directory: PathBuf,
    plain: PathBuf,
    gzip: PathBuf,
}
impl<'a> Entry<'a> {
    pub(super) fn new(cfg: &'a Config, kind: &'a str, input: &'a str) -> io::Result<Self> {
        let name = input.trim().rsplit('/').next().unwrap_or_default();
        let name = name.strip_suffix(".gz").unwrap_or(name);
        if !valid(kind, name) {
            return Err(invalid("недопустимое имя файла"));
        }
        let directory = directory(cfg, kind)?;
        if directory.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
            return Err(invalid("каталог является символической ссылкой"));
        }
        Ok(Self {
            cfg,
            kind,
            name,
            plain: directory.join(name),
            gzip: directory.join(format!("{name}.gz")),
            directory,
        })
    }
    fn source(&self) -> io::Result<Option<(File, bool)>> {
        for (p, gz) in [(&self.plain, false), (&self.gzip, true)] {
            if regular(p)?.is_some() {
                let mut options = File::options();
                options.read(true);
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                }
                let file = options.open(p)?;
                if !file.metadata()?.is_file() {
                    return Err(invalid("ожидался обычный файл"));
                }
                return Ok(Some((file, gz)));
            }
        }
        Ok(None)
    }
    pub(super) fn read(&self) -> io::Result<String> {
        let Some((f, gz)) = self.source()? else {
            return Ok(String::new());
        };
        let b = if gz {
            bounded(MultiGzDecoder::new(f))?
        } else {
            bounded(f)?
        };
        Ok(String::from_utf8_lossy(&b).into_owned())
    }
    pub(super) fn download(&self) -> io::Result<(Vec<u8>, String)> {
        let (f, gz) = self.source()?.ok_or_else(|| invalid("файл не найден"))?;
        Ok((
            bounded(f)?,
            if gz {
                format!("{}.gz", self.name)
            } else {
                self.name.into()
            },
        ))
    }
    pub(super) fn write(&self, content: &str, create: bool) -> io::Result<()> {
        if managed(self.name) {
            return Err(invalid("список управляется вкладкой «Сервисы»"));
        }
        let prior = regular(&self.plain)?;
        if create && (prior.is_some() || regular(&self.gzip)?.is_some()) {
            return Err(invalid("файл уже существует"));
        }
        if content.contains('\0') || content.len() as u64 > READ_LIMIT {
            return Err(invalid("ожидается текст UTF-8 до 8 МиБ"));
        }
        let content = normalize(content);
        let content = if self.kind == "conf" {
            nfqws2_config::normalize_wan_interfaces(&content)?
        } else {
            content.as_str().into()
        };
        if !create {
            fs::create_dir_all(&self.directory)?;
        }
        let mut temp = NamedTempFile::new_in(&self.directory)?;
        temp.write_all(content.as_bytes())?;
        super::owner::apply(
            temp.as_file(),
            prior.as_ref(),
            self.cfg,
            self.kind,
            self.name,
        )?;
        temp.as_file().sync_all()?;
        if create {
            temp.persist_noclobber(&self.plain)?;
        } else {
            temp.persist(&self.plain)?;
        }
        self.sync()
    }
    pub(super) fn delete(&self) -> io::Result<()> {
        if protected(self.kind, self.name) {
            return Err(invalid("файл защищён от удаления"));
        }
        let (plain, gz) = (
            regular(&self.plain)?.is_some(),
            regular(&self.gzip)?.is_some(),
        );
        if !plain && !gz {
            return Err(invalid("файл не найден"));
        }
        if gz {
            fs::remove_file(&self.gzip)?;
        }
        if plain {
            fs::remove_file(&self.plain)?;
        }
        self.sync()
    }
    fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
pub(super) fn bounded(r: impl Read) -> io::Result<Vec<u8>> {
    let mut b = Vec::new();
    r.take(READ_LIMIT + 1).read_to_end(&mut b)?;
    if b.len() as u64 > READ_LIMIT {
        return Err(invalid("файл больше 8 МиБ"));
    }
    Ok(b)
}
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 1);
    let mut newlines = 0;
    let mut last_cr = false;
    for c in s.strip_prefix('\u{feff}').unwrap_or(s).chars() {
        if c == '\n' && last_cr {
            last_cr = false;
            continue;
        }
        last_cr = c == '\r';
        if c == '\n' || last_cr {
            if newlines < 2 {
                out.push('\n');
                newlines += 1;
            }
        } else {
            newlines = 0;
            out.push(c);
        }
    }
    if !out.is_empty() && newlines == 0 {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod package_files {
    use super::valid;

    #[test]
    fn edited_config_and_list_can_coexist_with_distribution_updates() {
        for (kind, suffix) in [("conf", "conf"), ("list", "list")] {
            for end in ["", "-opkg", ".apk-new"] {
                assert!(valid(kind, &format!("custom.{suffix}{end}")));
            }
            assert!(!valid(kind, &format!("../custom.{suffix}.apk-new")));
            assert!(!valid(kind, &format!("custom.{suffix}.apk-new.sh")));
        }
    }
}
