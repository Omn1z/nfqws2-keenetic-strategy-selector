use super::{invalid, Category};
use std::{io, path::Path};

#[cfg(all(feature = "embedded-geo", not(feature = "compact")))]
mod reader {
    use super::*;
    use nfqws2_geo::{scan, Entry, Kind, Query, Scan};
    use std::fs::File;

    pub fn available() -> bool {
        true
    }

    fn open(path: &Path, kind: &str) -> io::Result<(File, u64, Kind)> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let kind = match kind {
            "geosite" => Kind::Site,
            "geoip" => Kind::Ip,
            _ => Kind::Text,
        };
        Ok((file, len, kind))
    }

    pub fn categories(path: &Path, kind: &str) -> io::Result<Vec<Category>> {
        let (file, len, kind) = open(path, kind)?;
        match scan(file, len, kind, Query::List, |_| Ok(()))? {
            Scan::Categories(map) => Ok(map
                .into_iter()
                .map(|(name, count)| Category { name, count })
                .collect()),
            Scan::Extracted(_) => unreachable!(),
        }
    }

    pub fn extract(path: &Path, kind: &str, category: &str, limit: u64) -> io::Result<Vec<String>> {
        let query = Query::Extract {
            category: category.to_owned(),
            limit,
        };
        read_category(path, kind, query, usize::MAX)?.ok_or_else(|| invalid("category not found"))
    }
    pub fn bounded_extract(
        path: &Path,
        kind: &str,
        category: &str,
        limit: u64,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<String>>> {
        let query = Query::ExtractChecked {
            category: category.to_owned(),
            limit,
        };
        read_category(path, kind, query, max_bytes)
    }
    fn read_category(
        path: &Path,
        kind: &str,
        query: Query,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<String>>> {
        let (file, len, kind) = open(path, kind)?;
        let mut values = Vec::new();
        let mut bytes = 0usize;
        match scan(file, len, kind, query, |entry| {
            let value = match entry {
                Entry::Text(value) => value.to_owned(),
                Entry::Network(ip, prefix) => format!("{ip}/{prefix}"),
            };
            bytes += value.len();
            if bytes > max_bytes {
                return Err(invalid("снимок Geo превышает допустимый размер"));
            }
            values.push(value);
            Ok(())
        })? {
            Scan::Extracted(true) => Ok(Some(values)),
            Scan::Extracted(false) => Ok(None),
            Scan::Categories(_) => unreachable!(),
        }
    }
}

#[cfg(any(not(feature = "embedded-geo"), feature = "compact"))]
mod reader {
    use super::*;
    use serde::de::{DeserializeOwned, Error, SeqAccess, Visitor};
    use serde::Deserializer;
    use std::{
        fmt, fs,
        io::{BufReader, Read},
        path::PathBuf,
        process::{ChildStdout, Command, Stdio},
    };

    fn helper() -> PathBuf {
        crate::assets::module_dir()
            .join("geo")
            .join(format!("nfqws2-geo{}", std::env::consts::EXE_SUFFIX))
    }
    pub fn available() -> bool {
        let Ok(meta) = fs::metadata(helper()) else {
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                return false;
            }
        }
        meta.is_file()
    }

    fn run<T: DeserializeOwned>(
        action: &str,
        kind: &str,
        path: &Path,
        extra: &[&str],
    ) -> io::Result<T> {
        run_limited(action, kind, path, extra, u64::MAX, |r| {
            serde_json::from_reader(r)
        })?
        .ok_or_else(|| invalid("category not found"))
    }
    fn run_limited<T>(
        action: &str,
        kind: &str,
        path: &Path,
        extra: &[&str],
        limit: u64,
        parse: impl FnOnce(&mut io::Take<BufReader<ChildStdout>>) -> serde_json::Result<T>,
    ) -> io::Result<Option<T>> {
        let mut cmd = Command::new(helper())
            .args([action, kind])
            .arg(path)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!("не удалось запустить модуль GeoSite/GeoIP: {err}"),
                )
            })?;
        let stdout = cmd.stdout.take().expect("piped stdout");
        let mut bounded = BufReader::new(stdout).take(limit.saturating_add(1));
        let parsed = parse(&mut bounded);
        let oversized = bounded.limit() == 0;
        if oversized || parsed.as_ref().is_err_and(|e| !e.is_eof()) {
            let _ = cmd.kill();
        }
        drop(bounded);
        if oversized {
            let _ = cmd.wait();
            return Err(invalid("снимок Geo превышает допустимый размер"));
        }
        match cmd.wait()?.code() {
            Some(0) => Ok(Some(parsed?)),
            Some(3) => Ok(None),
            Some(2) if action == "extract-checked" => {
                Err(invalid("для экспорта обновите модуль GeoSite/GeoIP"))
            }
            _ => Err(invalid("модуль GeoSite/GeoIP не смог прочитать файл")),
        }
    }
    pub fn categories(path: &Path, kind: &str) -> io::Result<Vec<Category>> {
        run("list", kind, path, &[])
    }
    pub fn extract(path: &Path, kind: &str, category: &str, limit: u64) -> io::Result<Vec<String>> {
        run("extract", kind, path, &[category, &limit.to_string()])
    }
    struct Entries {
        limit: u64,
        bytes: usize,
    }
    impl<'de> Visitor<'de> for Entries {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array of Geo entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
            let mut remaining = self.bytes;
            let mut values = Vec::new();
            while let Some(value) = entries.next_element::<String>()? {
                if self.limit != 0 && values.len() as u64 >= self.limit {
                    return Err(A::Error::custom("Geo category exceeds entry limit"));
                }
                remaining = remaining
                    .checked_sub(value.len())
                    .ok_or_else(|| A::Error::custom("снимок Geo превышает допустимый размер"))?;
                values.push(value);
            }
            Ok(values)
        }
    }
    pub fn bounded_extract(
        path: &Path,
        kind: &str,
        category: &str,
        limit: u64,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<String>>> {
        // A byte can expand to six in a JSON string. Each nonempty worker entry
        // adds two quotes and at most one comma; an empty array is "[]\n".
        let entries = if limit == 0 {
            max_bytes as u64
        } else {
            limit.min(max_bytes as u64)
        };
        let wire_bytes = (max_bytes as u64)
            .saturating_mul(6)
            .saturating_add(entries.saturating_mul(3))
            .saturating_add(3);
        run_limited(
            "extract-checked",
            kind,
            path,
            &[category, &limit.to_string()],
            wire_bytes,
            |source| {
                let mut de = serde_json::Deserializer::from_reader(source);
                let values = de.deserialize_seq(Entries {
                    limit,
                    bytes: max_bytes,
                })?;
                de.end()?;
                Ok(values)
            },
        )
    }
}

pub(super) use reader::{available, bounded_extract, categories, extract};
