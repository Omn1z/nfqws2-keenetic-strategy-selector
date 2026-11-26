//! Atomic JSON documents compatible with the panel's existing data directory.
mod protected;
pub use protected::ConfigFile;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}

struct BoundedWriter<W> {
    inner: W,
    remaining: u64,
}
impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime document exceeds read limit",
            ));
        }
        let count = self.inner.write(buf)?;
        self.remaining -= count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

pub fn new_id() -> io::Result<String> {
    let mut bytes = [0u8; 6];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A single portable filename, including legacy non-hex IDs and Unicode names.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && !matches!(s, "." | "..")
        && !s.eq_ignore_ascii_case(".store")
        && !s.contains(['/', '\\', ':', '\0'])
        && !s.ends_with(['.', ' '])
}

impl Store {
    /// Owner-local IPC and receipts are excluded from portable backups.
    pub fn private_runtime_dir(&self) -> PathBuf {
        self.root.join(".store/runtime")
    }
    /// Local receipts are excluded from portable backups and share the main writer lock.
    fn runtime_store(&self) -> Self {
        Self {
            root: self.root.join(".store"),
        }
    }
    pub fn read_runtime<T: DeserializeOwned>(&self, name: &str, limit: u64) -> io::Result<T> {
        if !valid_name(name) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.runtime_store()
            .read_limited(&format!("runtime/{name}"), limit)
    }
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let root = dir.into();
        fs::create_dir_all(&root)?;
        let metadata = root.join(".store");
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut b = builder;
            b.mode(0o700);
            b
        };
        match builder.create(&metadata) {
            Ok(()) => sync_dir(&root)?,
            Err(e)
                if e.kind() == io::ErrorKind::AlreadyExists
                    && metadata.symlink_metadata()?.is_dir() => {}
            Err(e) => return Err(e),
        }
        Ok(Self { root })
    }

    fn path(&self, rel: &str) -> io::Result<PathBuf> {
        if rel.is_empty()
            || rel.contains(['\\', ':', '\0'])
            || !Path::new(rel)
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
            || rel.split('/').any(|s| !valid_name(s))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid store path",
            ));
        }
        let mut path = self.root.clone();
        for part in rel.split('/') {
            path.push(part);
            match path.symlink_metadata() {
                Ok(meta) if meta.is_symlink() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "symlink in store path",
                    ));
                }
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(path)
    }

    pub fn read<T: DeserializeOwned>(&self, rel: &str) -> io::Result<T> {
        let f = File::open(self.path(rel)?)?;
        Ok(serde_json::from_reader(BufReader::new(f))?)
    }

    pub fn read_limited<T: DeserializeOwned>(&self, rel: &str, limit: u64) -> io::Result<T> {
        let path = self.path(rel)?;
        let meta = path.symlink_metadata()?;
        if !meta.is_file() || meta.len() > limit {
            return Err(io::Error::other("invalid document size or type"));
        }
        let mut reader = File::open(path)?.take(limit.saturating_add(1));
        let value = serde_json::from_reader(BufReader::new(&mut reader))?;
        if reader.limit() == 0 {
            return Err(io::Error::other("document exceeds byte limit"));
        }
        Ok(value)
    }

    pub fn files(&self, rel: &str) -> io::Result<Vec<String>> {
        let dir = match self.path(rel)?.read_dir() {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut files = Vec::new();
        for item in dir {
            let item = item?;
            if item.file_type()?.is_file() {
                if let Ok(name) = item.file_name().into_string() {
                    files.push(name);
                }
            }
        }
        files.sort_unstable();
        Ok(files)
    }

    /// Keep the same OS lock as the Go backup/restore code for read-modify-write operations.
    pub fn transaction<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let lock = self.lock_file()?;
        let start = Instant::now();
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock)
                    if start.elapsed() < Duration::from_secs(15) =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => return Err(e.into()),
            }
        }
        f(&Transaction { store: self })
    }

    /// For a callback already holding an independent service lock. Returning
    /// WouldBlock lets that service retry without reversing the lock order.
    pub fn try_transaction<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let lock = self.lock_file()?;
        lock.try_lock().map_err(io::Error::from)?;
        f(&Transaction { store: self })
    }

    fn lock_file(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(self.root.join(".store/lock"))
    }
}

pub struct Transaction<'a> {
    store: &'a Store,
}

impl Transaction<'_> {
    pub fn delete_runtime(&self, name: &str) -> io::Result<()> {
        if !valid_name(name) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Transaction {
            store: &self.store.runtime_store(),
        }
        .delete(&format!("runtime/{name}"))
    }

    pub fn save_runtime<T: Serialize>(&self, name: &str, value: &T) -> io::Result<()> {
        if !valid_name(name) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Transaction {
            store: &self.store.runtime_store(),
        }
        .save(&format!("runtime/{name}"), value)
    }
    /// Serialize a compact private journal and verify its reader's limit before
    /// replacing the last recoverable version.
    pub fn save_runtime_bounded<T: Serialize>(
        &self,
        name: &str,
        value: &T,
        limit: u64,
    ) -> io::Result<()> {
        if !valid_name(name) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Transaction {
            store: &self.store.runtime_store(),
        }
        .save_bounded(&format!("runtime/{name}"), value, limit)
    }
    pub fn save<T: Serialize>(&self, rel: &str, value: &T) -> io::Result<()> {
        self.save_inner(rel, value, None)
    }
    pub fn save_bounded<T: Serialize>(&self, rel: &str, value: &T, limit: u64) -> io::Result<()> {
        self.save_inner(rel, value, Some(limit))
    }
    fn save_inner<T: Serialize>(&self, rel: &str, value: &T, limit: Option<u64>) -> io::Result<()> {
        let target = self.store.path(rel)?;
        let dir = target.parent().expect("file underneath store root");
        fs::create_dir_all(dir)?;
        let mut file = NamedTempFile::new_in(dir)?;
        {
            let mut stream = BufWriter::new(file.as_file_mut());
            if let Some(remaining) = limit {
                serde_json::to_writer(
                    BoundedWriter {
                        inner: &mut stream,
                        remaining,
                    },
                    value,
                )?;
            } else {
                serde_json::to_writer_pretty(&mut stream, value)?;
            }
            stream.flush()?;
        }
        file.as_file().sync_all()?;
        file.persist(&target)?;
        sync_dir(dir)?;
        if dir != self.store.root {
            sync_dir(&self.store.root)?;
        }
        Ok(())
    }

    pub fn delete(&self, rel: &str) -> io::Result<()> {
        let target = self.store.path(rel)?;
        match fs::remove_file(&target) {
            Ok(()) => sync_dir(target.parent().expect("file underneath store root")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_runtime_update_keeps_last_readable_document() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .transaction(|tx| tx.save_runtime_bounded("test.json", &[1, 2], 5))
            .unwrap();
        assert!(store
            .transaction(|tx| tx.save_runtime_bounded("test.json", &[1, 22], 5))
            .is_err());
        assert_eq!(
            store.read_runtime::<Vec<i32>>("test.json", 5).unwrap(),
            [1, 2]
        );
        struct Generated;
        impl Serialize for Generated {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;
                let mut seq = s.serialize_seq(None)?;
                for _ in 0..8 {
                    seq.serialize_element(&22)?;
                }
                panic!("writer kept enumerating after exhausting the byte limit")
            }
        }
        let error = store
            .transaction(|tx| tx.save_runtime_bounded("test.json", &Generated, 5))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            store.read_runtime::<Vec<i32>>("test.json", 5).unwrap(),
            [1, 2]
        );
    }
    #[test]
    fn local_runtime_receipts_share_a_transaction_and_never_escape_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let db = Store::open(directory.path()).unwrap();
        db.transaction(|tx| {
            tx.save_runtime("receipt.json", &vec![1, 2])?;
            assert!(tx.save_runtime("../lock", &1).is_err());
            tx.save("public.json", &true)
        })
        .unwrap();
        assert!(directory
            .path()
            .join(".store/runtime/receipt.json")
            .is_file());
        assert_eq!(
            db.read_runtime::<Vec<u8>>("receipt.json", 64).unwrap(),
            [1, 2]
        );
        assert!(db.read_runtime::<Vec<u8>>("receipt.json", 1).is_err());
        assert!(db.read_runtime::<bool>("../../public.json", 10).is_err());
        assert!(db.read::<bool>("public.json").unwrap());
    }
    #[cfg(unix)]
    #[test]
    fn existing_directory_link_cannot_redirect_a_document() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("lists")).unwrap();
        assert!(store
            .transaction(|tx| tx.save("lists/test.json", &1))
            .is_err());
        assert!(!outside.path().join("test.json").exists());
    }
    #[test]
    fn independent_handles_serialize_edits_and_reject_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    store
                        .transaction(|tx| {
                            let n = match store.read::<usize>("lists/state.json") {
                                Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
                                value => value?,
                            };
                            tx.save("lists/state.json", &(n + 1))
                        })
                        .unwrap();
                });
            }
        });
        assert_eq!(store.read::<usize>("lists/state.json").unwrap(), 8);
        for path in [
            "../elsewhere",
            "/outside",
            "lists/../x",
            ".store/lock",
            "C:\\x",
        ] {
            assert_eq!(
                store.transaction(|tx| tx.delete(path)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
