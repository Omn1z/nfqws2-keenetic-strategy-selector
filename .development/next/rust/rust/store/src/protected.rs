//! Two checksummed generations shared with the Go store. Read, validate, edit
//! and commit under the same cross-process lock, including recovery.
use super::{sync_dir, Store, Transaction};
use base64ct::{Base64, Encoding};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

#[derive(Deserialize, Serialize)]
struct Snapshot {
    version: u32,
    generation: u64,
    data: String,
    sha256: String,
}
struct Generation {
    slot: usize,
    generation: u64,
    data: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(out, "{byte:02x}").expect("string writer");
    }
    out
}
fn checksum(seq: u64, data: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(format!("1:{seq}:"));
    digest.update(data);
    hex(&digest.finalize())
}
fn read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    let mut f = NamedTempFile::new_in(dir)?;
    f.write_all(data)?;
    f.as_file().sync_all()?;
    f.persist(path)?;
    sync_dir(dir)
}
pub struct ConfigFile<T> {
    name: &'static str,
    defaults: fn() -> T,
    validate: fn(&T) -> io::Result<()>,
}
impl<T: Serialize + DeserializeOwned> ConfigFile<T> {
    pub const fn new(
        name: &'static str,
        defaults: fn() -> T,
        validate: fn(&T) -> io::Result<()>,
    ) -> Self {
        Self {
            name,
            defaults,
            validate,
        }
    }
    fn prefix(&self, store: &Store) -> PathBuf {
        store
            .root
            .join(".store")
            .join(hex(&Sha256::digest(self.name.as_bytes())))
    }
    fn decode(&self, data: &[u8]) -> io::Result<T> {
        let value = serde_json::from_slice(data).map_err(io::Error::other)?;
        (self.validate)(&value)?;
        Ok(value)
    }
    fn generations(&self, prefix: &Path) -> io::Result<(Vec<Generation>, bool)> {
        let mut copies = Vec::with_capacity(2);
        let mut found = false;
        for slot in 0..2 {
            let path = prefix.with_extension(format!("{slot}.json"));
            let raw = match read(&path) {
                Ok(None) => continue,
                Err(_) => {
                    found = true;
                    continue;
                }
                Ok(Some(raw)) => raw,
            };
            found = true;
            let Ok(s) = serde_json::from_slice::<Snapshot>(&raw) else {
                continue;
            };
            if s.version != 1 || s.generation == 0 {
                continue;
            }
            let Ok(bytes) = Base64::decode_vec(&s.data) else {
                continue;
            };
            if checksum(s.generation, &bytes) == s.sha256 && self.decode(&bytes).is_ok() {
                copies.push(Generation {
                    slot,
                    generation: s.generation,
                    data: bytes,
                });
            }
        }
        copies.sort_by_key(|c| c.generation);
        Ok((copies, found))
    }
    fn mirror(&self, prefix: &Path, previous: Option<&Generation>, data: &[u8]) -> io::Result<()> {
        if previous.is_some_and(|v| v.data == data) {
            return Ok(());
        }
        let slot = previous.map_or(0, |v| 1 - v.slot);
        let seq = previous
            .map_or(Some(1), |v| v.generation.checked_add(1))
            .ok_or_else(|| io::Error::other("configuration recovery generation overflow"))?;
        let snap = Snapshot {
            version: 1,
            generation: seq,
            data: Base64::encode_string(data),
            sha256: checksum(seq, data),
        };
        write_private(
            &prefix.with_extension(format!("{slot}.json")),
            &serde_json::to_vec(&snap)?,
        )
    }
    fn restore_or_seed(&self, tx: &Transaction<'_>) -> io::Result<(T, Vec<u8>, bool)> {
        let file = tx.store.path(self.name)?;
        let prefix = self.prefix(tx.store);
        let old = read(&file)?;
        let (copies, found) = self.generations(&prefix)?;
        if let Some(bytes) = old.as_ref() {
            if let Ok(value) = self.decode(bytes) {
                // A full disk must not make a valid primary unreadable.
                let _ = self.mirror(&prefix, copies.last(), bytes);
                return Ok((value, old.unwrap(), false));
            }
        }
        if let Some(copy) = copies.last() {
            if let Some(bytes) = old.as_ref() {
                write_private(&prefix.with_extension("corrupt"), bytes)?;
            }
            let value = self.decode(&copy.data)?;
            write_private(&file, &copy.data)?;
            return Ok((value, copy.data.clone(), true));
        }
        if old.is_some() || found {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "saved configuration and recovery copies are invalid",
            ));
        }
        let value = (self.defaults)();
        (self.validate)(&value)?;
        let bytes = serde_json::to_vec_pretty(&value)?;
        write_private(&file, &bytes)?;
        let _ = self.mirror(&prefix, None, &bytes);
        Ok((value, bytes, false))
    }
    pub fn read(&self, store: &Store) -> io::Result<T> {
        self.read_with_recovery(store).map(|(value, _)| value)
    }
    /// Read the configuration and report whether this call repaired the primary from a verified copy.
    pub fn read_with_recovery(&self, store: &Store) -> io::Result<(T, bool)> {
        store.transaction(|tx| {
            self.restore_or_seed(tx)
                .map(|(value, _, recovered)| (value, recovered))
        })
    }
    /// Read-only inspection for status and exports: no new primary or snapshot
    /// is created. A valid recovery copy remains available to the caller.
    pub fn inspect(&self, store: &Store) -> io::Result<(T, bool)> {
        let primary = read(&store.path(self.name)?)?;
        if let Some(bytes) = &primary {
            if let Ok(value) = self.decode(bytes) {
                return Ok((value, false));
            }
        }
        let (copies, found) = self.generations(&self.prefix(store))?;
        if let Some(copy) = copies.last() {
            return Ok((self.decode(&copy.data)?, true));
        }
        if found || primary.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "saved configuration and recovery copies are invalid",
            ));
        }
        let value = (self.defaults)();
        (self.validate)(&value)?;
        Ok((value, false))
    }
    pub fn edit<R>(
        &self,
        store: &Store,
        edit: impl FnOnce(&mut T) -> io::Result<R>,
    ) -> io::Result<R> {
        store.transaction(|tx| self.edit_locked(tx, edit))
    }
    pub fn edit_locked<R>(
        &self,
        tx: &Transaction<'_>,
        edit: impl FnOnce(&mut T) -> io::Result<R>,
    ) -> io::Result<R> {
        let store = tx.store;
        let (mut value, old, _) = self.restore_or_seed(tx)?;
        let result = edit(&mut value)?;
        (self.validate)(&value)?;
        let bytes = serde_json::to_vec_pretty(&value)?;
        if old != bytes {
            let prefix = self.prefix(store);
            let (copies, _) = self.generations(&prefix)?;
            self.mirror(&prefix, copies.last(), &old)?;
            write_private(&store.path(self.name)?, &bytes)?;
            let (copies, _) = self.generations(&prefix)?;
            let _ = self.mirror(&prefix, copies.last(), &bytes);
        }
        Ok(result)
    }
    pub fn reset(&self, store: &Store) -> io::Result<T> {
        self.replace(store, (self.defaults)())
    }
    /// Explicit recovery after the operator has validated the entire replacement.
    pub fn replace(&self, store: &Store, value: T) -> io::Result<T> {
        self.replace_checked(store, value, || Ok(()))
    }
    pub fn replace_checked(
        &self,
        store: &Store,
        value: T,
        check: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<T> {
        store.transaction(|_| {
            check()?;
            let file = store.path(self.name)?;
            let prefix = self.prefix(store);
            (self.validate)(&value)?;
            let new = serde_json::to_vec_pretty(&value)?;
            if let Some(old) = read(&file)? {
                if self.decode(&old).is_err() {
                    write_private(&prefix.with_extension("corrupt"), &old)?;
                } else {
                    let (copies, _) = self.generations(&prefix)?;
                    self.mirror(&prefix, copies.last(), &old)?;
                }
            }
            write_private(&file, &new)?;
            let (copies, _) = self.generations(&prefix)?;
            let _ = self.mirror(&prefix, copies.last(), &new);
            Ok(value)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CFG: ConfigFile<Vec<String>> = ConfigFile::new("dns.json", Vec::new, |_| Ok(()));
    #[test]
    fn validates_go_snapshots_roundtrips_and_retains_corrupt_primary() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let prefix = CFG.prefix(&store);
        // Independent fixture encoded like Go json.Marshal of []byte.
        let snap = include_str!("../tests/fixtures/go-snapshot.json");
        fs::write(prefix.with_extension("0.json"), snap).unwrap();
        fs::write(dir.path().join("dns.json"), b"bad primary").unwrap();
        assert_eq!(CFG.read(&store).unwrap(), ["legacy"]);
        assert_eq!(
            fs::read(prefix.with_extension("corrupt")).unwrap(),
            b"bad primary"
        );
        CFG.edit(&store, |v| {
            v.push("next".into());
            Ok(())
        })
        .unwrap();
        fs::remove_file(dir.path().join("dns.json")).unwrap();
        assert_eq!(CFG.read(&store).unwrap(), ["legacy", "next"]);
        fs::write(prefix.with_extension("1.json"), b"bad generation").unwrap();
        fs::write(dir.path().join("dns.json"), b"null").unwrap();
        assert_eq!(CFG.read(&store).unwrap(), ["legacy"]);
        fs::write(prefix.with_extension("0.json"), b"broken").unwrap();
        fs::write(dir.path().join("dns.json"), b"invalid").unwrap();
        assert!(CFG.edit(&store, |_| Ok(())).is_err());
        assert_eq!(fs::read(dir.path().join("dns.json")).unwrap(), b"invalid");
        assert!(CFG.reset(&store).unwrap().is_empty());
    }
}
