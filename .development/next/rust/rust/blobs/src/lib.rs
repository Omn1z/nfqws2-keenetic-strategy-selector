mod archive;
#[cfg(test)]
mod tests;
mod tls;
pub use nfqws2_tls_record::validate;
pub use tls::generate;

use nfqws2_store::{valid_name, Store};
use serde::Serialize;
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

pub const MAX_UPLOAD: u64 = 4 << 20;
pub const MAX_ZIP: u64 = 32 << 20;
const TRASH_CAP: usize = 50;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn blob_name(name: &str) -> io::Result<&str> {
    if !valid_name(name) {
        return Err(invalid("invalid blob name"));
    }
    Ok(name)
}

fn files(dir: &Path) -> io::Result<Vec<String>> {
    let entries = match dir.read_dir() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        found => found?,
    };
    let mut names = Vec::new();
    for item in entries {
        let item = item?;
        if item.file_type()?.is_file() {
            if let Ok(name) = item.file_name().into_string() {
                names.push(name);
            }
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn regular(file: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(file)?.is_file() {
        return Err(invalid("expected a regular blob file"));
    }
    Ok(())
}

fn directory(dir: &Path, create: bool) -> io::Result<()> {
    if create {
        fs::create_dir_all(dir)?;
    }
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(invalid("invalid blob directory")),
        Err(e) if !create && e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
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

#[derive(Serialize)]
pub struct Catalog {
    pub system: Vec<String>,
    pub custom: Vec<String>,
    pub trash: Vec<String>,
}

pub struct Blobs<'a> {
    lock: &'a Store,
    active: PathBuf,
    trash: PathBuf,
    system: &'a Path,
    stage: PathBuf,
}

impl<'a> Blobs<'a> {
    pub fn new(lock: &'a Store, data: &Path, system: &'a Path) -> Self {
        Self {
            lock,
            active: data.join("blobs"),
            trash: data.join("blobs_trash"),
            system,
            stage: data.join(".store"),
        }
    }
    pub fn temporary(&self) -> io::Result<NamedTempFile> {
        NamedTempFile::new_in(&self.stage)
    }
    pub fn list(&self) -> io::Result<Catalog> {
        directory(&self.active, false)?;
        Ok(Catalog {
            system: files(self.system)?,
            custom: files(&self.active)?,
            trash: self.trashed()?,
        })
    }
    fn trashed(&self) -> io::Result<Vec<String>> {
        directory(&self.trash, false)?;
        let mut dates = Vec::new();
        for name in files(&self.trash)? {
            match self.trash.join(&name).symlink_metadata() {
                Ok(meta) => dates.push((std::cmp::Reverse(meta.modified()?), name)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            }
        }
        dates.sort_unstable();
        Ok(dates.into_iter().map(|(_, name)| name).collect())
    }
    pub fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let name = blob_name(name)?;
        directory(&self.active, false)?;
        let custom = self.active.join(name);
        match regular(&custom) {
            Ok(()) => Ok(custom),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let path = self.system.join(name);
                regular(&path)?;
                Ok(path)
            }
            Err(e) => Err(e),
        }
    }
    fn open(&self, name: &str) -> io::Result<File> {
        File::open(self.resolve(name)?)
    }
    pub fn commit(&self, name: &str, file: NamedTempFile) -> io::Result<PathBuf> {
        let dest = self.active.join(blob_name(name)?);
        file.as_file().sync_all()?;
        self.lock.transaction(|_| {
            directory(&self.active, true)?;
            file.persist(&dest)?;
            sync_dir(&self.active)
        })?;
        Ok(dest)
    }
    pub fn validate(&self, name: &str) -> io::Result<(bool, String)> {
        let f = self.open(name)?;
        let size = f.metadata()?.len();
        // A TLS record's payload length is an unsigned 16-bit field.
        let mut bytes = Vec::new();
        f.take(if size > 65_540 { 9 } else { size })
            .read_to_end(&mut bytes)?;
        Ok(nfqws2_tls_record::validate_record(&bytes, size))
    }
    pub fn remove(&self, name: &str) -> io::Result<()> {
        let name = blob_name(name)?;
        self.lock.transaction(|_| {
            directory(&self.active, false)?;
            let old = self.active.join(name);
            regular(&old)?;
            directory(&self.trash, true)?;
            fs::rename(old, self.trash.join(name))?;
            for old in self.trashed()?.into_iter().skip(TRASH_CAP) {
                fs::remove_file(self.trash.join(old))?;
            }
            sync_dir(&self.active)?;
            sync_dir(&self.trash)
        })
    }
    pub fn restore(&self, name: &str) -> io::Result<()> {
        let name = blob_name(name)?;
        self.lock.transaction(|_| {
            directory(&self.active, true)?;
            directory(&self.trash, false)?;
            let old = self.trash.join(name);
            regular(&old)?;
            let dest = self.active.join(name);
            match dest.symlink_metadata() {
                Ok(_) => {
                    return Err(invalid(format!(
                        "активный блоб «{name}» уже существует — удалите или переименуйте его"
                    )))
                }
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => (),
            }
            fs::rename(old, dest)?;
            sync_dir(&self.trash)?;
            sync_dir(&self.active)
        })
    }
    pub fn purge(&self, name: &str) -> io::Result<()> {
        let name = blob_name(name)?;
        self.lock.transaction(|tx| {
            directory(&self.trash, false)?;
            tx.delete(&format!("blobs_trash/{name}"))
        })
    }
    pub fn empty(&self) -> io::Result<()> {
        self.lock.transaction(|tx| {
            for name in self.trashed()? {
                tx.delete(&format!("blobs_trash/{name}"))?;
            }
            Ok(())
        })
    }
}
