use super::{blob_name, directory, files, invalid, regular, sync_dir, Blobs, MAX_ZIP};
use nfqws2_store::Transaction;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Seek, Write},
    path::Path,
};
use tempfile::TempPath;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

const MAX_ENTRY: u64 = 8 << 20;
const MAX_UNPACKED: u64 = 128 << 20;
const MAX_ENTRIES: usize = 4096;

impl Blobs<'_> {
    pub fn export(
        &self,
        names: &[String],
        strategy: Option<&[u8]>,
        mut sink: impl Write,
    ) -> io::Result<()> {
        let listed;
        let selected = if names.is_empty() && strategy.is_none() {
            directory(&self.active, false)?;
            listed = files(&self.active)?;
            &listed[..]
        } else {
            names
        };
        let mut archive = ZipWriter::new_stream(&mut sink);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let mut written = BTreeSet::new();
        for reference in selected {
            let name = if strategy.is_some() {
                blob_name(reference.rsplit(['/', '\\']).next().unwrap_or_default())?
            } else {
                blob_name(reference)?
            };
            if strategy.is_some() && name == "strategy.json" {
                return Err(invalid("strategy.json is reserved for strategy metadata"));
            }
            if written.contains(name) {
                continue;
            }
            // Explicit library paths retain their source when a custom and a
            // system blob share a filename. Never read outside these libraries.
            let path = Path::new(reference);
            let source = match path.parent() {
                Some(dir) if strategy.is_some() && (dir == self.system || dir == self.active) => {
                    directory(dir, false)?;
                    regular(path).and_then(|_| fs::File::open(path))
                }
                _ => self.open(name),
            };
            let mut file = match source {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            archive.start_file(name, options)?;
            io::copy(&mut file, &mut archive)?;
            written.insert(name);
        }
        if let Some(metadata) = strategy {
            archive.start_file("strategy.json", options)?;
            archive.write_all(metadata)?;
        }
        archive.finish()?;
        sink.flush()
    }

    pub fn import(&self, src: impl Read + Seek) -> io::Result<usize> {
        let (files, count) = self.unpack(src)?;
        self.commit_archive(files, |_| Ok(count))
    }

    pub fn import_strategy<T>(
        &self,
        src: impl Read + Seek,
        save: impl FnOnce(&Transaction<'_>, &[u8]) -> io::Result<T>,
    ) -> io::Result<T> {
        let (mut files, _) = self.unpack(src)?;
        let meta = files
            .remove("strategy.json")
            .ok_or_else(|| invalid("strategy.json missing or empty"))?;
        let data = fs::read(meta)?;
        self.commit_archive(files, |tx| save(tx, &data))
    }

    fn unpack(&self, mut src: impl Read + Seek) -> io::Result<(BTreeMap<String, TempPath>, usize)> {
        if src.seek(io::SeekFrom::End(0))? > MAX_ZIP {
            return Err(invalid("ZIP exceeds 32 MiB"));
        }
        src.rewind()?;
        let mut archive = ZipArchive::new(src).map_err(|e| invalid(format!("invalid ZIP: {e}")))?;
        if archive.len() > MAX_ENTRIES {
            return Err(invalid("too many ZIP entries"));
        }
        let mut staged = BTreeMap::new();
        let mut total = 0;
        let mut count = 0;
        for i in 0..archive.len() {
            let entry = archive.by_index(i).map_err(|e| invalid(e.to_string()))?;
            if entry.is_dir() {
                continue;
            }
            let path = entry
                .enclosed_name()
                .ok_or_else(|| invalid("invalid ZIP path"))?;
            if entry.is_symlink() || entry.size() > MAX_ENTRY {
                return Err(invalid("invalid or oversized blob entry"));
            }
            let name =
                blob_name(path.file_name().and_then(|n| n.to_str()).unwrap_or(""))?.to_owned();
            let max_bytes = MAX_ENTRY.min(MAX_UNPACKED - total);
            if entry.size() > max_bytes {
                return Err(invalid("expanded blob archive exceeds 128 MiB"));
            }
            let size = entry.size();
            let mut file = self.temporary()?;
            let copied = io::copy(&mut entry.take(max_bytes + 1), file.as_file_mut()).map_err(
                |e| match e.kind() {
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                        invalid(e.to_string())
                    }
                    _ => e,
                },
            )?;
            if copied != size || copied > max_bytes {
                return Err(invalid("invalid ZIP entry size"));
            }
            total += copied;
            file.as_file().sync_all()?;
            staged.insert(name, file.into_temp_path());
            count += 1;
        }
        Ok((staged, count))
    }

    fn commit_archive<T>(
        &self,
        files: BTreeMap<String, TempPath>,
        finish: impl FnOnce(&Transaction<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let backup = tempfile::tempdir_in(&self.stage)?;
        self.lock.transaction(|tx| {
            directory(&self.active, true)?;
            for name in files.keys() {
                let path = self.active.join(name);
                match path.symlink_metadata() {
                    Ok(meta) if meta.is_file() => {
                        let old = backup.path().join(name);
                        if fs::hard_link(&path, &old).is_err() {
                            fs::copy(path, old)?;
                        }
                    }
                    Ok(_) => return Err(invalid("expected a regular blob file")),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e),
                }
            }
            let mut installed = Vec::new();
            let result = (|| {
                for (name, file) in files {
                    file.persist(self.active.join(&name))?;
                    installed.push(name);
                }
                sync_dir(&self.active)?;
                finish(tx)
            })();
            if result.is_err() {
                for previous in installed.iter().rev() {
                    let old = backup.path().join(previous);
                    let new = self.active.join(previous);
                    if old.exists() {
                        fs::rename(old, new)?;
                    } else {
                        fs::remove_file(new)?;
                    }
                }
                sync_dir(&self.active)?;
            }
            result
        })
    }
}
