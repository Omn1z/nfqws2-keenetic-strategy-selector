//! Compatible SLBAK1 archives. Encrypt/decrypt the private scratch file in
//! place so an archive never requires a second archive-sized heap allocation.
use md5::{Digest, Md5};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, Cursor, Read, Seek, Write},
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

pub const LIMIT: u64 = 256 * 1024 * 1024;
const MAGIC: &[u8; 6] = b"SLBAK1";
const HEADER: usize = 6 + 16 + 16 + 12;
fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
fn key() -> io::Result<aead::LessSafeKey> {
    let hash = digest::digest(&digest::SHA256, b"nfqws2-strategy/backup/v1/seal-key");
    aead::UnboundKey::new(&aead::AES_256_GCM, hash.as_ref())
        .map(aead::LessSafeKey::new)
        .map_err(|_| bad("backup encryption unavailable"))
}
fn hidden(p: &Path) -> bool {
    p.components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case(".store"))
}
fn archive_name(p: &Path) -> io::Result<String> {
    let p = std::path::absolute(p)?;
    let s = p
        .to_str()
        .ok_or_else(|| bad("archive path must be UTF-8"))?
        .replace('\\', "/");
    Ok(s.trim_start_matches('/').to_owned())
}
pub struct Archive {
    pub header: [u8; HEADER],
    pub file: File,
    pub files: usize,
}
struct Builder {
    zip: ZipWriter<File>,
    seen: HashSet<String>,
    remaining: u64,
}
impl Builder {
    fn add(&mut self, path: &Path) -> io::Result<()> {
        if hidden(path) {
            return Ok(());
        }
        let st = match path.symlink_metadata() {
            Ok(st) => st,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if st.is_dir() {
            let mut names = fs::read_dir(path)?
                .map(|e| e.map(|d| d.path()))
                .collect::<io::Result<Vec<_>>>()?;
            names.sort_unstable();
            for child in names {
                self.add(&child)?;
            }
            return Ok(());
        }
        // Do not read through symlinks into unrelated private router directories.
        if !st.is_file() {
            return Ok(());
        }
        let name = archive_name(path)?;
        if !self.seen.insert(name.clone()) {
            return Ok(());
        }
        if self.seen.len() > 65535 || st.len() > self.remaining {
            return Err(bad("backup exceeds archive limits"));
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            st.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0o600;
        let opt = SimpleFileOptions::default()
            .unix_permissions(mode)
            .compression_method(CompressionMethod::Deflated);
        self.zip.start_file(name, opt)?;
        let n = io::copy(
            &mut File::open(path)?.take(self.remaining + 1),
            &mut self.zip,
        )?;
        self.remaining = self
            .remaining
            .checked_sub(n)
            .ok_or_else(|| bad("backup exceeds archive limits"))?;
        Ok(())
    }
}
/// scratch must be a fresh private file exclusively owned by this call.
pub fn build(roots: &[PathBuf], scratch_dir: &Path) -> io::Result<Archive> {
    let mut builder = Builder {
        zip: ZipWriter::new(tempfile::tempfile_in(scratch_dir)?),
        seen: HashSet::new(),
        remaining: LIMIT,
    };
    for root in roots {
        builder.add(root)?;
    }
    let mut file = builder.zip.finish()?;
    let len = file.metadata()?.len();
    if len + HEADER as u64 + 16 > LIMIT {
        return Err(bad("sealed archive exceeds size limit"));
    }
    let mut header = [0; HEADER];
    header[..6].copy_from_slice(MAGIC);
    SystemRandom::new()
        .fill(&mut header[22..])
        .map_err(|_| io::Error::other("OS random unavailable"))?;
    let nonce = header[38..].try_into().expect("12-byte nonce");
    // tempfile_in created an exclusive scratch file. No external writer
    // can truncate it while we hold this mapping.
    let mut map = unsafe { memmap2::MmapMut::map_mut(&file)? };
    let tag = key()?
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(MAGIC),
            &mut map,
        )
        .map_err(|_| bad("backup encryption failed"))?;
    let mut md = Md5::new();
    md.update(&header[22..]);
    md.update(&map);
    md.update(tag.as_ref());
    header[6..22].copy_from_slice(&md.finalize());
    drop(map);
    file.seek(io::SeekFrom::End(0))?;
    file.write_all(tag.as_ref())?;
    file.rewind()?;
    Ok(Archive {
        header,
        file,
        files: builder.seen.len(),
    })
}
fn checked_path(name: &str, roots: &[PathBuf]) -> io::Result<Option<(PathBuf, PathBuf)>> {
    #[cfg(windows)]
    {
        let tail =
            if name.as_bytes().get(1) == Some(&b':') && name.as_bytes()[0].is_ascii_alphabetic() {
                &name[2..]
            } else {
                name
            };
        if tail.contains(':') {
            return Err(bad("invalid archive member path"));
        }
    }
    if name.contains(['\0', '\\']) || name.split('/').any(|c| c == ".." || c == ".") {
        return Err(bad("invalid archive member path"));
    }
    let input = Path::new(name);
    let full = if input.is_absolute() {
        input.to_owned()
    } else {
        Path::new("/").join(input)
    };
    let full = std::path::absolute(full)?;
    if hidden(&full) {
        return Ok(None);
    }
    for root in roots {
        let root = std::path::absolute(root)?;
        if full == root || full.starts_with(&root) {
            return Ok(Some((root, full)));
        }
    }
    Ok(None)
}
fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return File::open(path)?.sync_all();
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
fn directories(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| bad("invalid restore directory"))?;
    directories(parent)?;
    fs::create_dir(path)?;
    sync_dir(parent)
}
fn checked_parent(root: &Path, dst: &Path) -> io::Result<PathBuf> {
    if root.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
        return Err(bad("restore root is a symlink"));
    }
    let mut part = root.to_owned();
    for component in dst
        .strip_prefix(root)
        .map_err(|_| bad("outside restore root"))?
        .components()
    {
        let Component::Normal(name) = component else {
            return Err(bad("invalid restore path"));
        };
        part.push(name);
        if part.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
            return Err(bad("symlink in restore path"));
        }
    }
    if dst.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
        return Err(bad("restore destination is a symlink"));
    }
    dst.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| bad("missing restore parent"))
}
pub struct Upload {
    file: File,
    len: u64,
}
impl Upload {
    pub fn new(scratch_dir: &Path) -> io::Result<Self> {
        Ok(Self {
            file: tempfile::tempfile_in(scratch_dir)?,
            len: 0,
        })
    }
    pub fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let len = self
            .len
            .checked_add(data.len() as u64)
            .filter(|v| *v <= LIMIT)
            .ok_or_else(|| bad("invalid backup size"))?;
        self.file.write_all(data)?;
        self.len = len;
        Ok(())
    }
    pub fn restore(self, roots: &[PathBuf]) -> io::Result<usize> {
        restore(roots, self.file, self.len, None)
    }
    /// Stage and validate an observational member before restoring files, and
    /// publish it only after all other commits succeed.
    pub fn restore_checked_last(
        self,
        roots: &[PathBuf],
        path: &Path,
        check: fn(&Path) -> io::Result<()>,
    ) -> io::Result<usize> {
        restore(
            roots,
            self.file,
            self.len,
            Some(FinalMember { path, check }),
        )
    }
}
struct FinalMember<'a> {
    path: &'a Path,
    check: fn(&Path) -> io::Result<()>,
}
fn restore(
    roots: &[PathBuf],
    scratch: File,
    len: u64,
    last: Option<FinalMember<'_>>,
) -> io::Result<usize> {
    if len < (HEADER + 16) as u64 {
        return Err(bad("invalid backup size"));
    }
    // This anonymous file has no shared writer and is closed after the mapping.
    let mut map = unsafe { memmap2::MmapMut::map_mut(&scratch)? };
    if &map[..6] != MAGIC {
        return Err(bad("unknown backup format"));
    }
    if Md5::digest(&map[22..])[..] != map[6..22] {
        return Err(bad("corrupt backup checksum"));
    }
    let nonce = map[38..HEADER].try_into().expect("12-byte nonce");
    let plain = key()?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(MAGIC),
            &mut map[HEADER..],
        )
        .map_err(|_| bad("invalid backup authentication tag"))?;
    let mut archive = ZipArchive::new(Cursor::new(plain))?;
    if archive.len() > 65535 {
        return Err(bad("too many archive members"));
    }
    let mut seen = HashSet::new();
    let mut remaining = LIMIT;
    let mut staged = Vec::new();
    let mut final_stage = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let Some((root, dst)) = checked_path(entry.name()?.as_ref(), roots)? else {
            continue;
        };
        if !seen.insert(dst.clone()) || entry.size() > remaining {
            return Err(bad("duplicate or oversized archive member"));
        }
        let mode = entry.unix_mode().unwrap_or(0o600);
        let ty = mode & 0o170000;
        if !matches!(ty, 0 | 0o100000 | 0o120000) {
            return Err(bad("unsupported archive entry type"));
        }
        let parent = checked_parent(&root, &dst)?;
        directories(&parent)?;
        let mut tmp = NamedTempFile::new_in(&parent)?;
        let n = io::copy(&mut (&mut entry).take(remaining + 1), tmp.as_file_mut())?;
        remaining = remaining
            .checked_sub(n)
            .ok_or_else(|| bad("extracted archive exceeds size limit"))?;
        if n != entry.size() {
            return Err(bad("incomplete archive entry"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = mode & 0o777;
            if permissions == 0
                || ty == 0o120000
                || dst.file_name().is_some_and(|v| v == "awg.json")
            {
                permissions = 0o600;
            }
            if dst
                .metadata()
                .is_ok_and(|s| s.permissions().mode() & 0o077 == 0)
            {
                permissions &= !0o077;
            }
            tmp.as_file()
                .set_permissions(fs::Permissions::from_mode(permissions))?;
        }
        tmp.as_file().sync_all()?;
        if let Some(last) = last.as_ref().filter(|m| dst == m.path) {
            (last.check)(tmp.path())?;
            final_stage = Some((tmp, root, dst));
        } else {
            staged.push((tmp, root, dst));
        }
    }
    let mut committed = 0;
    for (tmp, root, dst) in staged.into_iter().chain(final_stage) {
        let result = (|| {
            let parent = checked_parent(&root, &dst)?;
            tmp.persist(dst)?;
            committed += 1;
            sync_dir(&parent)
        })();
        result
            .map_err(|e| io::Error::other(format!("restore committed {committed} files: {e}")))?;
    }
    Ok(committed)
}
