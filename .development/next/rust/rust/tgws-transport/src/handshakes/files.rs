use super::{io, File, Path, COUNT};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid private handshake lock path",
    )
}
fn store(runtime: &Path) -> io::Result<&Path> {
    let parent = runtime.parent().ok_or_else(invalid)?;
    (runtime.file_name().is_some_and(|s| s == "runtime")
        && parent.file_name().is_some_and(|s| s == ".store"))
    .then_some(parent)
    .ok_or_else(invalid)
}
#[cfg(unix)]
pub(super) fn open(runtime: &Path, create: bool) -> io::Result<[File; COUNT]> {
    use rustix::fs::{mkdirat, open, openat, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let meta: File = open(store(runtime)?, flags, Mode::empty())?.into();
    let uid = rustix::process::geteuid().as_raw();
    let directory = |dir: &File| -> io::Result<()> {
        let m = dir.metadata()?;
        if m.uid() != uid || m.mode() & 0o022 != 0 {
            return Err(invalid());
        };
        Ok(())
    };
    directory(&meta)?;
    if create {
        match mkdirat(&meta, "runtime", Mode::from_bits_truncate(0o700)) {
            Err(e) if e != rustix::io::Errno::EXIST => return Err(e.into()),
            _ => (),
        }
    }
    let dir: File = openat(&meta, "runtime", flags, Mode::empty())?.into();
    directory(&dir)?;
    let mut out = Vec::with_capacity(COUNT);
    for n in 0..COUNT {
        let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        let flags = if create {
            flags | OFlags::CREATE
        } else {
            flags
        };
        let file: File = openat(
            &dir,
            format!("tgws-handshake-{n}.lock"),
            flags,
            Mode::from_bits_truncate(0o600),
        )?
        .into();
        let m = file.metadata()?;
        if !m.is_file() || m.nlink() != 1 || m.uid() != uid || m.mode() & 0o077 != 0 || m.len() != 0
        {
            return Err(invalid());
        }
        out.push(file);
    }
    out.try_into().map_err(|_| invalid())
}
#[cfg(windows)]
pub(super) fn open(runtime: &Path, create: bool) -> io::Result<[File; COUNT]> {
    use std::{
        fs::OpenOptions,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
    };
    const OPEN_REPARSE_POINT: u32 = 0x00200000;
    const BACKUP_SEMANTICS: u32 = 0x02000000;
    const REPARSE_POINT: u32 = 0x0400;
    let directory = |path: &Path| -> io::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(OPEN_REPARSE_POINT | BACKUP_SEMANTICS)
            .open(path)?;
        let m = f.metadata()?;
        if !m.is_dir() || m.file_attributes() & REPARSE_POINT != 0 {
            return Err(invalid());
        }
        Ok(f)
    };
    // No FILE_SHARE_DELETE: keep checked ancestors stable while opening children.
    let _store = directory(store(runtime)?)?;
    if create {
        match std::fs::create_dir(runtime) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => (),
        }
    }
    let _runtime = directory(runtime)?;
    let mut out = Vec::with_capacity(COUNT);
    for n in 0..COUNT {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .share_mode(3)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(runtime.join(format!("tgws-handshake-{n}.lock")))?;
        let m = file.metadata()?;
        if !m.is_file() || m.file_attributes() & REPARSE_POINT != 0 || m.len() != 0 {
            return Err(invalid());
        }
        out.push(file);
    }
    out.try_into().map_err(|_| invalid())
}
