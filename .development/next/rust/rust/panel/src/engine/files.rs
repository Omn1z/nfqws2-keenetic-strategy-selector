use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;

fn open(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if fs::symlink_metadata(path)?.is_symlink() {
        return Err(io::Error::other("символическая ссылка вместо файла"));
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("ожидался обычный файл"));
    }
    Ok(file)
}
pub(super) fn read(path: &Path, limit: u64) -> io::Result<Option<String>> {
    let file = match open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    if file.metadata()?.len() > limit {
        return Err(io::Error::other(format!(
            "Недопустимый файл или размер: {}",
            path.display()
        )));
    }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::Error::other("слишком большой файл"));
    }
    Ok(Some(text))
}

fn permissions(f: &fs::File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.permissions().mode() & 0o7777 != mode {
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(not(unix))]
    let _ = (f, mode);
    Ok(())
}

pub(super) fn write(path: &Path, data: &str, mode: u32, existing: Option<&str>) -> io::Result<()> {
    if existing == Some(data) {
        return permissions(&open(path)?, mode);
    }
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("нет каталога"))?;
    fs::create_dir_all(dir)?;
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(data.as_bytes())?;
    permissions(tmp.as_file(), mode)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

pub(super) fn backup(path: &Path, data: &str) -> io::Result<()> {
    if read(path, 2 << 20)?.is_some() {
        return Ok(());
    }
    let mut tmp = NamedTempFile::new_in(
        path.parent()
            .ok_or_else(|| io::Error::other("нет каталога"))?,
    )?;
    tmp.write_all(data.as_bytes())?;
    permissions(tmp.as_file(), 0o755)?;
    tmp.as_file().sync_all()?;
    match tmp.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.error),
    }
}
