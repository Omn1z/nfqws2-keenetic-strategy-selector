//! Boot-scoped ownership of a configured, independent foreground engine.
use super::{identity, invalid, nested_transport, request, Runtime, Spec};
use crate::client::legacy::{matching_peer, process_start, reported_identity, start_time};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    version: u8,
    boot: String,
    pub id: String,
    iface: String,
    config: [u8; 32],
    keys: [u8; 32],
    pub pid: u32,
    started: u64,
    executable: (u64, u64),
    ifindex: u32,
    socket: String,
    pub nested: Option<nested_transport::Saved>,
}
fn changed() -> io::Error {
    invalid("личность сохранённого процесса AWG не подтверждена")
}
fn file_id(path: &Path) -> io::Result<(u64, u64)> {
    let m = fs::metadata(path)?;
    Ok((m.dev(), m.ino()))
}
fn current_boot(root: &Path) -> io::Result<String> {
    let raw = fs::read_to_string(root.join("proc/sys/kernel/random/boot_id"))?;
    let s = raw.trim();
    if s.len() != 36
        || !s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(changed());
    }
    Ok(s.to_owned())
}
fn ifindex(root: &Path, iface: &str) -> io::Result<u32> {
    fs::read_to_string(root.join("sys/class/net").join(iface).join("ifindex"))?
        .trim()
        .parse()
        .map_err(|_| changed())
}
fn path(socket: &Path) -> PathBuf {
    socket.with_extension("n2s-native.json")
}
pub(super) fn read(socket: &Path) -> io::Result<Option<Receipt>> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path(socket))
    {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => result?,
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > 8192
    {
        return Err(changed());
    }
    let record: Receipt = serde_json::from_reader(file.take(8193)).map_err(|_| changed())?;
    if record.version != 1
        || record.pid <= 1
        || record.pid > i32::MAX as u32
        || !nfqws2_store::valid_name(&record.id)
        || record.iface.len() >= libc::IFNAMSIZ
        || !record
            .iface
            .strip_prefix("awg")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        || socket.file_stem().and_then(|n| n.to_str()) != Some(record.iface.as_str())
    {
        return Err(changed());
    }
    Ok(Some(record))
}
impl Receipt {
    pub(super) fn removal_seal(&self) -> io::Result<super::NativeRemovalSeal> {
        Ok(super::NativeRemovalSeal {
            id: self.id.clone(),
            iface: self.iface.clone(),
            boot: self.boot.clone(),
            pid: self.pid,
            started: self.started,
            receipt_sha256: Sha256::digest(serde_json::to_vec(self)?).into(),
            nested: self
                .nested
                .as_ref()
                .map(|saved| saved.removal_scope(&self.iface))
                .transpose()?,
        })
    }

    pub(super) fn same_boot(&self, root: &Path) -> io::Result<bool> {
        Ok(current_boot(root)? == self.boot)
    }

    pub fn capture(
        runtime: &Runtime,
        spec: &Spec,
        pid: u32,
        socket: &Path,
        nested: Option<nested_transport::Saved>,
    ) -> io::Result<Self> {
        let bytes = request(socket, b"get=1\n\n", Duration::from_secs(1), Some(pid))?;
        let root = &runtime.root;
        let process = root.join("proc").join(pid.to_string());
        let r = Self {
            version: 1,
            boot: current_boot(root)?,
            id: spec.id.clone(),
            iface: spec.iface.clone(),
            config: Sha256::digest(spec.conf.as_bytes()).into(),
            keys: matching_peer(spec, &bytes).ok_or_else(changed)?,
            pid,
            started: start_time(&process)?,
            executable: file_id(&runtime.engine)?,
            ifindex: ifindex(root, &spec.iface)?,
            socket: identity(socket)?,
            nested,
        };
        r.verify(root, socket)?;
        Ok(r)
    }
    pub fn matches_spec(&self, spec: &Spec) -> bool {
        self.matches_config(spec, Sha256::digest(spec.conf.as_bytes()).into())
    }
    pub fn matches_config(&self, spec: &Spec, fingerprint: [u8; 32]) -> bool {
        self.id == spec.id && self.iface == spec.iface && fingerprint == self.config
    }
    pub fn vacant(&self, root: &Path, socket: &Path) -> io::Result<bool> {
        if !matches!(fs::symlink_metadata(root.join("sys/class/net").join(&self.iface)), Err(e) if e.kind()==io::ErrorKind::NotFound)
        {
            return Ok(false);
        }
        let socket_absent = match identity(socket) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Ok(id) if id == self.socket => false,
            Ok(_) => return Ok(false),
            Err(e) => return Err(e),
        };
        let proc_dir = root.join("proc").join(self.pid.to_string());
        Ok(current_boot(root)? != self.boot
            || match process_start(&proc_dir) {
                Ok((started, true)) if started == self.started && socket_absent => true,
                Ok((_, true)) => return Err(changed()),
                Ok((started, false)) => started != self.started,
                Err(e) if e.kind() == io::ErrorKind::NotFound => true,
                Err(e) => return Err(e),
            })
    }
    pub fn owner(&self, root: &Path, socket: &Path) -> io::Result<()> {
        let process = root.join("proc").join(self.pid.to_string());
        let args = fs::read(process.join("cmdline"))?;
        let mut args = args.split(|b| *b == 0);
        if current_boot(root)? != self.boot
            || start_time(&process)? != self.started
            || file_id(&process.join("exe"))? != self.executable
            || identity(socket)? != self.socket
            || ifindex(root, &self.iface)? != self.ifindex
            || args.next().is_none_or(|v| v.is_empty())
            || args.next() != Some(b"-f")
            || args.next() != Some(self.iface.as_bytes())
            || args.next() != Some(b"")
            || args.next().is_some()
        {
            return Err(changed());
        }
        Ok(())
    }
    pub fn verify(&self, root: &Path, socket: &Path) -> io::Result<()> {
        self.verify_peer(root, socket, None)
    }
    pub fn verify_for_spec(&self, root: &Path, socket: &Path, spec: &Spec) -> io::Result<()> {
        self.verify_peer(root, socket, Some(spec))
    }
    fn verify_peer(&self, root: &Path, socket: &Path, spec: Option<&Spec>) -> io::Result<()> {
        self.owner(root, socket)?;
        let bytes = request(socket, b"get=1\n\n", Duration::from_secs(1), Some(self.pid))?;
        if !spec.map_or_else(
            || self.matches_keys(&bytes),
            |spec| matching_peer(spec, &bytes) == Some(self.keys),
        ) {
            return Err(changed());
        }
        self.owner(root, socket)
    }
    pub fn matches_keys(&self, bytes: &[u8]) -> bool {
        reported_identity(bytes) == Some(self.keys)
    }
    pub fn remove_stale_socket(&self, socket: &Path) -> io::Result<()> {
        match identity(socket) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(id) if id == self.socket => {
                let probe =
                    socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
                if !matches!(probe.connect_timeout(&socket2::SockAddr::unix(socket)?,Duration::from_millis(100)),Err(e) if e.kind()==io::ErrorKind::ConnectionRefused)
                    || identity(socket)? != self.socket
                {
                    return Err(changed());
                }
                fs::remove_file(socket)
            }
            _ => Err(changed()),
        }
    }
    pub fn persist(&self, socket: &Path) -> io::Result<()> {
        let mut tmp = tempfile::NamedTempFile::new_in(socket.parent().ok_or_else(changed)?)?;
        serde_json::to_writer(&mut tmp, self).map_err(io::Error::other)?;
        tmp.flush()?;
        tmp.as_file().sync_all()?;
        tmp.persist_noclobber(path(socket)).map_err(|e| e.error)?;
        fs::File::open(socket.parent().ok_or_else(changed)?)?.sync_all()
    }
    pub fn remove(&self, socket: &Path) -> io::Result<()> {
        if read(socket)?.as_ref() != Some(self) {
            return Err(changed());
        }
        fs::remove_file(path(socket))
    }
}
