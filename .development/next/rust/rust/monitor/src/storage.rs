use crate::StorageUsage;
use std::path::Path;

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)] // statvfs field widths depend on the target ABI.
pub(crate) fn usage(data_dir: &Path, root: &Path) -> Option<StorageUsage> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    use std::{ffi::CString, mem::MaybeUninit};
    if data_dir.as_os_str().is_empty() {
        return None;
    }
    let path = CString::new(data_dir.as_os_str().as_bytes()).ok()?;
    let mut out = MaybeUninit::<libc::statvfs>::uninit();
    // statvfs initializes out on success; the NUL-terminated path lives through the call.
    if unsafe { libc::statvfs(path.as_ptr(), out.as_mut_ptr()) } != 0 {
        return None;
    }
    let stat = unsafe { out.assume_init() };
    let block = if stat.f_frsize > 0 {
        stat.f_frsize
    } else {
        stat.f_bsize
    } as u64;
    let blocks = stat.f_blocks as u64;
    let free = stat.f_bfree as u64;
    let available = stat.f_bavail as u64;
    let opt = root.join("opt");
    let same_device = |a: &Path, b: &Path| {
        a.metadata()
            .ok()
            .zip(b.metadata().ok())
            .is_some_and(|(x, y)| x.dev() == y.dev())
    };
    let label = if data_dir == opt.join("etc/nfqws2-strategy")
        && !root.join("etc/openwrt_release").exists()
        && !root.join("etc/rc.common").exists()
        && same_device(data_dir, &opt)
    {
        opt.as_path()
    } else {
        data_dir
    };
    from_counts(label, block, blocks, free, available)
}

#[cfg(any(target_os = "linux", test))]
fn from_counts(
    label: &Path,
    block: u64,
    blocks: u64,
    free: u64,
    available: u64,
) -> Option<StorageUsage> {
    if block == 0 || blocks == 0 || free > blocks {
        return None;
    }
    Some(StorageUsage {
        path: label.to_string_lossy().into_owned(),
        total_bytes: blocks.checked_mul(block)?,
        used_bytes: (blocks - free) * block,
        available_bytes: if available <= free {
            available * block
        } else {
            0
        },
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn usage(_: &Path, _: &Path) -> Option<StorageUsage> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn block_counts_distinguish_reserved_and_available_space() {
        let path = Path::new("/opt");
        let stat = from_counts(path, 4096, 100, 40, 35).unwrap();
        assert_eq!(stat.path, "/opt");
        assert_eq!(stat.total_bytes, 409600);
        assert_eq!(stat.available_bytes, 143360);
        assert_eq!(stat.used_bytes, 245760);
        assert_eq!(
            from_counts(path, 4096, 100, 40, u64::MAX)
                .unwrap()
                .available_bytes,
            0
        );
        for (block, count, free) in [(0, 2, 0), (8, 0, 0), (2, u64::MAX, 0), (8, 2, 3)] {
            assert!(from_counts(path, block, count, free, 0).is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn labels_entware_filesystem_and_keeps_openwrt_data_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let data = root.join("opt/etc/nfqws2-strategy");
        assert!(usage(&data, root).is_none());
        std::fs::create_dir_all(&data).unwrap();
        assert_eq!(
            usage(&data, root).unwrap().path,
            root.join("opt").to_string_lossy()
        );
        std::fs::create_dir(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/openwrt_release"), "").unwrap();
        assert_eq!(usage(&data, root).unwrap().path, data.to_string_lossy());
    }
}
