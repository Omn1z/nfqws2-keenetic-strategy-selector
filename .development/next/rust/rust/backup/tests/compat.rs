use nfqws2_backup::{build, Upload};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

fn sealed(dir: &Path, roots: &[PathBuf]) -> Vec<u8> {
    let mut archive = build(roots, dir).unwrap();
    let mut bytes = archive.header.to_vec();
    archive.file.read_to_end(&mut bytes).unwrap();
    bytes
}
fn upload(dir: &Path, bytes: &[u8]) -> Upload {
    let mut upload = Upload::new(dir).unwrap();
    for part in bytes.chunks(37) {
        upload.append(part).unwrap();
    }
    upload
}
#[test]
fn restores_go_envelope_and_round_trips_without_following_unlisted_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("state");
    let other = tmp.path().join("other");
    fs::create_dir_all(root.join(".store")).unwrap();
    fs::create_dir_all(root.join("lists")).unwrap();
    fs::write(root.join(".store/lock"), b"skip").unwrap();
    fs::write(root.join("lists/new.json"), b"[]").unwrap();
    fs::write(&other, b"before").unwrap();
    let roots = [root.clone(), other.clone()];
    let bytes = sealed(tmp.path(), &roots);
    assert!(bytes.starts_with(b"SLBAK1"));
    fs::write(&other, b"after").unwrap();
    fs::write(root.join(".store/lock"), b"keep").unwrap();
    fs::write(root.join("lists/new.json"), b"broken").unwrap();
    assert_eq!(upload(tmp.path(), &bytes).restore(&roots[..1]).unwrap(), 1);
    assert_eq!(fs::read(root.join("lists/new.json")).unwrap(), b"[]");
    assert_eq!(fs::read(root.join(".store/lock")).unwrap(), b"keep");
    assert_eq!(fs::read(other).unwrap(), b"after");
    assert_eq!(
        upload(tmp.path(), include_bytes!("go-empty.bak"))
            .restore(&roots[..1])
            .unwrap(),
        0
    );
}
#[test]
fn invalid_checksum_tag_and_magic_preserve_existing_files() {
    use md5::{Digest, Md5};
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("x");
    fs::write(&f, "untouched").unwrap();
    let roots = [f.clone()];
    let bytes = sealed(tmp.path(), &roots);
    for index in [0, 6, 49, bytes.len() - 1] {
        let mut invalid = bytes.clone();
        invalid[index] ^= 1;
        if index > 22 {
            let checksum = Md5::digest(&invalid[22..]);
            invalid[6..22].copy_from_slice(&checksum);
        }
        assert!(upload(tmp.path(), &invalid).restore(&roots).is_err());
        assert_eq!(fs::read(&f).unwrap(), b"untouched");
    }
}
#[test]
fn checked_history_commits_only_after_all_regular_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    let history = root.join("history.json");
    let ordinary = root.join("zzz");
    fs::write(&history, b"history from backup").unwrap();
    fs::write(&ordinary, b"restored").unwrap();
    let roots = [root];
    let bytes = sealed(temp.path(), &roots);
    fs::write(&history, b"running history").unwrap();
    fs::remove_file(&ordinary).unwrap();
    fs::create_dir(&ordinary).unwrap();
    let accepts_saved_history = |path: &Path| {
        if fs::read(path)? == b"history from backup" {
            Ok(())
        } else {
            Err(std::io::Error::other("unexpected history"))
        }
    };
    assert!(upload(temp.path(), &bytes)
        .restore_checked_last(&roots, &history, accepts_saved_history)
        .is_err());
    assert_eq!(fs::read(&history).unwrap(), b"running history");
    fs::remove_dir(&ordinary).unwrap();
    assert_eq!(
        upload(temp.path(), &bytes)
            .restore_checked_last(&roots, &history, accepts_saved_history)
            .unwrap(),
        2
    );
    assert_eq!(fs::read(history).unwrap(), b"history from backup");
}
#[cfg(unix)]
#[test]
fn existing_symlink_destination_is_rejected_before_first_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("state");
    fs::create_dir(&root).unwrap();
    let a = root.join("a");
    let z = root.join("z");
    fs::write(&a, b"saved").unwrap();
    fs::write(&z, b"saved").unwrap();
    let roots = [root];
    let bytes = sealed(tmp.path(), &roots);
    fs::write(&a, b"current").unwrap();
    fs::remove_file(&z).unwrap();
    std::os::unix::fs::symlink(&a, &z).unwrap();
    assert!(upload(tmp.path(), &bytes).restore(&roots).is_err());
    assert_eq!(fs::read(&a).unwrap(), b"current");
}
