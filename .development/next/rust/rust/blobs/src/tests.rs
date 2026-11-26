use super::*;
use std::io::{Cursor, Write};
use zip::{write::SimpleFileOptions, ZipWriter};

#[test]
fn generated_tls_has_valid_record_sni_and_alpn_without_network() {
    for minimum in [0, 771, 772] {
        let hello = generate(
            "  example.test. ",
            &["h2".into(), "http/1.1".into()],
            minimum,
        )
        .unwrap();
        assert_eq!(
            validate(&hello),
            (true, "валидный ClientHello, SNI example.test".into())
        );
        assert!(hello.windows(8).any(|part| part == b"http/1.1"));
        let mut bad = hello.clone();
        bad.pop();
        assert!(!validate(&bad).0);
        let mut bad = hello.clone();
        bad[5] = 2;
        assert!(!validate(&bad).0);
        let mut bad = hello;
        bad[8] ^= 1;
        assert!(!validate(&bad).0);
    }
    assert!(generate("127.0.0.1", &[], 0).is_err());
    assert!(generate("", &[], 0).is_err());
    assert!(generate("host.test", &[String::new()], 0).is_err());
}

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        zip.start_file(*name, SimpleFileOptions::default()).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
#[test]
fn archives_restore_originals_on_invalid_entries_and_strategy_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let db = Store::open(root).unwrap();
    let blobs = Blobs::new(&db, root, root);
    let first = archive(&[("nested/alpha.bin", b"prior")]);
    assert_eq!(blobs.import(Cursor::new(first)).unwrap(), 1);
    let invalid = archive(&[("alpha.bin", b"replacement"), ("../escape", b"never")]);
    assert!(blobs.import(Cursor::new(invalid)).is_err());
    let package = archive(&[
        ("alpha.bin", b"replacement"),
        ("new.bin", b"not published"),
        ("strategy.json", b"invalid"),
    ]);
    assert!(blobs
        .import_strategy(Cursor::new(package), |_, _| Err::<(), _>(super::invalid(
            "invalid strategy"
        )))
        .is_err());
    assert_eq!(fs::read(root.join("blobs/alpha.bin")).unwrap(), b"prior");
    assert!(!root.join("blobs/new.bin").exists());
}

#[test]
fn portable_export_reads_explicit_library_and_restricts_other_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let db = Store::open(root).unwrap();
    let system = root.join("system");
    let service = Blobs::new(&db, root, &system);
    fs::create_dir(&system).unwrap();
    fs::create_dir(root.join("blobs")).unwrap();
    let reference = system.join("same.bin");
    fs::write(&reference, b"system").unwrap();
    fs::write(root.join("blobs/same.bin"), b"custom").unwrap();
    let private = root.join("private.txt");
    fs::write(&private, b"outside").unwrap();
    let selected = [reference, private].map(|p| p.to_string_lossy().into_owned());
    let mut output = Vec::new();
    service.export(&selected, Some(b"{}"), &mut output).unwrap();
    let mut zip = zip::ZipArchive::new(Cursor::new(output)).unwrap();
    assert_eq!(zip.len(), 2);
    assert!(zip.by_name("private.txt").is_err());
    let mut data = String::new();
    zip.by_name("same.bin")
        .unwrap()
        .read_to_string(&mut data)
        .unwrap();
    assert_eq!(data, "system");
}

#[test]
fn trash_is_bounded_and_restore_preserves_active_data() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let db = Store::open(root).unwrap();
    let service = Blobs::new(&db, root, root);
    fs::create_dir(root.join("blobs")).unwrap();
    for idx in 0..=TRASH_CAP {
        let name = format!("blob{idx:02}.bin");
        fs::write(root.join("blobs").join(&name), b"x").unwrap();
        service.remove(&name).unwrap();
    }
    let names = service.list().unwrap().trash;
    assert_eq!(names.len(), TRASH_CAP);
    let name = &names[0];
    let dest = root.join("blobs").join(name);
    fs::write(&dest, b"active").unwrap();
    assert!(service.restore(name).is_err());
    assert_eq!(fs::read(&dest).unwrap(), b"active");
    fs::remove_file(&dest).unwrap();
    service.restore(name).unwrap();
    assert_eq!(fs::read(dest).unwrap(), b"x");
    service.empty().unwrap();
    assert!(service.list().unwrap().trash.is_empty());
}
