use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    RootCertStore,
};
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
};

const MAX_BUNDLE: u64 = 8 << 20;

fn read(
    paths: impl IntoIterator<Item = PathBuf>,
    dirs: &[&Path],
    explicit_dirs: bool,
) -> io::Result<RootCertStore> {
    let mut anchors = HashSet::new();
    let mut append = |path: PathBuf| {
        if !fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() <= MAX_BUNDLE) {
            return;
        }
        if let Ok(certs) = CertificateDer::pem_file_iter(path) {
            let mut store = RootCertStore::empty();
            store.add_parsable_certificates(certs.filter_map(Result::ok));
            anchors.extend(store.roots);
        }
    };
    for path in paths {
        append(path);
    }
    for dir in dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for path in entries.flatten().map(|entry| entry.path()) {
                if explicit_dirs
                    || path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|ext| {
                            ["crt", "pem", "cer"]
                                .iter()
                                .any(|s| ext.eq_ignore_ascii_case(s))
                        })
                {
                    append(path);
                }
            }
        }
    }
    if anchors.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "не найдены доверенные корневые сертификаты для TLS",
        ));
    }
    let mut store = RootCertStore::empty();
    store.roots.extend(anchors);
    Ok(store)
}

fn load_from(
    file: Option<std::ffi::OsString>,
    dirs: Option<std::ffi::OsString>,
) -> io::Result<RootCertStore> {
    let file = file.filter(|name| !name.is_empty());
    let dirs = dirs.filter(|names| !names.is_empty());
    if file.is_some() || dirs.is_some() {
        let paths: Vec<_> = dirs
            .as_ref()
            .map(|list| {
                std::env::split_paths(list)
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let dirs: Vec<_> = paths.iter().map(PathBuf::as_path).collect();
        return read(file.into_iter().map(PathBuf::from), &dirs, true);
    }
    let files = [
        "/opt/etc/ssl/cert.pem",
        "/opt/etc/ssl/ca-bundle.pem",
        "/opt/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ];
    read(
        files.map(PathBuf::from),
        &[Path::new("/opt/etc/ssl/certs"), Path::new("/etc/ssl/certs")],
        false,
    )
}

/// Explicit CA sources, including OpenSSL hash directories, take precedence
/// over the firmware bundles. An empty explicit store remains an error.
pub fn load() -> io::Result<RootCertStore> {
    load_from(
        std::env::var_os("SSL_CERT_FILE"),
        std::env::var_os("SSL_CERT_DIR"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};

    #[test]
    fn entware_certificate_directory_and_bundle_merge_without_duplicates() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("certs");
        fs::create_dir(&dir).unwrap();
        let pem = || {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .unwrap()
                .cert;
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                Base64::encode_string(cert.der())
            )
        };
        let bundle = root.path().join("ca-bundle.pem");
        let first = pem();
        fs::write(&bundle, &first).unwrap();
        fs::write(dir.join("duplicate.crt"), first).unwrap();
        fs::write(dir.join("local.CER"), pem()).unwrap();
        fs::write(dir.join("bad.pem"), b"broken").unwrap();
        fs::write(dir.join("skip.txt"), pem()).unwrap();
        let large = fs::File::create(dir.join("large.pem")).unwrap();
        large.set_len(MAX_BUNDLE + 1).unwrap();
        assert_eq!(read([bundle.clone()], &[&dir], false).unwrap().len(), 2);
        assert!(read([dir.join("bad.pem")], &[], false).is_err());
        let extra = root.path().join("private-roots");
        fs::create_dir(&extra).unwrap();
        fs::write(extra.join("12ab3456.0"), pem()).unwrap();
        let list = std::env::join_paths([&dir, &extra]).unwrap();
        assert_eq!(
            load_from(Some(bundle.into_os_string()), Some(list))
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            load_from(None, Some(extra.into_os_string())).unwrap().len(),
            1
        );
        assert!(load_from(None, Some(root.path().join("absent").into_os_string())).is_err());
    }
}
