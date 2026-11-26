use super::{
    encode, execute, explorer, location, read, revision, Config, Document, Input, Operation,
    SERVICE,
};
use std::{
    borrow::Cow,
    io::{self, Read},
};

pub(crate) fn normalize_wan(cfg: &Config) -> io::Result<()> {
    let main = location(cfg, "nfqws2.conf")?;
    let mut snapshot = main.relative.as_os_str().to_owned();
    snapshot.push(".run");
    let runtime = explorer::Location {
        root: main.root.clone(),
        relative: snapshot.into(),
        kind: "conf",
    };
    let mut edits = Vec::new();
    for path in [main, runtime] {
        let file = match path.open() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            other => other?,
        };
        let mut old = String::new();
        file.take(explorer::FILE_LIMIT + 1)
            .read_to_string(&mut old)?;
        if old.len() as u64 > explorer::FILE_LIMIT {
            return Err(explorer::invalid("слишком большой файл настроек WAN"));
        }
        if let Cow::Owned(next) = nfqws2_config::normalize_wan_interfaces(&old)? {
            edits.push((path, old, next));
        }
    }
    for (index, (file, _, next)) in edits.iter().enumerate() {
        if let Err(e) = file.replace(cfg, next.as_bytes(), true, Some(0o644)) {
            for (path, old, _) in &edits[..index] {
                path.replace(cfg, old.as_bytes(), true, Some(0o644))
                    .map_err(|r| {
                        io::Error::other(format!(
                            "{e}. Не удалось восстановить параметры WAN ({r})"
                        ))
                    })?;
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Caller holds the store transaction shared with the file editor.
pub(crate) fn prepare_for_engine(cfg: &Config) -> io::Result<Option<String>> {
    normalize_wan(cfg)?;
    let Some(raw) = read(cfg, SERVICE)? else {
        return Ok(None);
    };
    let doc: Document = serde_json::from_slice(&raw)?;
    if doc.services.is_empty() && !doc.restart_required {
        return Ok(None);
    }
    let current = execute(cfg, Operation::Read)?;
    if current["restart_required"] != true {
        return Ok(None);
    }
    let saved = execute(
        cfg,
        Operation::Save(Input {
            revision: current["revision"].as_str().unwrap_or_default().to_owned(),
            services: doc.services,
        }),
    )?;
    Ok(saved["revision"].as_str().map(str::to_owned))
}

pub(crate) fn mark_engine_applied(cfg: &Config, expected: Option<&str>) -> io::Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let Some(saved) = read(cfg, SERVICE)? else {
        return Ok(());
    };
    let conf = read(cfg, "nfqws2.conf")?.unwrap_or_default();
    if revision(&saved, &conf) == expected {
        let mut doc: Document = serde_json::from_slice(&saved)?;
        if doc.restart_required {
            doc.restart_required = false;
            location(cfg, SERVICE)?.replace(cfg, encode(&doc)?.as_slice(), true, Some(0o600))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfqws2_config::Resolver;
    use std::{fs, path::Path};

    fn config(root: &Path) -> Config {
        let mut cfg = Config::from_resolver(&Resolver::new_at(root));
        cfg.data_dir = root.to_string_lossy().into_owned();
        cfg.nfqws2_conf = root.join("nfqws2.conf").to_string_lossy().into_owned();
        cfg
    }
    #[test]
    fn pending_and_live_wan_lists_remain_distinct_and_invalid_runtime_is_atomic() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        let runtime = format!("{}.run", cfg.nfqws2_conf);
        let main = "ISP_INTERFACE=\"wan0,wan1\"\nTCP_PORTS=80,443\n";
        fs::write(&cfg.nfqws2_conf, main).unwrap();
        fs::write(&runtime, "ISP_INTERFACE=\"bad/wan,good\"\n").unwrap();
        assert!(prepare_for_engine(&cfg).is_err());
        assert_eq!(fs::read_to_string(&cfg.nfqws2_conf).unwrap(), main);
        fs::write(&runtime, "ISP_INTERFACE=\"wan1,wan2\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o640)).unwrap();
        }
        assert!(prepare_for_engine(&cfg).unwrap().is_none());
        assert_eq!(
            fs::read_to_string(&cfg.nfqws2_conf).unwrap(),
            "ISP_INTERFACE=\"wan0 wan1\"\nTCP_PORTS=80,443\n"
        );
        assert_eq!(
            fs::read_to_string(&runtime).unwrap(),
            "ISP_INTERFACE=\"wan1 wan2\"\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    }
    #[test]
    fn only_the_document_revision_of_the_running_service_is_marked_applied() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        let named = root.path().join(SERVICE);
        let raw = br#"{"services":[],"restart_required":true}"#;
        fs::write(&named, raw).unwrap();
        fs::write(&cfg.nfqws2_conf, b"new config").unwrap();
        mark_engine_applied(&cfg, Some(&revision(raw, b"old config"))).unwrap();
        assert_eq!(fs::read(&named).unwrap(), raw);
        mark_engine_applied(&cfg, Some(&revision(raw, b"new config"))).unwrap();
        assert!(
            !serde_json::from_slice::<Document>(&fs::read(&named).unwrap())
                .unwrap()
                .restart_required
        );
    }
}
