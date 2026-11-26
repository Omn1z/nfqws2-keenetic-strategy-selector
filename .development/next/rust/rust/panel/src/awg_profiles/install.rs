use crate::{
    http::Shared,
    release_assets::{arch, asset_tag, bad, check_elf, checksum, download, manifest},
};
use axum::{extract::State, Json};
use flate2::read::MultiGzDecoder;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Seek},
    path::Path,
};
use tempfile::NamedTempFile;

const BINARY_LIMIT: u64 = 64 << 20;
const ARCHIVE_LIMIT: u64 = BINARY_LIMIT + (1 << 20);

fn unpack(mut archive: File, digest: [u8; 32], dst: &Path) -> io::Result<()> {
    let mut hash = Sha256::new();
    let mut buffer = [0; 16_384];
    loop {
        let count = archive.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hash.finalize().into();
    if actual != digest {
        return Err(bad("не совпадает SHA256 архива движка"));
    }
    archive.rewind()?;
    let dir = dst.parent().ok_or_else(|| bad("нет каталога движка"))?;
    let mut staged = NamedTempFile::new_in(dir)?;
    let mut tar =
        tar::Archive::new(MultiGzDecoder::new(BufReader::new(archive)).take(ARCHIVE_LIMIT + 1));
    let mut found = false;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let name = entry.path()?;
        let name = name.strip_prefix(".").unwrap_or(&name);
        if name != Path::new("amneziawg-go") || !entry.header().entry_type().is_file() || found {
            return Err(bad("неожиданный файл в архиве движка"));
        }
        let size = entry.size();
        if !(64..=BINARY_LIMIT).contains(&size) || io::copy(&mut entry, &mut staged)? != size {
            return Err(bad("неверный размер движка"));
        }
        found = true;
    }
    let mut decoded = tar.into_inner();
    io::copy(&mut decoded, &mut io::sink())?;
    if !found || decoded.limit() == 0 {
        return Err(bad("архив движка пуст или слишком велик"));
    }
    staged.rewind()?;
    let mut ident = [0; 20];
    staged.read_exact(&mut ident)?;
    check_elf(&ident)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staged.as_file().sync_all()?;
    staged.persist(dst)?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

async fn install(s: &Shared) -> io::Result<String> {
    if !cfg!(target_os = "linux") {
        return Err(bad("установка движка доступна на Linux"));
    }
    let _lock = s
        .awg_installer
        .try_lock()
        .map_err(|_| bad("установка уже запущена"))?;
    let dst = s.awg_runtime.engine_path().to_path_buf();
    if s.awg_runtime.engine()["tun_ok"] != true {
        return Err(bad("недоступен /dev/net/tun, необходим драйвер TUN"));
    }
    let name = format!("awg-engine-linux-{}.tar.gz", arch()?);
    let repo = &s.config.repo;
    let tag = asset_tag(&manifest(repo).await?, &name)?;
    let base = format!("https://github.com/{repo}/releases/download/{tag}");
    let mut sums = Vec::new();
    download(&format!("{base}/SHA256SUMS"), &mut sums, 1 << 20, 15).await?;
    let digest = checksum(&sums, &name)?;
    let dir = dst.parent().ok_or_else(|| bad("нет каталога движка"))?;
    fs::create_dir_all(dir)?;
    let archive = tempfile::tempfile_in(dir)?;
    let mut out = tokio::fs::File::from_std(archive);
    download(&format!("{base}/{name}"), &mut out, BINARY_LIMIT, 180).await?;
    let mut archive = out.into_std().await;
    archive.rewind()?;
    tokio::task::spawn_blocking(move || unpack(archive, digest, &dst)).await??;
    Ok(format!("установлен движок AmneziaWG из выпуска {tag}"))
}

pub(super) async fn handle(State(s): State<Shared>) -> Json<Value> {
    Json(match install(&s).await {
        Ok(detail) => {
            s.logs.append("awg2", "info", &detail);
            json!({"ok":true,"detail":detail})
        }
        Err(e) => json!({"ok":false,"error":e.to_string()}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    fn blob() -> Vec<u8> {
        let mut data = vec![0; 128];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = if cfg!(target_pointer_width = "64") {
            2
        } else {
            1
        };
        data[5] = if cfg!(target_endian = "little") { 1 } else { 2 };
        let machine: u16 = match std::env::consts::ARCH {
            "x86_64" => 62,
            "aarch64" => 183,
            "arm" => 40,
            "mips" => 8,
            _ => 0,
        };
        data[18..20].copy_from_slice(&machine.to_ne_bytes());
        data
    }
    fn bundle(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            tar.append_data(&mut h, name, &data[..]).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }
    fn apply(bytes: &[u8], correct: bool, dst: &Path) -> io::Result<()> {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        file.rewind()?;
        let digest = if correct {
            Sha256::digest(bytes).into()
        } else {
            [0; 32]
        };
        unpack(file, digest, dst)
    }
    #[test]
    fn verified_archive_atomically_replaces_engine() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("amneziawg-go");
        fs::write(&dst, b"previous").unwrap();
        let name = "amneziawg-go";
        let good = bundle(&[(name, blob())]);
        let duplicate = bundle(&[(name, blob()), (name, blob())]);
        for bytes in [
            &good[..good.len() - 5],
            &duplicate,
            &bundle(&[("other", blob())]),
            &bundle(&[(name, vec![0; 128])]),
        ] {
            assert!(apply(bytes, true, &dst).is_err());
            assert_eq!(fs::read(&dst).unwrap(), b"previous");
        }
        assert!(apply(&good, false, &dst).is_err());
        apply(&good, true, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), blob());
    }
}
