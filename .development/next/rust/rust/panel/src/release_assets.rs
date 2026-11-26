use serde::Deserialize;
use std::io;
use std::process::Stdio;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
};

pub(crate) fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
pub(crate) fn arch() -> io::Result<&'static str> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "mips" if cfg!(target_endian = "little") => "mipsle",
        "mips" => "mips",
        _ => return Err(bad("архитектура выпуска Rust не поддерживается")),
    };
    Ok(arch)
}
pub(crate) fn owner_repo(repo: &str) -> io::Result<&str> {
    let component = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && !matches!(s, "." | "..")
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    if repo
        .split_once('/')
        .is_some_and(|(o, r)| component(o) && component(r))
    {
        Ok(repo)
    } else {
        Err(bad("не задан корректный репозиторий панели"))
    }
}
pub(crate) async fn download(
    url: &str,
    out: &mut (impl AsyncWrite + Unpin),
    limit: u64,
    seconds: u64,
) -> io::Result<()> {
    let mut child = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--location",
            "--max-redirs",
            "5",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            &seconds.to_string(),
            "--connect-timeout",
            "8",
            "--user-agent",
            "nfqws2-strategy",
            "--",
            url,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdout.take().expect("piped stdout").take(limit + 1);
    let bytes = tokio::io::copy(&mut input, out).await?;
    if bytes > limit {
        let _ = child.kill().await;
        return Err(bad("превышен размер загрузки"));
    }
    if !child.wait().await?.success() || bytes == 0 {
        return Err(bad("не удалось скачать выпуск по HTTPS"));
    }
    out.flush().await
}
#[derive(Deserialize)]
struct Metadata {
    tag_name: String,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
}

pub(crate) fn asset_tag(bytes: &[u8], name: &str) -> io::Result<String> {
    let data: Metadata = serde_json::from_slice(bytes)?;
    let tag = data.tag_name;
    if tag.is_empty()
        || matches!(tag.as_str(), "." | "..")
        || tag.len() > 64
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(bad("некорректный тег выпуска"));
    }
    for required in [name, "SHA256SUMS"] {
        if data.assets.iter().filter(|a| a.name == required).count() != 1 {
            return Err(bad(
                "в выпуске отсутствует пакет для этой архитектуры или файл SHA256SUMS",
            ));
        }
    }
    Ok(tag)
}
pub(crate) async fn manifest(repo: &str) -> io::Result<Vec<u8>> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        owner_repo(repo)?
    );
    let mut bytes = Vec::new();
    download(&url, &mut bytes, 1 << 20, 12).await?;
    Ok(bytes)
}
pub(crate) fn checksum(manifest: &[u8], name: &str) -> io::Result<[u8; 32]> {
    let text = std::str::from_utf8(manifest).map_err(|_| bad("некорректный SHA256SUMS"))?;
    let mut found = None;
    for line in text.lines() {
        let (digest, path) = line
            .split_once(' ')
            .ok_or_else(|| bad("некорректная запись SHA256SUMS"))?;
        let path = path
            .strip_prefix([' ', '*'])
            .ok_or_else(|| bad("некорректный путь SHA256SUMS"))?;
        if path != name {
            continue;
        }
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) || found.is_some() {
            return Err(bad("некорректная или повторяющаяся сумма образа"));
        }
        let mut sum = [0; 32];
        for (i, byte) in sum.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16)
                .map_err(|_| bad("некорректный SHA256"))?;
        }
        found = Some(sum);
    }
    found.ok_or_else(|| bad("отсутствует SHA256 файла"))
}

pub(crate) fn check_elf(ident: &[u8; 20]) -> io::Result<()> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        "arm" => 40,
        "mips" => 8,
        _ => return Err(bad("неизвестная архитектура")),
    };
    let machine = if cfg!(target_endian = "little") {
        u16::from_le_bytes([ident[18], ident[19]])
    } else {
        u16::from_be_bytes([ident[18], ident[19]])
    };
    if &ident[..4] != b"\x7fELF"
        || ident[4]
            != if cfg!(target_pointer_width = "64") {
                2
            } else {
                1
            }
        || ident[5] != if cfg!(target_endian = "little") { 1 } else { 2 }
        || machine != arch
    {
        return Err(bad("неверная архитектура ELF"));
    }
    Ok(())
}
