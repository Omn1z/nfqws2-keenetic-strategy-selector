use nfqws2_config::Config;
use std::{
    fs::{File, Metadata},
    io,
};
#[cfg(not(target_os = "linux"))]
pub(super) fn apply(
    _: &File,
    _: Option<&Metadata>,
    _: &Config,
    _: &str,
    _: &str,
) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn apply(
    f: &File,
    prior: Option<&Metadata>,
    cfg: &Config,
    kind: &str,
    name: &str,
) -> io::Result<()> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    };
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let owner = if let Some(prior) = prior {
        Some((prior.uid(), prior.gid()))
    } else if kind == "list"
        && (matches!(
            stem.as_str(),
            "auto" | "autolist" | "hostlist-auto" | "hostlist_auto"
        ) || stem.starts_with("autolist-"))
    {
        owner_from_config(cfg)?
    } else {
        None
    };
    if let Some((uid, gid)) = owner {
        let now = f.metadata()?;
        // f remains open until the atomic replacement has completed.
        if (uid, gid) != (now.uid(), now.gid())
            && unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    f.set_permissions(std::fs::Permissions::from_mode(
        prior.map_or(0o644, |m| m.mode() & 0o777),
    ))
}
#[cfg(target_os = "linux")]
fn owner_from_config(cfg: &Config) -> io::Result<Option<(u32, u32)>> {
    use nfqws2_config::{literal_shell_config_value, Key, Resolver};
    use std::io::{BufRead, BufReader, Read};
    fn numeric(s: &str) -> Option<u32> {
        s.parse::<i32>().ok()?.try_into().ok()
    }
    let source = match File::open(&cfg.nfqws2_conf) {
        Ok(f) => super::files::bounded(f)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some(user) = literal_shell_config_value(&String::from_utf8_lossy(&source), "USER")?
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    if let Some((uid, gid)) = user.split_once(':') {
        return numeric(uid)
            .zip(numeric(gid))
            .map(Some)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "неверные UID/GID в USER"));
    }
    for key in [Key::AuthEtcDir, Key::EtcDir] {
        let Ok(f) = File::open(Resolver::current().path(key).join("passwd")) else {
            continue;
        };
        for line in BufReader::new(f.take(1 << 20)).lines() {
            let line = line?;
            let mut fields = line.split(':');
            if let (Some(name), Some(_), Some(uid), Some(gid)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            {
                if name == user || uid == user {
                    if let Some(pair) = numeric(uid).zip(numeric(gid)) {
                        return Ok(Some(pair));
                    }
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "пользователь NFQWS2 для нового autolist не найден",
    ))
}
