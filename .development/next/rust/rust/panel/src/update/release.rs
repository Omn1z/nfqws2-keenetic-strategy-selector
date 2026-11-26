use super::*;
use crate::release_assets::*;
fn version(tag: &str) -> Option<(semver::Version, &str)> {
    let raw = tag.trim().strip_prefix('v').unwrap_or(tag.trim());
    if let Ok(mut v) = semver::Version::parse(raw) {
        // Project EA tags use ea-N. Compare the ordinal numerically, while
        // keeping the published tag unchanged for the download and checksum.
        if let Some(n) = v
            .pre
            .as_str()
            .strip_prefix("ea-")
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            v.pre = semver::Prerelease::new(&format!("ea.{n}")).ok()?;
        }
        return Some((v, ""));
    }
    let base = raw.trim_end_matches(|c: char| c.is_ascii_lowercase());
    if raw.contains(['+', '-']) {
        return None;
    }
    semver::Version::parse(base)
        .ok()
        .map(|v| (v, &raw[base.len()..]))
}
fn asset_name() -> io::Result<String> {
    Ok(format!("nfqws2-strategy-rust-linux-{}", arch()?))
}
pub(super) struct Release {
    tag: String,
    base: String,
    name: String,
    available: bool,
}
impl Release {
    pub fn view(&self, current: &str) -> Value {
        json!({"current":current,"latest":self.tag,"available":self.available,"asset":self.name,"url":self.base.replace("/releases/download/","/releases/tag/")})
    }
}
fn metadata(repo: &str, current: &str, bytes: &[u8]) -> io::Result<Release> {
    let repo = owner_repo(repo)?;
    let name = asset_name()?;
    let tag = asset_tag(bytes, &name)?;
    let (next, suffix) = version(&tag).ok_or_else(|| bad("некорректная версия выпуска"))?;
    let available = version(current)
        .is_none_or(|(old, rev)| next.cmp_precedence(&old).then(suffix.cmp(rev)).is_gt());
    let base = format!("https://github.com/{repo}/releases/download/{tag}");
    Ok(Release {
        tag,
        base,
        name,
        available,
    })
}
pub(super) async fn latest(repo: &str, current: &str) -> io::Result<Release> {
    let prereleases = version(current).is_some_and(|(v, _)| !v.pre.is_empty());
    if !prereleases {
        let stable = manifest(repo)
            .await
            .and_then(|m| metadata(repo, current, &m));
        if let Ok(release) = stable {
            return Ok(release);
        }
    }
    // GitHub "latest" omits EA releases, and the latest stable release can
    // contain only Go artifacts. Select the newest eligible native release.
    let url = format!(
        "https://api.github.com/repos/{}/releases?per_page=30",
        owner_repo(repo)?
    );
    let mut bytes = Vec::new();
    download(&url, &mut bytes, 4 << 20, 15).await?;
    select(repo, current, prereleases, &bytes)
}
fn select(repo: &str, current: &str, prereleases: bool, bytes: &[u8]) -> io::Result<Release> {
    let rows: Vec<Value> = serde_json::from_slice(bytes)?;
    let mut latest: Option<Release> = None;
    for row in rows {
        if row["draft"] == true || (!prereleases && row["prerelease"] == true) {
            continue;
        }
        let Ok(release) = metadata(repo, current, &serde_json::to_vec(&row)?) else {
            continue;
        };
        let (next, suffix) = version(&release.tag).unwrap();
        if !prereleases && !next.pre.is_empty() {
            continue;
        }
        if latest.as_ref().is_none_or(|r| {
            let (old, rev) = version(&r.tag).unwrap();
            next.cmp_precedence(&old).then(suffix.cmp(rev)).is_gt()
        }) {
            latest = Some(release);
        }
    }
    latest.ok_or_else(|| bad("Не найден выпуск Rust для архитектуры и канала этой панели"))
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::{install_cli, update, Binary};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ea_orders_numerically_and_skips_ineligible_builds() {
        let name = asset_name().unwrap();
        let release = |tag: &str, asset: &str, ea: bool, draft: bool| json!({"tag_name":tag,"assets":[{"name":"SHA256SUMS"},{"name":asset}],"draft":draft,"prerelease":ea});
        let rows = serde_json::to_vec(&[
            release("v9.0.0", "nfqws2-strategy-linux-arm64", false, false),
            release("v8.0.0", &name, false, true),
            release("v2.0.0-ea-2", &name, true, false),
            release("v2.0.0-ea-10", &name, true, false),
            release("v1.9.0", &name, false, false),
        ])
        .unwrap();
        let ea = select("repo/name", "2.0.0-ea-2", true, &rows).unwrap();
        assert_eq!(ea.tag, "v2.0.0-ea-10");
        assert!(ea.available);
        assert_eq!(
            select("repo/name", "1.8.0", false, &rows).unwrap().tag,
            "v1.9.0"
        );
    }
    #[test]
    fn separates_native_releases_and_requires_unique_hash_and_version() {
        let name = asset_name().unwrap();
        let meta = |tag: &str, n: &str| {
            serde_json::to_vec(&json!({"tag_name":tag,"assets":[{"name":"SHA256SUMS"},{"name":n}]}))
                .unwrap()
        };
        assert!(
            metadata("example/repo", "v1.3.1a", &meta("v1.3.1b", &name))
                .unwrap()
                .available
        );
        assert!(
            !metadata("example/repo", "v1.3.1b", &meta("v1.3.1a", &name))
                .unwrap()
                .available
        );
        assert!(metadata(
            "example/repo",
            "dev",
            &meta("v1.3.1", "nfqws2-strategy-linux-amd64")
        )
        .is_err());
        for repo in ["../repo", "local/repo?q=x", "user/repo/path"] {
            assert!(metadata(repo, "dev", &meta("v1.0.0", &name)).is_err());
        }
        let line = format!("{} *{name}\n", "ab".repeat(32));
        assert_eq!(checksum(line.as_bytes(), &name).unwrap(), [0xab; 32]);
        assert!(checksum(line.repeat(2).as_bytes(), &name).is_err());
    }
}
