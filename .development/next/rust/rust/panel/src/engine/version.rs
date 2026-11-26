use super::*;
#[derive(Serialize, Default)]
pub(super) struct Info {
    package: String,
    package_status: &'static str,
    engine: String,
    latest: String,
    available: bool,
    url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}
fn parsed_version(raw: &str) -> io::Result<(semver::Version, u64)> {
    let raw = raw.trim();
    let mut version = raw.strip_prefix('v').unwrap_or(raw);
    let mut package_revision = 0;
    if let Some((base, revision)) = version.rsplit_once('-') {
        let revision = revision.strip_prefix('r').unwrap_or(revision);
        if !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit()) {
            package_revision = revision.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "некорректная ревизия пакета")
            })?;
            version = base;
        }
    }
    let core = version.split(['-', '+']).next().unwrap_or("");
    let fields = core.split('.').count();
    let normalized = if fields < 3 && core == version {
        format!("{version}{}", ".0".repeat(3 - fields))
    } else {
        version.into()
    };
    semver::Version::parse(&normalized)
        .map(|v| (v, package_revision))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "некорректная версия пакета"))
}
fn validate(raw: &str) -> io::Result<String> {
    parsed_version(raw).map(|_| raw.to_owned())
}
#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
}
fn upstream(repo: &str, runner: &dyn nfqws2_router_command::Runner) -> io::Result<Release> {
    let valid = |part: &str| {
        !part.is_empty()
            && !matches!(part, "." | "..")
            && part.len() <= 100
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    };
    if !repo
        .split_once('/')
        .is_some_and(|(owner, name)| valid(owner) && valid(name))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "неверный репозиторий NFQWS2",
        ));
    }
    let path = format!("https://api.github.com/repos/{repo}/releases/latest");
    let raw = runner.run(
        "curl",
        &[
            "--disable",
            "--fail",
            "--silent",
            "--proto",
            "=https",
            "--max-time",
            "8",
            "--max-filesize",
            "1048576",
            "--user-agent",
            "nfqws2-strategy",
            "--",
            &path,
        ],
        std::time::Instant::now() + Duration::from_secs(8),
    )?;
    let release: Release = serde_json::from_str(&raw)?;
    if !release
        .html_url
        .starts_with(&format!("https://github.com/{repo}/releases/"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "неверная ссылка выпуска NFQWS2",
        ));
    }
    Ok(release)
}
impl Info {
    fn apply(&mut self, release: Release) -> io::Result<()> {
        self.latest = release.tag_name.trim().trim_start_matches('v').into();
        self.url = release.html_url;
        let (new, revision) = parsed_version(&release.tag_name)?;
        self.available = match self.package_status {
            "installed" => {
                let (old, old_revision) = parsed_version(&self.package)?;
                new.cmp_precedence(&old)
                    .then(revision.cmp(&old_revision))
                    .is_gt()
            }
            "missing" => self.engine.is_empty(),
            _ => false,
        };
        Ok(())
    }
}
pub(super) async fn check(State(s): State<Shared>) -> Json<Info> {
    let repo = s.config.nfqws2_repo.clone();
    let Json(mut info) = get(State(s)).await;
    if info.package_status != "unknown" {
        let result =
            tokio::task::spawn_blocking(move || upstream(&repo, &nfqws2_router_command::System))
                .await
                .map_err(io::Error::other)
                .and_then(|r| r)
                .and_then(|r| info.apply(r));
        if let Err(e) = result {
            info.error = e.to_string();
        }
    }
    Json(info)
}
fn installed(src: &str, pkg: &str, apk: bool) -> io::Result<String> {
    fn fail() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "не удалось разобрать статус установленного пакета",
        )
    }
    if src.trim().is_empty() {
        return Ok(String::new());
    }
    if apk {
        let head = format!("{pkg} policy:");
        let mut rows = src.lines().skip_while(|l| l.trim() != head);
        rows.next().ok_or_else(fail)?;
        let mut release = "";
        for line in rows.take_while(|l| l.trim().is_empty() || l.starts_with([' ', '\t'])) {
            let value = line.trim();
            if let Some(heading) = value.strip_suffix(':') {
                release = heading.trim();
            }
            if value.contains("lib/apk/db/installed") {
                return validate(release);
            }
        }
        return Ok(String::new());
    }
    for block in src.replace("\r\n", "\n").split("\n\n") {
        let field = |key: &str| {
            block
                .lines()
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.trim())
        };
        if field("Package") != Some(pkg) {
            continue;
        }
        let state = field("Status")
            .ok_or_else(fail)?
            .split_whitespace()
            .collect::<Vec<_>>();
        if state.len() != 3 {
            return Err(fail());
        }
        return if state[2] == "installed" {
            validate(field("Version").ok_or_else(fail)?)
        } else {
            Ok(String::new())
        };
    }
    Err(fail())
}
async fn output(path: &Path, args: &[&str], seconds: u64) -> io::Result<String> {
    let (ok, text) = tokio::time::timeout(
        Duration::from_secs(seconds),
        crate::packages::command(path, args),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "истекло время ожидания"))??;
    if ok {
        Ok(text)
    } else {
        Err(io::Error::other("команда завершилась с ошибкой"))
    }
}

fn engine_version(output: &str) -> Option<&str> {
    // Match Go's `version\s+(v?[0-9][0-9A-Za-z._-]*)` against the banner.
    output.match_indices("version").find_map(|(i, word)| {
        let rest = &output[i + word.len()..];
        let version = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        let first = version
            .strip_prefix('v')
            .unwrap_or(version)
            .as_bytes()
            .first()?;
        if rest.len() == version.len() || !first.is_ascii_digit() {
            return None;
        }
        let end = version
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
            .unwrap_or(version.len());
        Some(&version[..end])
    })
}
pub(super) async fn get(State(s): State<Shared>) -> Json<Info> {
    let pkg = &s.config.nfqws2_pkg;
    let installed = async {
        let (path, apk) = crate::packages::find_manager(true)?;
        let out = output(&path, &[if apk { "policy" } else { "status" }, pkg], 4).await?;
        installed(&out, pkg, apk)
    };
    let (pkg_version, engine) = tokio::join!(
        installed,
        output(Path::new(&s.config.nfqws_bin), &["--version"], 2)
    );
    let mut info = Info::default();
    match pkg_version {
        Ok(v) => {
            info.package_status = if v.is_empty() { "missing" } else { "installed" };
            info.package = v;
        }
        Err(e) => {
            info.package_status = "unknown";
            info.error = e.to_string();
        }
    }
    if let Ok(out) = engine {
        info.engine = engine_version(&out).unwrap_or_default().into();
    }
    Json(info)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn engine_banner_matches_go_version_token_boundaries() {
        for (banner, expected) in [
            ("nfqws2 version v1.2.3+build", Some("v1.2.3")),
            ("(version\tv72.0-beta_1),", Some("v72.0-beta_1")),
            ("version invalid, version\n3.4-", Some("3.4-")),
            ("version=2 version\u{a0}v4", None),
            ("version v", None),
        ] {
            assert_eq!(engine_version(banner), expected);
        }
    }
    #[test]
    fn official_release_uses_package_revision_and_handles_manual_engine() {
        struct Fixture;
        impl nfqws2_router_command::Runner for Fixture {
            fn run(&self, p: &str, args: &[&str], _: std::time::Instant) -> io::Result<String> {
                assert_eq!(p, "curl");
                assert_eq!(
                    args.last(),
                    Some(&"https://api.github.com/repos/example/engine/releases/latest")
                );
                Ok(serde_json::json!({"tag_name":"v2.1.0-2","html_url":"https://github.com/example/engine/releases/tag/v2.1.0-2"}).to_string())
            }
        }
        assert!(upstream("../other", &Fixture).is_err());
        for (pkg, status, engine, expected) in [
            ("2.1.0-r1", "installed", "v4", true),
            ("2.1.0-r2", "installed", "v4", false),
            ("2.1.1", "installed", "v4", false),
            ("", "missing", "v4", false),
            ("", "missing", "", true),
        ] {
            let mut info = Info {
                package: pkg.into(),
                package_status: status,
                engine: engine.into(),
                ..Default::default()
            };
            info.apply(upstream("example/engine", &Fixture).unwrap())
                .unwrap();
            assert_eq!(info.available, expected);
        }
    }
    #[test]
    fn installed_package_record_is_distinct_from_available_or_missing() {
        assert_eq!(
            installed(
                "Package: p\nVersion: 1.2.0-1\nStatus: install ok installed",
                "p",
                false
            )
            .unwrap(),
            "1.2.0-1"
        );
        assert_eq!(
            installed(
                "p policy:\n  2.9.1:\n     /tmp/feed\n  1.0.0-r2:\n     lib/apk/db/installed",
                "p",
                true
            )
            .unwrap(),
            "1.0.0-r2"
        );
        assert!(installed("p policy:\n  bad:\n    lib/apk/db/installed", "p", true).is_err());
        assert_eq!(
            installed("p policy:\n  2.0.1:\n    /tmp/feed", "p", true).unwrap(),
            ""
        );
        assert!(installed("Package: other\nVersion: 1.0", "p", false).is_err());
    }
}
