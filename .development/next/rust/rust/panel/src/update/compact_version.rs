use nfqws2_config::Platform;
use std::io;
pub(super) const BASE: &str = "nfqws2-strategy-compact";

#[derive(Debug, PartialEq)]
pub(super) struct Target {
    pub(super) package: String,
    pub(super) build: String,
}
pub(super) fn candidate(
    rows: &str,
    apk: bool,
    installed: bool,
    platform: Platform,
) -> io::Result<Option<Target>> {
    let mut found = None;
    for row in rows.lines() {
        let raw = if apk {
            let Some(raw) = row
                .split_whitespace()
                .next()
                .and_then(|p| p.strip_prefix(BASE))
                .and_then(|p| p.strip_prefix('-'))
            else {
                continue;
            };
            raw
        } else {
            let fields: Vec<_> = row.split_whitespace().collect();
            if fields.first() != Some(&BASE) {
                continue;
            }
            match fields.as_slice() {
                [_, "-", _, "-", next] if !installed => *next,
                [_, "-", version] if installed => *version,
                _ => return Err(io::Error::other("Некорректная версия в ответе opkg")),
            }
        };
        if found.is_some()
            || raw.len() > 96
            || !raw.starts_with(|c: char| c.is_ascii_digit())
            || !raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".~+-".contains(&b))
        {
            return Err(io::Error::other("Неоднозначная версия пакета панели"));
        }
        let build = match platform {
            Platform::Entware => raw.strip_suffix("+shared").unwrap_or(raw).to_owned(),
            Platform::OpenWrt => {
                // openwrt_recipe.py interleaves SDK release numbers for the two layouts.
                let (upstream, revision) = raw
                    .rsplit_once('-')
                    .ok_or_else(|| io::Error::other("Отсутствует ревизия OpenWrt"))?;
                let revision = revision
                    .trim_start_matches('r')
                    .parse::<u32>()
                    .ok()
                    .filter(|v| *v > 0)
                    .ok_or_else(|| io::Error::other("Некорректная ревизия OpenWrt"))?;
                format!("{upstream}-{}", revision.div_ceil(2))
            }
        };
        found = Some(Target {
            package: raw.into(),
            build,
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_base_and_binary_versions_survive_both_package_layouts() {
        let rows = "nfqws2-strategy-runs - 1 - 9\nnfqws2-strategy-compact - 1 - 2.0.0-ea-10+shared";
        let t = candidate(rows, false, false, Platform::Entware)
            .unwrap()
            .unwrap();
        assert_eq!(
            (t.package.as_str(), t.build.as_str()),
            ("2.0.0-ea-10+shared", "2.0.0-ea-10")
        );
        assert!(candidate(&format!("{rows}\n{rows}"), false, false, Platform::Entware).is_err());
        assert!(candidate(
            "nfqws2-strategy-compact - 1",
            false,
            false,
            Platform::Entware
        )
        .is_err());
        assert_eq!(
            candidate(
                "nfqws2-strategy-compact - 2.0.0-ea-1",
                false,
                true,
                Platform::Entware
            )
            .unwrap()
            .unwrap()
            .build,
            "2.0.0-ea-1"
        );
        for rev in [3, 4] {
            let t = candidate(
                &format!("nfqws2-strategy-compact-1.8.7-r{rev} aarch64 {{pkg}}"),
                true,
                false,
                Platform::OpenWrt,
            )
            .unwrap()
            .unwrap();
            assert_eq!(t.build, "1.8.7-2");
        }
        assert!(candidate("", false, false, Platform::Entware)
            .unwrap()
            .is_none());
    }
}
