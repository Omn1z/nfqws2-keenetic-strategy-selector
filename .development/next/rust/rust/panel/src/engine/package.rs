use super::{bypass, files, lifecycle};
use crate::{http::Shared, packages};
use axum::{extract::State, Json};
use nfqws2_config::{Key, Resolver};
use nfqws2_router_command::Runner;
use serde_json::{json, Value};
use std::{
    future::Future,
    io,
    path::Path,
    time::{Duration, Instant},
};

const APK_DEPS: &[&str] = &[
    "ca-certificates",
    "curl",
    "ip-full",
    "ipset",
    "kmod-ipt-ipset",
    "kmod-tun",
    "iptables-nft",
    "iptables-mod-nfqueue",
    "iptables-mod-conntrack-extra",
    "iptables-mod-ipopt",
    "iptables-mod-extra",
    "iptables-mod-filter",
    "ip6tables-nft",
    "ip6tables-extra",
    "ip6tables-mod-nat",
];

fn valid_pkg(name: &str) -> bool {
    name.len() <= 128
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".+-".contains(&b))
}

fn trusted_feed(etc: &Path, repo: &str, runner: &impl Runner) -> io::Result<()> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| io::Error::other("некорректный репозиторий NFQWS2"))?;
    let label = |s: &str| {
        s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !s.is_empty()
            && s.len() <= 63
            && !s.starts_with('-')
            && !s.ends_with('-')
    };
    if !label(owner)
        || name.is_empty()
        || name.len() > 100
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    {
        return Err(io::Error::other("некорректный репозиторий NFQWS2"));
    }
    let base = format!("https://{owner}.github.io/{name}/openwrt");
    let key = etc.join("apk/keys/nfqws2-keenetic.pem");
    if files::read(&key, 64 << 10)?.is_none() {
        let raw = runner.run(
            "curl",
            &[
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "30",
                "--max-filesize",
                "65536",
                "--write-out",
                "\n%{http_code}",
                "--",
                &format!("{base}/nfqws2-keenetic.pem"),
            ],
            Instant::now() + Duration::from_secs(30),
        )?;
        let (key_data, status) = raw
            .trim_end()
            .rsplit_once('\n')
            .ok_or_else(|| io::Error::other("пустой ответ сервера ключей APK"))?;
        let key_data = key_data.trim();
        let valid = ["PUBLIC KEY", "RSA PUBLIC KEY"].iter().any(|kind| {
            key_data.starts_with(&format!("-----BEGIN {kind}-----\n"))
                && key_data.ends_with(&format!("\n-----END {kind}-----"))
        });
        if status != "200" || key_data.len() > 65536 || !valid {
            return Err(io::Error::other(
                "некорректный публичный ключ репозитория APK",
            ));
        }
        files::write(&key, &format!("{key_data}\n"), 0o644, None)?;
    }
    let list = etc.join("apk/repositories.d/nfqws2-keenetic.list");
    let old = files::read(&list, 1 << 20)?;
    let url = format!("{base}/packages.adb");
    let mut next = old.clone().unwrap_or_default();
    if !next.lines().any(|line| line.trim() == url) {
        if !next.is_empty() && !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str(&url);
        next.push('\n');
        files::write(&list, &next, 0o644, old.as_deref())?;
    }
    Ok(())
}

fn tail(text: &str, count: usize) -> String {
    let mut last: Vec<_> = text.lines().rev().take(count).collect();
    last.reverse();
    last.into_iter()
        .map(|line| {
            if line
                .split_whitespace()
                .any(|word| word.contains("://") && (word.contains('@') || word.contains('?')))
            {
                "[скрыт URL репозитория с параметрами]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn install<F, Fut>(apk: bool, pkg: &str, output: &mut String, mut run: F) -> io::Result<()>
where
    F: FnMut(Vec<String>) -> Fut,
    Fut: Future<Output = io::Result<(bool, String)>>,
{
    if !valid_pkg(pkg) {
        return Err(io::Error::other("недопустимое имя пакета NFQWS2"));
    }
    let mut steps = vec![vec!["update"]];
    if apk {
        let mut deps = vec!["add"];
        deps.extend(APK_DEPS);
        steps.push(deps);
        steps.push(vec!["add", "--upgrade", pkg]);
    } else {
        steps.push(vec!["install", pkg]);
    }
    for step in steps {
        let action = step[0];
        let (ok, msg) = run(step.iter().map(|v| (*v).to_owned()).collect()).await?;
        *output = tail(format!("{}\n{}", output, msg).trim(), 20);
        if !ok {
            return Err(io::Error::other(format!(
                "{} {action}: {}",
                if apk { "apk" } else { "opkg" },
                tail(output, 4)
            )));
        }
    }
    Ok(())
}

async fn restore_after_install(
    result: io::Result<()>,
    off: bool,
    stop: impl Future<Output = io::Result<()>>,
) -> io::Result<()> {
    if off {
        if let Err(cleanup) = stop.await {
            return Err(io::Error::other(format!(
                "{}Остановка NFQWS2 после обновления: {cleanup}",
                result.err().map(|e| format!("{e}. ")).unwrap_or_default()
            )));
        }
    }
    result
}

async fn update(s: Shared, output: &mut String) -> io::Result<()> {
    let _engine = lifecycle::OPERATIONS.lock().await;
    let _install = packages::INSTALL
        .try_lock()
        .map_err(|_| io::Error::other("Установка уже выполняется"))?;
    let prep = s.clone();
    let _acceleration = tokio::task::spawn_blocking(move || {
        lifecycle::pause_acceleration(&prep.store, &prep.config)
    })
    .await
    .map_err(io::Error::other)??;
    let off = lifecycle::manual_off(&s.store)?;
    let pkg = &s.config.nfqws2_pkg;
    if !valid_pkg(pkg) {
        return Err(io::Error::other("недопустимое имя пакета NFQWS2"));
    }
    let (pm, apk) = packages::find_manager(true)?;
    let prep = s.clone();
    tokio::task::spawn_blocking(move || {
        prep.store
            .transaction(|_| crate::editor::normalize_wan(&prep.config))?;
        if apk {
            trusted_feed(
                Resolver::current().path(Key::EtcDir),
                &prep.config.nfqws2_repo,
                &bypass::TimedCommand,
            )?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(io::Error::other)??;
    let steps = install(apk, pkg, output, |args| {
        let pm = &pm;
        async move { packages::command(pm, &args.iter().map(String::as_str).collect::<Vec<_>>()).await }
    });
    let result = tokio::time::timeout(Duration::from_secs(600), steps)
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "истекло время обновления NFQWS2",
            ))
        });
    restore_after_install(result, off, lifecycle::stop_after_update(s.clone())).await?;
    if bypass::configured(&s.config)? {
        bypass::apply_locked(s.clone(), !off).await?;
    }
    Ok(())
}

pub(super) async fn post(State(s): State<Shared>) -> Json<Value> {
    let job = tokio::spawn(async move {
        let mut output = String::new();
        match update(s.clone(), &mut output).await {
            Ok(()) => {
                s.logs.append("nfqws2", "info", "Пакет NFQWS2 обновлён");
                json!({"ok":true,"output":output})
            }
            Err(e) => {
                s.logs
                    .append("nfqws2", "warn", "Обновление пакета NFQWS2 не выполнено");
                json!({"ok":false,"output":output,"error":e.to_string()})
            }
        }
    })
    .await;
    Json(job.unwrap_or_else(|e| json!({"ok":false,"output":"","error":e.to_string()})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn packages_use_fixed_argv_and_stop_before_install_on_update_failure() {
        for apk in [true, false] {
            let mut commands = Vec::new();
            let mut output = String::new();
            install(apk, "nfqws2-keenetic", &mut output, |args| {
                commands.push(args);
                std::future::ready(Ok((true, "fixture ok".into())))
            })
            .await
            .unwrap();
            assert_eq!(commands[0], ["update"]);
            if apk {
                assert_eq!(&commands[1][1..], APK_DEPS);
                assert_eq!(commands[2], ["add", "--upgrade", "nfqws2-keenetic"]);
            } else {
                assert_eq!(commands[1], ["install", "nfqws2-keenetic"]);
            }
        }
        let mut count = 0;
        let mut output = String::new();
        let err = install(false, "nfqws2-keenetic", &mut output, |_| {
            count += 1;
            std::future::ready(Ok((
                false,
                "fixture unavailable at https://user:secret@fixture.invalid".into(),
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(count, 1);
        assert!(!err.to_string().contains("secret") && !output.contains("secret"));
        assert!(!valid_pkg("--force"));
        assert!(!valid_pkg("a/../b"));
    }

    struct KeySource(AtomicUsize, &'static str);
    impl Runner for KeySource {
        fn run(&self, p: &str, args: &[&str], _: Instant) -> io::Result<String> {
            assert_eq!(p, "curl");
            assert_eq!(
                args.last(),
                Some(&"https://nfqws.github.io/nfqws2-keenetic/openwrt/nfqws2-keenetic.pem")
            );
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(format!(
                "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n\n{}",
                self.1
            ))
        }
    }
    #[test]
    fn apk_feed_is_idempotent_preserves_vendor_repositories_and_rejects_partial_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path();
        let list = etc.join("apk/repositories.d/nfqws2-keenetic.list");
        fs::create_dir_all(list.parent().unwrap()).unwrap();
        fs::write(&list, "# fixture\nhttps://firmware.invalid/feed").unwrap();
        let partial = KeySource(AtomicUsize::new(0), "206");
        assert!(trusted_feed(etc, "nfqws/nfqws2-keenetic", &partial).is_err());
        assert!(!etc.join("apk/keys/nfqws2-keenetic.pem").exists());
        let source = KeySource(AtomicUsize::new(0), "200");
        for _ in 0..2 {
            trusted_feed(etc, "nfqws/nfqws2-keenetic", &source).unwrap();
        }
        assert_eq!(source.0.load(Ordering::Relaxed), 1);
        assert_eq!(fs::read_to_string(list).unwrap(),"# fixture\nhttps://firmware.invalid/feed\nhttps://nfqws.github.io/nfqws2-keenetic/openwrt/packages.adb\n");
        assert!(trusted_feed(etc, "../something", &source).is_err());
    }
    #[tokio::test]
    async fn manually_stopped_engine_is_restored_even_if_installer_or_postinstall_fails() {
        for off in [false, true] {
            for installed in [false, true] {
                let mut called = false;
                let result = if installed {
                    Ok(())
                } else {
                    Err(io::Error::other("fixture install failed"))
                };
                let out = restore_after_install(result, off, async {
                    called = true;
                    Ok(())
                })
                .await;
                assert_eq!(called, off);
                assert_eq!(out.is_ok(), installed);
            }
        }
        let err = restore_after_install(Err(io::Error::other("install")), true, async {
            Err(io::Error::other("stop"))
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("install") && err.contains("stop"));
    }
}
