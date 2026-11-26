//! Provision the selected server engine only for an explicit VPS deployment.
//! The router package and routine peer updates never invoke these scripts.
#[cfg(target_os = "linux")]
use {
    super::{Backend, Deployment},
    serde_json::Value,
    std::io,
};

#[cfg(target_os = "linux")]
pub(super) fn prepare(
    cfg: &Value,
    requested: Backend,
    report: &mut Deployment,
) -> io::Result<Backend> {
    let mut method = requested;
    if requested == Backend::Kernel {
        let command = format!(
            "PATH=/usr/bin:/usr/sbin:/bin:/sbin sh -s -- {}",
            crate::s(cfg, "interface")
        );
        method = match provision(cfg, include_str!("apt-install.sh"), &command).as_deref() {
            Ok("ready") => {
                report.step(
                    "install (apt)",
                    "Подтверждены инструменты и загружен модуль AmneziaWG",
                );
                Backend::Kernel
            }
            Ok("installed") => {
                report.step(
                    "install (apt)",
                    "Установлен пакет и загружен модуль AmneziaWG",
                );
                Backend::Kernel
            }
            Ok("userspace") => {
                report.step(
                    "probe service",
                    "Сохранена действующая userspace-служба AmneziaWG",
                );
                Backend::Userspace
            }
            Ok("fallback") => {
                report.warn(
                    "install (apt)",
                    "Модуль AmneziaWG недоступен, выбран userspace",
                );
                Backend::Userspace
            }
            Ok("blocked") => {
                let detail = "VPS использует стороннюю службу AmneziaWG";
                report.fail("install (apt)", detail);
                return Err(io::Error::other(detail));
            }
            _ => {
                let detail = "VPS не подтвердил проверку пакета AmneziaWG";
                report.fail("install (apt)", detail);
                return Err(io::Error::other(detail));
            }
        };
    }
    report.set_backend(method);
    if method == Backend::Userspace {
        match ensure_userspace(cfg) {
            Ok(detail) => report.step("install (userspace)", detail),
            Err(e) => {
                report.fail(
                    "install (userspace)",
                    "VPS не подтвердил установку инструментов AmneziaWG",
                );
                return Err(e);
            }
        }
    }
    Ok(method)
}
#[cfg(any(target_os = "linux", test))]
mod script {
    pub(super) const LOCK: &str = include_str!("../../../../internal/services/awg/engine-deps.mod");
    const SUM: &str = include_str!("../../../../internal/services/awg/engine-deps.sum");
    const METADATA: &str = include_str!("../../../../internal/services/awg/userspace-metadata.sh");
    const INSTALL: &str = include_str!("../../../../internal/services/awg/userspace-install.sh");
    const TOOLS_TAG: &str = "v3.1.20260812";
    const TOOLS_REV: &str = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843";

    fn dependency(name: &str) -> &str {
        LOCK.lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next()? == name).then(|| fields.next()).flatten()
            })
            .expect("dependency present in the reviewed engine lock")
    }

    fn metadata() -> String {
        METADATA
            .replace("\r\n", "\n")
            .replace("@GO_VERSION@", dependency("go"))
            .replace("@ENGINE_REV@", crate::runtime::REV)
            .replace("@CRYPTO_VERSION@", dependency("golang.org/x/crypto"))
            .replace("@NET_VERSION@", dependency("golang.org/x/net"))
            .replace("@SYS_VERSION@", dependency("golang.org/x/sys"))
    }
    pub(super) fn render() -> String {
        // The fast path performs read-only version and capability checks. The
        // remote compiler/linker metadata also identifies the pinned engine.
        let probe = r#"set -eu
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
ready() {
  test -x /usr/bin/amneziawg-go && test -x /usr/bin/awg-quick &&
    test -x /usr/local/libexec/nfqws-awg-quick-userspace || return 1
  awg --version 2>/dev/null | grep -Fq '@TOOLS_VERSION@' || return 1
  grep -Fq 'cmd /usr/bin/amneziawg-go' /usr/local/libexec/nfqws-awg-quick-userspace || return 1
  reader=/usr/local/lib/nfqws-awg/go@GO_VERSION@/bin/go
  if ! test -x "$reader"; then reader=$(command -v go) || return 1; fi
  metadata=$("$reader" version -m /usr/bin/amneziawg-go 2>/dev/null) || return 1
@METADATA_CHECK@
}
if ready; then echo ready; exit 0; fi
"#;
        // Each placeholder contains only project-owned source or reviewed
        // upstream version metadata; no profile text is interpreted as shell.
        let body =
            format!("{probe}\n(\n{INSTALL}\n) >/dev/null 2>&1\nready || exit 1\necho installed\n");
        body.replace("\r\n", "\n")
            .replace("@GO_VERSION@", dependency("go"))
            .replace("@TOOLS_VERSION@", TOOLS_TAG)
            .replace("@TOOLS_REV@", TOOLS_REV)
            .replace("@ENGINE_VERSION@", crate::runtime::TARGET)
            .replace("@ENGINE_REV@", crate::runtime::REV)
            .replace("@METADATA_CHECK@", &metadata())
            .replace("@DEPS_MOD@", &LOCK.replace("\r\n", "\n"))
            .replace("@DEPS_SUM@", &SUM.replace("\r\n", "\n"))
    }
}
#[cfg(target_os = "linux")]
fn provision(cfg: &Value, script: &str, command: &str) -> io::Result<String> {
    use std::{
        io::{Seek, Write},
        time::{Duration, Instant},
    };
    let (_secrets, mut ssh) = crate::remote::pinned_command(cfg)?;
    let mut input = tempfile::tempfile()?;
    input.write_all(script.replace("\r\n", "\n").as_bytes())?;
    input.rewind()?;
    ssh.arg(command);
    nfqws2_router_command::output_with_file(
        &mut ssh,
        input,
        Instant::now() + Duration::from_secs(1200),
        1024,
    )
}

#[cfg(target_os = "linux")]
fn ensure_userspace(cfg: &Value) -> io::Result<&'static str> {
    let answer = provision(cfg, &script::render(), "sh -s")
        .map_err(|_| io::Error::other("VPS не подтвердил установку инструментов AmneziaWG"))?;
    match answer.as_str() {
        "ready" => Ok("Версия установленных инструментов AmneziaWG подтверждена"),
        "installed" => Ok("Установлены и проверены официальные инструменты AmneziaWG"),
        _ => Err(io::Error::other(
            "VPS не подтвердил версию движка AmneziaWG",
        )),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pinned_installer_preserves_the_reviewed_dependency_lock_and_has_a_read_only_fast_path() {
        let sh = super::script::render();
        for marker in [
            "@DEPS_SUM@",
            "@TOOLS_VERSION@",
            "@ENGINE_REV@",
            "@GO_VERSION@",
            "@METADATA_CHECK@",
        ] {
            assert!(!sh.contains(marker));
        }
        let (probe, installs) = sh
            .split_once("if ready; then echo ready; exit 0; fi")
            .unwrap();
        assert!(!probe.contains("apt-get") && !probe.contains("install -m"));
        assert!(probe.contains("version -m /usr/bin/amneziawg-go"));
        assert!(installs.contains(&super::script::LOCK.replace("\r\n", "\n")));
        assert!(installs.contains("GOTOOLCHAIN=local") && installs.contains("-mod=readonly"));
    }
}
