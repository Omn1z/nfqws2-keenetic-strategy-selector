use super::Backend;
use serde::Serialize;
use serde_json::{json, Value};
use std::io;

#[derive(Serialize)]
struct Step {
    name: &'static str,
    ok: bool,
    detail: &'static str,
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Clone, Copy)]
pub(super) enum Rollback {
    Restored,
    RemovedNew,
    Failed { journal: bool },
}

#[derive(Serialize)]
pub(super) struct Deployment {
    ok: bool,
    method: &'static str,
    wan_iface: String,
    listening: bool,
    handshake: bool,
    steps: Vec<Step>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_backup: Option<String>,
}

impl Deployment {
    pub(super) fn new(backend: Backend) -> Self {
        Self {
            ok: false,
            method: backend.method(),
            wan_iface: String::new(),
            listening: false,
            handshake: false,
            steps: Vec::new(),
            error: None,
            rollback_status: None,
            rollback_error: None,
            rollback_backup: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn set_backend(&mut self, backend: Backend) {
        self.method = backend.method();
    }

    pub(super) fn wan(&mut self, cfg: &Value) {
        if super::userspace::selected(cfg) {
            let wan = super::userspace::wan_iface(cfg);
            if super::userspace::safe_wan(wan) {
                self.wan_iface = wan.to_owned();
            }
        }
    }

    pub(super) fn step(&mut self, name: &'static str, detail: &'static str) {
        self.steps.push(Step {
            name,
            ok: true,
            detail,
        });
    }

    pub(super) fn warn(&mut self, name: &'static str, detail: &'static str) {
        self.steps.push(Step {
            name,
            ok: false,
            detail,
        });
    }

    pub(super) fn fail(&mut self, name: &'static str, detail: &'static str) {
        self.warn(name, detail);
        self.error = Some(detail);
    }

    pub(super) fn apply(&mut self, remote: Remote, cfg: &Value) -> io::Result<()> {
        let phases = [
            (
                "validate VPS",
                "Проверены конфигурация, сеть и владелец интерфейса",
            ),
            ("backup conf", "Проверено исходное состояние для отката"),
            ("write conf", "Конфигурация сохранена"),
            ("bring up", "Служба настроена и запущена"),
            ("verify", "Подтверждены конфигурация, интерфейс и UDP-порт"),
        ];
        if let Remote::Unchanged { handshake } = remote {
            self.step(phases[0].0, phases[0].1);
            self.step("verify", "Проверена действующая конфигурация");
            self.listening = true;
            self.handshake = handshake;
            return Ok(());
        }
        let (completed, failure) = match remote {
            Remote::Applied { handshake } => {
                self.listening = true;
                self.handshake = handshake;
                (phases.len(), None)
            }
            Remote::Failed {
                phase,
                code,
                rollback,
            } => (phase as usize, Some((code, rollback))),
            Remote::Unchanged { .. } => unreachable!(),
        };
        for (name, detail) in phases.into_iter().take(completed) {
            self.step(name, detail);
        }
        let Some((code, rollback)) = failure else {
            return Ok(());
        };
        self.fail(phases[completed].0, code.detail());
        match rollback {
            Some(Rollback::Restored) => {
                self.rollback_status = Some("restored");
                self.step("rollback conf", "Прежнее состояние VPN восстановлено");
            }
            Some(Rollback::RemovedNew) => {
                self.rollback_status = Some("removed_new");
                self.step("rollback conf", "Новая конфигурация удалена");
            }
            Some(Rollback::Failed { journal }) => {
                let detail = "Восстановление состояния VPN не подтверждено";
                self.rollback_status = Some("failed");
                self.rollback_error = Some(detail);
                let iface = crate::s(cfg, "interface");
                if journal && super::interface(iface) {
                    let directory = if super::userspace::selected(cfg) {
                        "/etc/amnezia/amneziawg"
                    } else {
                        "/etc/wireguard"
                    };
                    self.rollback_backup = Some(format!("{directory}/.n2s-{iface}.rollback"));
                }
                self.warn("rollback conf", detail);
            }
            None => {}
        }
        Err(io::Error::other(code.detail()))
    }

    pub(super) fn finish(&mut self, result: io::Result<Option<io::Error>>) {
        match result {
            Ok(local) => {
                self.ok = true;
                if local.is_some() {
                    self.warn(
                        "Клиент роутера",
                        "Не удалось применить настройки клиента роутера",
                    );
                }
            }
            Err(_) if self.error.is_none() => {
                if self.listening {
                    self.fail(
                        "save state",
                        "VPN применён, но локальное подтверждение не записано",
                    );
                } else {
                    self.fail("prepare", "Не удалось подготовить профиль к развёртыванию");
                }
            }
            Err(_) => {}
        }
    }

    pub(super) fn response(&self) -> Value {
        if let Some(error) = self.error {
            json!({"ok":false,"error":error,"result":self})
        } else {
            json!({"ok":self.ok,"result":self})
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Clone, Copy)]
pub(super) enum Phase {
    Preflight,
    Backup,
    Write,
    Activate,
    Verify,
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Clone, Copy)]
pub(super) enum Error {
    Invalid,
    Prerequisite,
    Busy,
    Ownership,
    Conflict,
    Apply,
    RollbackFailed,
    RollbackPending,
}
impl Error {
    fn detail(self) -> &'static str {
        match self {
            Self::Invalid => "VPS отклонил конфигурацию",
            Self::Prerequisite => "VPS не подтвердил наличие необходимых средств",
            Self::Busy => "На VPS уже выполняется настройка VPN",
            Self::Ownership => "VPS не подтвердил владельца интерфейса или конфигурации",
            Self::Conflict => "Конфигурация конфликтует с текущим состоянием VPS",
            Self::Apply => "VPS не подтвердил применение конфигурации",
            Self::RollbackFailed | Self::RollbackPending => {
                "Требуется проверить восстановление VPN на VPS"
            }
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(super) enum Remote {
    Applied {
        handshake: bool,
    },
    Unchanged {
        handshake: bool,
    },
    Failed {
        phase: Phase,
        code: Error,
        rollback: Option<Rollback>,
    },
}

impl Remote {
    pub(super) fn result(self) -> io::Result<()> {
        match self {
            Self::Failed { code, .. } => Err(io::Error::other(code.detail())),
            _ => Ok(()),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn parse(response: &str) -> io::Result<Self> {
        let invalid = || io::Error::other("SSH не подтвердил результат применения VPN");
        let fields: Vec<_> = response.split(' ').collect();
        match fields.as_slice() {
            ["ok", phase @ ("verify" | "unchanged"), handshake @ ("0" | "1")] => {
                let handshake = *handshake == "1";
                if *phase == "verify" {
                    Ok(Self::Applied { handshake })
                } else {
                    Ok(Self::Unchanged { handshake })
                }
            }
            ["error", code, phase, rollback] => {
                let phase = match *phase {
                    "preflight" => Phase::Preflight,
                    "backup" => Phase::Backup,
                    "write" => Phase::Write,
                    "activate" => Phase::Activate,
                    "verify" => Phase::Verify,
                    _ => return Err(invalid()),
                };
                let (code, rollback) = match (*code, *rollback) {
                    ("invalid", "-") => (Error::Invalid, None),
                    ("prerequisite", "-") => (Error::Prerequisite, None),
                    ("busy", "-") => (Error::Busy, None),
                    ("ownership", "-") => (Error::Ownership, None),
                    ("conflict", "-") => (Error::Conflict, None),
                    ("apply", "restored") => (Error::Apply, Some(Rollback::Restored)),
                    ("apply", "removed_new") => (Error::Apply, Some(Rollback::RemovedNew)),
                    ("rollback_failed", "failed" | "journal") => (
                        Error::RollbackFailed,
                        Some(Rollback::Failed {
                            journal: *rollback == "journal",
                        }),
                    ),
                    ("rollback_pending", "failed" | "journal") => (
                        Error::RollbackPending,
                        Some(Rollback::Failed {
                            journal: *rollback == "journal",
                        }),
                    ),
                    _ => return Err(invalid()),
                };
                Ok(Self::Failed {
                    phase,
                    code,
                    rollback,
                })
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_reports_distinguish_the_previous_state() {
        for (response, expected) in [
            ("error apply activate removed_new", "removed_new"),
            ("error apply verify restored", "restored"),
            ("error rollback_failed write failed", "failed"),
            ("error rollback_pending preflight journal", "failed"),
        ] {
            let mut deployment = Deployment::new(Backend::Userspace);
            let cfg = json!({"install":"userspace","interface":"awg7"});
            let failure = deployment
                .apply(Remote::parse(response).unwrap(), &cfg)
                .unwrap_err();
            deployment.finish(Err(failure));
            let report = &deployment.response()["result"];
            assert_eq!(report["ok"], false);
            assert_eq!(report["listening"], false);
            assert_eq!(report["handshake"], false);
            assert_eq!(report["rollback_status"], expected);
            assert_eq!(report["rollback_error"].is_string(), expected == "failed");
            assert_eq!(
                report["rollback_backup"].as_str(),
                response
                    .ends_with(" journal")
                    .then_some("/etc/amnezia/amneziawg/.n2s-awg7.rollback")
            );
            assert_eq!(
                report["steps"].as_array().unwrap().last().unwrap()["name"],
                "rollback conf"
            );
        }
    }

    #[test]
    fn report_accepts_only_the_fixed_remote_protocol() {
        for rejected in [
            "ok",
            "ok verify 9",
            "ok verify 1\nextra",
            "error apply preflight private-test-credential",
            "error ownership preflight restored",
            "error unknown preflight -",
            "error apply unexpected restored",
        ] {
            assert!(!Remote::parse(rejected)
                .err()
                .unwrap()
                .to_string()
                .contains(rejected));
        }
        let mut deployment = Deployment::new(Backend::WireGuard);
        deployment
            .apply(Remote::parse("ok unchanged 0").unwrap(), &Value::Null)
            .unwrap();
        deployment.finish(Ok(None));
        let report = &deployment.response()["result"];
        assert_eq!(report["handshake"], false);
        assert_eq!(report["steps"].as_array().unwrap().len(), 2);
        assert_eq!(report["steps"][1]["name"], "verify");
    }
}
