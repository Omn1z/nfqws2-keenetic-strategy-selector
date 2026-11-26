pub(super) mod capture;

use super::{
    discovery,
    observer::{self, Reader, Target, Wan},
    ppp, Event, Session,
};
use crate::dnsserver::lan;
use nfqws2_router_command::{Runner, System};
use serde_json::{json, Value};
use std::{
    io,
    net::IpAddr,
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout_at,
};

use capture::Observation;

const COMMAND_LIMIT: usize = 128 << 10;
const COOLDOWN: Duration = Duration::from_secs(5 * 60);

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "обновление DHCP для Shadow DNS доступно только на Keenetic",
    )
}

fn changed() -> io::Error {
    io::Error::other("адрес, интерфейс или основной маршрут WAN изменился")
}

pub(super) fn native_error(output: &str) -> bool {
    output.lines().map(str::trim).any(|line| {
        line.starts_with("ndmc: initialization failure")
            || line.starts_with("ndmc: system failed [")
    })
}

fn dhcp_running(output: &str, iface: &str) -> bool {
    let mut id = None;
    let mut service = None;
    for line in output.lines() {
        let Some((key, value)) = line.trim_start_matches("\x1b[K").trim().split_once(':') else {
            continue;
        };
        let field = match key.trim() {
            "id" => &mut id,
            "service" => &mut service,
            _ => continue,
        };
        if field.replace(value.trim()).is_some() {
            return false;
        }
    }
    id == Some(iface) && service == Some("running")
}

fn target_with(
    run: &dyn Runner,
    configured: &[String],
    hosts: &[(String, IpAddr)],
    expected: &Target,
    deadline: Instant,
    identity: impl FnOnce(&str) -> io::Result<(u32, [u8; 6])>,
) -> io::Result<()> {
    let routes = run.run_bounded(
        "ip",
        &["-4", "route", "show", "table", "main", "default"],
        deadline,
        COMMAND_LIMIT,
    )?;
    let wan = Wan::read(&routes, configured, hosts)
        .filter(|wan| wan.key == expected.wan_key)
        .ok_or_else(changed)?;
    let (index, mac) = identity(&expected.candidate.device)?;
    if index != expected.index || mac != expected.mac {
        return Err(changed());
    }
    let interfaces = run.run_bounded("ndmc", &["-c", "show interface"], deadline, COMMAND_LIMIT)?;
    if native_error(&interfaces)
        || !wan
            .candidates(&interfaces, hosts)
            .contains(&expected.candidate)
    {
        return Err(changed());
    }
    let iface = &expected.candidate.iface;
    let output = run.run_bounded(
        "ndmc",
        &["-c", &format!("show ip dhcp client {iface}")],
        deadline,
        COMMAND_LIMIT,
    )?;
    if native_error(&output) || !dhcp_running(&output, iface) {
        return Err(io::Error::other(
            "штатный DHCP-клиент выбранного WAN не запущен",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct State {
    active: bool,
    next: Option<Instant>,
}

pub(super) struct Renewal {
    wan: Vec<String>,
    available: bool,
    state: Arc<Mutex<State>>,
}

pub(super) struct Guard(Arc<Mutex<State>>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.lock().unwrap().active = false;
    }
}

impl Guard {
    fn sent(&self) {
        self.0.lock().unwrap().next = Some(Instant::now() + COOLDOWN);
    }
}

fn platform() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        Path::new("/etc/openwrt_release")
            .metadata()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            && std::env::var_os("PATH").is_some_and(|path| {
                std::env::split_paths(&path).any(|root| {
                    root.join("ndmc")
                        .metadata()
                        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                })
            })
    }
    #[cfg(not(target_os = "linux"))]
    false
}

impl Renewal {
    #[cfg(test)]
    pub(super) fn fixture(available: bool) -> Self {
        Self {
            wan: Vec::new(),
            available,
            state: Default::default(),
        }
    }

    pub(super) fn new(wan: Vec<String>) -> Self {
        Self {
            wan,
            available: platform(),
            state: Default::default(),
        }
    }

    pub(super) fn available(&self) -> bool {
        self.available
    }

    pub(super) fn begin(&self) -> io::Result<Guard> {
        if !self.available {
            return Err(unavailable());
        }
        let mut state = self.state.lock().unwrap();
        if state.active {
            return Err(io::Error::other(
                "обновление DNS провайдера уже выполняется",
            ));
        }
        if let Some(next) = state.next.filter(|next| *next > Instant::now()) {
            let wait = next.saturating_duration_since(Instant::now()).as_secs() + 1;
            return Err(io::Error::other(format!(
                "повторное обновление DNS провайдера доступно через {wait} с"
            )));
        }
        state.active = true;
        Ok(Guard(self.state.clone()))
    }
}

pub(in crate::dnsserver) struct Prepared {
    reader: Reader,
}

pub(in crate::dnsserver) struct Pending {
    reader: Reader,
    baseline: u64,
    until: tokio::time::Instant,
}

async fn issue(program: &Path, iface: &str, deadline: Instant) -> io::Result<()> {
    let mut child = tokio::process::Command::new(program)
        .args(["-c", &format!("interface {iface} ip dhcp client renew")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().ok_or(io::ErrorKind::BrokenPipe)?;
    let stderr = child.stderr.take().ok_or(io::ErrorKind::BrokenPipe)?;
    timeout_at(deadline.into(), async {
        let (stdout, stderr) = tokio::try_join!(native_output(stdout), native_output(stderr))?;
        if native_error(&stdout) || native_error(&stderr) || !child.wait().await?.success() {
            return Err(io::Error::other("ошибка штатной команды DHCP"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

async fn native_output(reader: impl AsyncRead + Unpin) -> io::Result<String> {
    let mut output = Vec::new();
    reader
        .take(COMMAND_LIMIT as u64 + 1)
        .read_to_end(&mut output)
        .await?;
    if output.len() > COMMAND_LIMIT {
        return Err(io::Error::other(
            "ответ штатной команды DHCP слишком длинный",
        ));
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

pub(in crate::dnsserver) struct Request<'a> {
    session: &'a Session,
    guard: Guard,
    deadline: Instant,
    event: Event<'a>,
}

impl<'a> Request<'a> {
    pub(super) fn new(session: &'a Session) -> io::Result<Self> {
        Ok(Self {
            session,
            guard: session.env.renewal.begin()?,
            deadline: Instant::now() + Duration::from_secs(16),
            event: session.env.diagnostics.begin(
                "native.renew.preflight",
                "Пользователь подтвердил однократное штатное обновление DHCP; проверка WAN и захвата",
            ),
        })
    }

    async fn discover(&self) -> io::Result<Arc<[discovery::Peer]>> {
        timeout_at(
            self.deadline.into(),
            self.session.read_provider(true, Some(&self.event)),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    pub(in crate::dnsserver) async fn already_resolved(&self) -> Option<Value> {
        let peers = self.discover().await.ok()?;
        Some(self.resolved(
            None,
            &peers,
            "DNS провайдера уже определены автоматически; обновлять аренду не потребовалось.",
        ))
    }

    pub(in crate::dnsserver) async fn prepare(&self) -> io::Result<Prepared> {
        let env = &self.session.env;
        let slot = timeout_at(self.deadline.into(), env.observer.lock())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
        let reader = slot.reader(&self.session.stopped.subscribe()).cloned().ok_or_else(|| {
            let wan = &env.renewal.wan;
            if !wan.is_empty() && wan.iter().all(|device| ppp::device(device)) {
                io::Error::other("на PPP WAN обновление DHCP неприменимо; DNS читаются из IPCP текущего PPPoE-сеанса")
            } else {
                io::Error::other("нет активного наблюдения DHCP на подтверждённом WAN; обновление не выполнялось")
            }
        })?;
        Ok(Prepared { reader })
    }

    pub(in crate::dnsserver) async fn send(&self, prepared: Prepared) -> io::Result<Pending> {
        let Prepared { reader } = prepared;
        let lifecycle = self.session.stopped.subscribe();
        let _read_gate = timeout_at(self.deadline.into(), self.session.cache.lock())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
        let env = &self.session.env;
        let slot = timeout_at(self.deadline.into(), env.observer.lock())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
        let still_current = || {
            !*lifecycle.borrow()
                && slot
                    .reader(&lifecycle)
                    .is_some_and(|live| live.current(&reader))
        };
        if !still_current() {
            return Err(changed());
        }
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(3));
        let wan = env.renewal.wan.clone();
        let expected = reader.target.clone();
        tokio::task::spawn_blocking(move || {
            target_with(
                &System,
                &wan,
                &lan::addresses()?,
                &expected,
                deadline,
                observer::link_identity,
            )
        })
        .await
        .map_err(io::Error::other)??;
        if !still_current() || Instant::now() >= self.deadline {
            return Err(changed());
        }
        let baseline = reader.snapshot().sequence;
        let target = &reader.target.candidate;
        self.guard.sent();
        self.event.step(
            "native.renew.command",
            &format!(
                "{} / {}: штатная команда DHCP renew отправляется один раз",
                target.iface, target.device
            ),
        );
        issue(
            Path::new("ndmc"),
            &target.iface,
            self.deadline.min(Instant::now() + Duration::from_secs(3)),
        )
        .await
        .map_err(|_| {
            io::Error::other(
                "команда DHCP renew не подтвердилась; автоматического повтора не будет",
            )
        })?;
        let until = (self.deadline - Duration::from_millis(2500))
            .min(Instant::now() + Duration::from_secs(8));
        Ok(Pending {
            reader,
            baseline,
            until: until.into(),
        })
    }

    pub(in crate::dnsserver) async fn finish(&self, pending: Pending) -> io::Result<Value> {
        let observation = pending
            .reader
            .clone()
            .wait(pending.baseline, pending.until)
            .await;
        let target = &pending.reader.target;
        match self.discover().await {
            Ok(peers) => {
                return Ok(self.resolved(
                    Some(target),
                    &peers,
                    "DNS провайдера получены автоматически.",
                ))
            }
            Err(error) => self
                .event
                .step("native.renew.discovery", &error.to_string()),
        }
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let current = timeout_at(self.deadline.into(), self.session.env.observer.lock())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?
            .reader(&self.session.stopped.subscribe())
            .is_some_and(|live| live.current(&pending.reader));
        let (status, message) = match observation.map(|receipt| receipt.observation) {
            Some(Observation::Nak) => (
                "nak",
                "Провайдер отклонил прежнюю DHCP-аренду. Штатный клиент Keenetic восстанавливает подключение.",
            ),
            Some(Observation::AckNoDns) if current => (
                "no_dns",
                "Провайдер подтвердил DHCP-аренду, но не передал пригодные DNS-серверы (option 6).",
            ),
            _ => waiting(),
        };
        let mut state = self.session.state.lock().unwrap();
        state.servers.clear();
        state.error = message.into();
        Ok(json!({
            "status":status, "interface":target.candidate.iface,
            "device":target.candidate.device, "message":message
        }))
    }

    pub(in crate::dnsserver) fn report(&mut self, result: Option<&Value>, error: &str) {
        let (status, message, servers) = result.map_or(("", "", Vec::new()), |result| {
            let servers = result["servers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            (
                result["status"].as_str().unwrap_or_default(),
                result["message"].as_str().unwrap_or_default(),
                servers,
            )
        });
        self.event
            .step("native.renew.result", &format!("{status}: {message}"));
        self.event.record(servers, error, None);
    }

    fn resolved(&self, target: Option<&Target>, peers: &[discovery::Peer], message: &str) -> Value {
        let mut state = self.session.state.lock().unwrap();
        state.servers = peers.iter().map(|peer| peer.addr.to_string()).collect();
        if state.fallback.is_some() {
            state.gen = state.gen.wrapping_add(1);
            state.probing = false;
            state.fallback = Some(Instant::now());
        } else {
            state.error.clear();
        }
        let iface = target.map_or("", |target| target.candidate.iface.as_str());
        let device = target.map_or("", |target| target.candidate.device.as_str());
        json!({"status":"resolved","interface":iface,"device":device,"servers":state.servers,"message":message})
    }
}

fn waiting() -> (&'static str, &'static str) {
    (
        "waiting",
        "Команда DHCP renew отправлена. Новый DNS пока не получен; наблюдение продолжится без повторной команды.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsserver::shadow::Environment;
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    const ISP: &str = "Interface, name = \"ISP\":\nid: ISP\ntype: GigabitEthernet\nconnected: yes\nglobal: yes\ndefaultgw: yes\nsecurity-level: public\naddress: 192.0.2.10\n";
    const DEFAULT_ROUTE: &str = "default via 192.0.2.1 dev eth9 src 192.0.2.10 metric 10";

    fn fixture_target() -> Target {
        Target {
            wan_key: "ip=192.0.2.10|route=eth9/192.0.2.1".into(),
            candidate: observer::Candidate {
                iface: "ISP".into(),
                device: "eth9".into(),
                client: Ipv4Addr::new(192, 0, 2, 10),
            },
            index: 7,
            mac: [2, 0, 0, 0, 0, 1],
        }
    }

    struct Firmware<'a> {
        routes: &'a str,
        interfaces: &'a str,
        dhcp: &'a str,
    }

    impl Runner for Firmware<'_> {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            let output = match (program, args) {
                ("ip", ["-4", "route", "show", "table", "main", "default"]) => self.routes,
                ("ndmc", ["-c", "show interface"]) => self.interfaces,
                ("ndmc", ["-c", "show ip dhcp client ISP"]) => self.dhcp,
                _ => panic!("unexpected preflight command {program} {args:?}"),
            };
            Ok(output.to_owned())
        }
    }

    #[test]
    fn renew_preflight_requires_exact_physical_public_default_and_running_native_dhcp() {
        let wan = ["eth9".to_owned()];
        let hosts = [("eth9".to_owned(), "192.0.2.10".parse().unwrap())];
        let confirmed = |fw: Firmware<'_>| {
            target_with(
                &fw,
                &wan,
                &hosts,
                &fixture_target(),
                Instant::now() + Duration::from_secs(1),
                |device| {
                    assert_eq!(device, "eth9");
                    Ok((7, [2, 0, 0, 0, 0, 1]))
                },
            )
        };
        confirmed(Firmware {
            routes: DEFAULT_ROUTE,
            interfaces: ISP,
            dhcp: "id: ISP\nservice: running\n",
        })
        .unwrap();
        for (routes, interfaces, dhcp) in [
            (
                "default via 192.0.2.1 dev awg0",
                ISP,
                "id: ISP\nservice: running",
            ),
            (DEFAULT_ROUTE, ISP, "id: WAN\nservice: running"),
            (DEFAULT_ROUTE, ISP, "id: ISP\nservice: stopped"),
            (
                DEFAULT_ROUTE,
                ISP,
                "id: ISP\nservice: running\nservice: running",
            ),
            (
                DEFAULT_ROUTE,
                ISP,
                "id: ISP\nservice: running\nndmc: system failed [1]",
            ),
        ] {
            assert!(confirmed(Firmware {
                routes,
                interfaces,
                dhcp
            })
            .is_err());
        }
        for field in ["connected", "global", "defaultgw", "security-level", "type"] {
            let invalid = ISP
                .lines()
                .filter(|line| !line.starts_with(&format!("{field}:")))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(confirmed(Firmware {
                routes: DEFAULT_ROUTE,
                interfaces: &invalid,
                dhcp: "id: ISP\nservice: running",
            })
            .is_err());
        }
    }

    #[test]
    fn renew_gate_remembers_ambiguous_send_but_releases_failed_preflight() {
        let service = Renewal {
            available: true,
            ..Renewal::new(Vec::new())
        };
        let preflight = service.begin().unwrap();
        assert!(service.begin().is_err());
        drop(preflight);
        let attempted = service.begin().unwrap();
        attempted.sent();
        drop(attempted);
        assert!(service.begin().is_err());
        service.state.lock().unwrap().next = Some(Instant::now() - Duration::from_secs(1));
        assert!(service.begin().is_ok());
    }

    #[tokio::test]
    async fn shared_reader_correlated_nak_survives_wan_loss_without_republishing_old_dns() {
        #[derive(Default)]
        struct OldDns(AtomicUsize);
        impl discovery::Source for OldDns {
            fn read(&self, _: &[discovery::History]) -> io::Result<discovery::Evidence> {
                if self.0.fetch_add(1, Ordering::Relaxed) != 0 {
                    return Err(io::ErrorKind::NotConnected.into());
                }
                Ok(discovery::Evidence::fixture(vec![discovery::Peer {
                    addr: "192.0.2.53:53".parse().unwrap(),
                    device: "eth9".into(),
                    expires: None,
                }]))
            }
        }

        let firmware = Arc::new(OldDns::default());
        let session = Session::fixture(
            &json!({"enabled":true,"domains":[{"domain":"test"}]}),
            Arc::new(Environment {
                source: firmware.clone(),
                diagnostics: Default::default(),
                renewal: Renewal::fixture(true),
                observer: Default::default(),
                leases: None,
                inform: Default::default(),
            }),
        )
        .unwrap();
        assert_eq!(session.discover(false).await.unwrap()[0].device, "eth9");
        session.env.diagnostics.set(true);
        let mut request = Request::new(&session).unwrap();
        let (reader, producer) = Reader::fixture(fixture_target());
        producer.send_modify(|state| {
            state.sequence = 1;
            state.receipt = Some(capture::Receipt {
                observation: Observation::Nak,
                observed_at: time::OffsetDateTime::now_utc(),
            });
        });
        let pending = Pending {
            reader,
            baseline: 0,
            until: tokio::time::Instant::now() + Duration::from_secs(1),
        };
        let response = request.finish(pending).await.unwrap();
        request.report(Some(&response), "");
        assert_eq!(response["status"], "nak");
        assert_eq!(response["interface"], "ISP");
        assert!(response.get("servers").is_none());
        assert_eq!(session.status()["servers"], json!([]));
        assert!(session.discover(false).await.is_err());
        assert_eq!(firmware.0.load(Ordering::Relaxed), 2);
        let diagnostics = session.env.diagnostics.read();
        let attempt = &diagnostics["attempts"][0];
        assert_eq!(attempt["events"][0]["stage"], "native.renew.preflight");
        assert_eq!(attempt["events"][2]["stage"], "native.renew.result");
        assert!(attempt["events"][2]["message"]
            .as_str()
            .unwrap()
            .starts_with("nak: "));
        assert_eq!(attempt["servers"], json!([]));
        assert_eq!(diagnostics["in_progress"], false);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn renew_issues_one_native_command_and_checks_standalone_stderr_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let command = dir.path().join("ndmc-fixture");
        std::fs::write(
            &command,
            "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = -c ] && [ \"$2\" = 'interface ISP ip dhcp client renew' ] || exit 3\nprintf 'ndmc: system failed [3]\\n' >&2\n",
        )
        .unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            issue(&command, "ISP", Instant::now() + Duration::from_secs(2))
                .await
                .is_err()
        );
        std::fs::write(&command, "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = -c ] && [ \"$2\" = 'interface ISP ip dhcp client renew' ]\n").unwrap();
        issue(&command, "ISP", Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
    }
}
