//! One-shot commands use the corresponding service component directly. They
//! neither open HTTP listeners nor autostart other router services.
use nfqws2_config::Config;
use std::io;
mod go_handoff;
mod go_services;

pub(super) fn run(cmd: &str, cfg: &Config, args: Vec<String>) -> io::Result<()> {
    if cmd == "release-native-clients" {
        if args.as_slice() == ["--supported"] {
            println!("native-client-release-v1");
            return Ok(());
        }
        if !args.is_empty() {
            return Err(super::invalid(
                "неизвестный аргумент освобождения AWG-клиентов",
            ));
        }
        let root = std::path::Path::new("/");
        let runtime = nfqws2_awg_profile::runtime::Runtime::new(
            root,
            nfqws2_config::Resolver::new_at(root)
                .path(nfqws2_config::Key::AwgEngineDir)
                .join("amneziawg-go"),
        );
        runtime.release_detached_clients(&nfqws2_store::Store::open(&cfg.data_dir)?)?;
        println!("released");
        return Ok(());
    }
    if matches!(
        cmd,
        "prepare-go-routing" | "finish-go-routing" | "finish-go-services" | "release-go-routing"
    ) {
        if cmd == "prepare-go-routing" {
            if args.as_slice() == ["--listen-address", "--supported"] {
                println!("panel-listener-v1");
                return Ok(());
            }
            if let [flag, token, port] = args.as_slice() {
                if flag == "--listen-address" {
                    let port = port
                        .parse()
                        .map_err(|_| super::invalid("неверный порт панели"))?;
                    println!(
                        "{}",
                        nfqws2_awg_rules::kernel::handoff::listen_address(
                            std::path::Path::new("/proc"),
                            token,
                            port
                        )?
                    );
                    return Ok(());
                }
            }
        }
        if cmd == "finish-go-services" && args.as_slice() == ["--supported"] {
            println!("go-services-v1");
            return Ok(());
        }
        if cmd == "prepare-go-routing" && args.as_slice() == ["--supported"] {
            println!("go-routing-v1");
            return Ok(());
        }
        if cmd == "release-go-routing" && args.as_slice() == ["--supported"] {
            println!("go-routing-release-v1");
            return Ok(());
        }
        if cmd == "prepare-go-routing" && args.as_slice() == ["--parked-guard-supported"] {
            println!("go-routing-parked-guard-v1");
            return Ok(());
        }
        let store = nfqws2_store::Store::open(&cfg.data_dir)?;
        if let [flag, port] = args.as_slice() {
            if flag == "--parked-guard" && matches!(cmd, "prepare-go-routing" | "release-go-routing") {
                let port = port.parse().map_err(|_| super::invalid("неверный порт Go-панели"))?;
                let run = &nfqws2_router_command::System;
                if cmd == "prepare-go-routing" {
                    let armed = nfqws2_awg_rules::kernel::handoff::arm_parked_guard(&store, run, port)?;
                    println!("{}", if armed { "armed" } else { "ordinary" });
                } else {
                    nfqws2_awg_rules::kernel::handoff::release_parked_guard(&store, run, port)?;
                    println!("released");
                }
                return Ok(());
            }
        }
        if cmd == "prepare-go-routing" && args.as_slice() == ["--source-chain"] {
            println!(
                "{}",
                nfqws2_awg_rules::kernel::handoff::source_chain(
                    &store,
                    &nfqws2_router_command::System
                )?
            );
            return Ok(());
        }
        if cmd == "release-go-routing" {
            if args.as_slice() == ["--accept-parked-guard"] {
                nfqws2_awg_rules::kernel::handoff::finish_parked_guard(
                    &store, &nfqws2_router_command::System,
                )?;
                println!("accepted");
                return Ok(());
            }
            let checkpoint = if args.is_empty() {
                false
            } else if args.as_slice() == ["--checkpoint"] {
                true
            } else {
                return Err(super::invalid("неизвестный аргумент снятия маршрутов"));
            };
            nfqws2_awg_rules::kernel::handoff::release_go_routing(
                &store,
                &nfqws2_router_command::System,
                checkpoint,
            )?;
            println!(
                "{}",
                if checkpoint {
                    "checkpointed"
                } else {
                    "released"
                }
            );
            return Ok(());
        }
        if cmd == "prepare-go-routing" && args.as_slice() == ["--needs-ip"] {
            let needed = nfqws2_awg_rules::kernel::handoff::needs_ip(&store)?;
            println!("{}", if needed { "yes" } else { "no" });
            return Ok(());
        }
        let [port] = args.as_slice() else {
            return Err(super::invalid("укажите порт работающей панели"));
        };
        let port = port
            .parse()
            .map_err(|_| super::invalid("неверный порт Go-панели"))?;
        if cmd == "finish-go-routing" {
            return go_handoff::finish(&store, port);
        }
        if cmd == "finish-go-services" {
            return go_services::finish(&store, port);
        }
        let mut services = go_services::capture(&store, port)?;
        crate::awg_rules::stage_sources(cfg, &store)?;
        let trial = nfqws2_awg_rules::kernel::handoff::prepare(
            &store,
            &nfqws2_router_command::System,
            port,
        )?;
        if go_services::capture(&store, port)? != services {
            return Err(io::Error::other(
                "работающие службы Go изменились во время подготовки перехода",
            ));
        }
        if !trial {
            services.clients = go_handoff::prepare_clients_only(&store, port)?;
        }
        go_services::stage(&store, &services)?;
        println!("{}", if trial { "trial" } else { "inactive" });
        return Ok(());
    }
    if cmd == "selftest" {
        let (strategy, hosts) = selftest_args(args)?;
        return selftest(cfg, strategy, hosts);
    }
    if !args.is_empty() {
        return Err(super::invalid(format!("{cmd} не принимает аргументы")));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if cmd == "checkupdate" {
        let info = runtime.block_on(crate::update::check_version(cfg))?;
        serde_json::to_writer_pretty(io::stdout().lock(), &info)?;
        println!();
    } else if cmd == "update" {
        let latest = runtime.block_on(crate::update::install_cli(cfg))?;
        println!("updated {} -> {}; service restarted", cfg.version, latest);
    } else {
        return Err(super::invalid("неизвестная команда CLI"));
    }
    Ok(())
}
fn selftest_args(args: Vec<String>) -> io::Result<(Option<usize>, Vec<String>)> {
    let usage = || super::invalid("selftest [-s ИНДЕКС | --current] ИМЯ [ИМЯ ...]");
    let mut args = args.into_iter();
    let mut index = Some(0);
    let mut hosts = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-s" => {
                index = Some(
                    args.next()
                        .ok_or_else(usage)?
                        .parse()
                        .map_err(|_| usage())?,
                )
            }
            "--current" => index = None,
            _ if arg.starts_with('-') => return Err(usage()),
            _ => hosts.push(arg),
        }
    }
    if hosts.is_empty() {
        return Err(usage());
    }
    Ok((index, hosts))
}
#[cfg(all(feature = "embedded-runs", not(feature = "compact")))]
fn selftest(cfg: &Config, index: Option<usize>, hosts: Vec<String>) -> io::Result<()> {
    let report = if let Some(index) = index {
        nfqws2_runs::matrix::selftest::run(
            cfg,
            include_bytes!("../../../internal/services/strategy/core/catalog/builtin.json"),
            index,
            hosts,
        )?
    } else {
        nfqws2_runs::measure::selftest(hosts)?
    };
    serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
    println!();
    Ok(())
}
#[cfg(any(not(feature = "embedded-runs"), feature = "compact"))]
fn selftest(_cfg: &Config, index: Option<usize>, hosts: Vec<String>) -> io::Result<()> {
    let helper = crate::assets::module_dir()
        .join("runs")
        .join(format!("nfqws2-runs{}", std::env::consts::EXE_SUFFIX));
    if !helper.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "для selftest установите nfqws2-strategy-runs",
        ));
    }
    let mut command = std::process::Command::new(helper);
    if let Some(index) = index {
        command
            .arg("selftest-catalog")
            .arg(index.to_string())
            .env("N2S_MODULE_DIR", crate::assets::module_dir());
    } else {
        command.arg("selftest");
    }
    command.args(hosts);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec())
    }
    #[cfg(not(unix))]
    {
        let status = command.status()?;
        if status.success() {
            return Ok(());
        }
        let kind = match status.code() {
            Some(2) => io::ErrorKind::InvalidInput,
            None | Some(130) => io::ErrorKind::Interrupted,
            _ => io::ErrorKind::Other,
        };
        Err(io::Error::new(kind, format!("selftest: {status}")))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_commands_never_open_sockets_or_run_a_worker() {
        let cfg = Config::default();
        for (cmd, args) in [
            ("checkupdate", vec!["junk"]),
            ("update", vec!["junk"]),
            ("selftest", vec![]),
            ("selftest", vec!["-s", "-1", "example.test"]),
        ] {
            assert_eq!(
                run(cmd, &cfg, args.into_iter().map(str::to_owned).collect())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn selftest_selects_one_builtin_strategy_and_defaults_to_zero() {
        for (args, index) in [
            (vec!["example.test"], Some(0)),
            (vec!["a.test", "-s", "3", "b.test"], Some(3)),
            (vec!["--current", "a.test"], None),
        ] {
            let (selected, hosts) =
                selftest_args(args.into_iter().map(str::to_owned).collect()).unwrap();
            assert_eq!(selected, index);
            assert!(hosts.iter().all(|v| v.ends_with(".test")));
        }
    }
}
