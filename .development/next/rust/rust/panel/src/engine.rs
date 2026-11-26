use crate::http::{blocking, ApiError, Shared};
use axum::{
    extract::State,
    http::header,
    routing::{get, post},
    Json, Router,
};
use nfqws2_config::{literal_shell_config_value, Config, Key, Resolver};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) mod automation;
mod bypass;
pub(crate) use bypass::refresh_transport_bypass;
mod files;
mod lifecycle;
pub(crate) use lifecycle::pause_acceleration;
mod package;
mod version;
pub(crate) use lifecycle::{restart_after_config, restore_manual_off};
pub fn routes() -> Router<Shared> {
    Router::new()
        .merge(lifecycle::routes())
        .route(
            "/api/nfqws2/automation",
            get(automation::status).post(automation::configure),
        )
        .route(
            "/api/nfqws2/automation/pick-now",
            post(automation::pick_now),
        )
        .route("/api/nfqws2/bypass/apply", post(bypass::apply))
        .route("/api/nfqws2/status", get(status))
        .route("/api/nfqws2/reload", post(reload))
        .route("/api/nfqws2/version", get(version::get))
        .route("/api/nfqws2/update/check", get(version::check))
        .route("/api/nfqws2/update", post(package::post))
}
fn read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "превышен размер файла идентификации NFQWS2",
        ));
    }
    Ok(data)
}
fn pid_path(cfg: &Config) -> PathBuf {
    let paths = Resolver::current();
    if Path::new(&cfg.nfqws2_conf) == paths.path(Key::Nfqws2Conf) {
        paths.path(Key::Nfqws2Pid).into()
    } else {
        Path::new(&cfg.nfqws2_conf).with_file_name("nfqws2.pid")
    }
}
fn pid(path: &Path) -> io::Result<i32> {
    let b = read(path, 64)?;
    let s = std::str::from_utf8(&b).unwrap_or("").trim();
    s.parse::<i32>()
        .ok()
        .filter(|&v| v > 1 && v.to_string() == s)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "некорректный PID NFQWS2"))
}
fn executable(argv0: &str) -> &str {
    argv0.rsplit('/').next().unwrap_or("")
}
fn main_identity(argv: &str, path: &Path, main: i32) -> bool {
    let mut args = argv.trim_end_matches('\0').split('\0');
    if !matches!(
        executable(args.next().unwrap_or("")),
        "nfqws2" | "nfqws2.real" | "nfqws2-keenetic"
    ) {
        return false;
    }
    let (mut daemon, mut own, mut queue) = (false, false, None);
    while let Some(arg) = args.next() {
        let (key, param) = arg
            .split_once('=')
            .map_or((arg, None), |(k, v)| (k, Some(v)));
        match key {
            "--daemon" | "-D" => daemon = param.is_none(),
            "--qnum" | "--pidfile" | "--writable" => {
                let Some(v) = param.or_else(|| args.next()) else {
                    return false;
                };
                match key {
                    "--qnum" => {
                        let Ok(n) = v.parse::<u16>() else {
                            return false;
                        };
                        queue = Some(i32::from(n));
                    }
                    "--pidfile" => {
                        if Path::new(v) != path {
                            return false;
                        }
                        own = true;
                    }
                    _ if v.contains("/tmp/nfqws2-strategy/") => return false,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    queue.is_some_and(|q| q == main || daemon && own)
}
fn running(cfg: &Config, proc: &Path) -> bool {
    observed(cfg, proc, None)
}
fn observed(cfg: &Config, proc: &Path, expected: Option<i32>) -> bool {
    let bytes = read(&proc.join("net/netfilter/nfnetlink_queue"), 1 << 20).unwrap_or_default();
    let queues = String::from_utf8_lossy(&bytes);
    let bound = |queue| {
        queues.lines().any(|line| {
            line.split_whitespace()
                .next()
                .and_then(|n| n.parse::<i32>().ok())
                == Some(queue)
        })
    };
    if bound(cfg.main_queue) {
        return true;
    }
    let pidfile = pid_path(cfg);
    let pid = pid(&pidfile).ok();
    if pid.is_none() && queues.is_empty() {
        return false;
    }
    let queue = expected.unwrap_or_else(|| effective_queue(cfg));
    if queue != cfg.main_queue && bound(queue) {
        return true;
    }
    let Some(pid) = pid else {
        return false;
    };
    let Ok(argv) = read(&proc.join(pid.to_string()).join("cmdline"), 256 << 10) else {
        return false;
    };
    main_identity(&String::from_utf8_lossy(&argv), &pidfile, queue)
}
fn effective_queue(cfg: &Config) -> i32 {
    let mut queue = cfg.main_queue;
    for conf in [cfg.nfqws2_conf.clone(), format!("{}.run", cfg.nfqws2_conf)] {
        if let Ok(bytes) = read(Path::new(&conf), 2 << 20) {
            if let Ok(Some(n)) =
                literal_shell_config_value(&String::from_utf8_lossy(&bytes), "NFQUEUE_NUM")
            {
                if let Ok(n) = n.parse::<u16>() {
                    queue = i32::from(n);
                }
            }
        }
    }
    queue
}
async fn status(State(s): State<Shared>) -> Result<impl axum::response::IntoResponse, ApiError> {
    let v=blocking(move||{
        Ok(Json(json!({"running":running(&s.config,Path::new("/proc")),"manual_off":lifecycle::manual_off(&s.store)?})))
    }).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], v))
}
#[cfg(target_os = "linux")]
fn hup(cfg: &Config) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let pid = pid(&pid_path(cfg))?;
    // Hold the original process identity across validation when supported.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    let handle = if fd < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOSYS) {
            return Err(e);
        }
        None
    } else {
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let cmd = read(&PathBuf::from(format!("/proc/{pid}/cmdline")), 256 << 10)?;
    if executable(
        String::from_utf8_lossy(&cmd)
            .split('\0')
            .next()
            .unwrap_or(""),
    ) != "nfqws2"
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PID не принадлежит движку NFQWS2",
        ));
    }
    let rc = if let Some(fd) = handle {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGHUP,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) as i32
        }
    } else {
        unsafe { libc::kill(pid, libc::SIGHUP) }
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
fn hup(_: &Config) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "перечитывание NFQWS2 доступно в Linux",
    ))
}
async fn reload(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    blocking(move || {
        hup(&s.config)?;
        s.logs.append("nfqws2", "info", "отправлен SIGHUP");
        Ok(Json(json!({"status":"reloaded"})))
    })
    .await
    .map_err(|e| ApiError(axum::http::StatusCode::BAD_REQUEST, e.1))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn main_engine_and_test_workers_are_distinct() {
        let path = Path::new("/opt/var/run/nfqws2.pid");
        assert!(main_identity("/bin/nfqws2\0--qnum\x00300", path, 300));
        assert!(!main_identity(
            "/bin/nfqws2-strategy\0--qnum=300",
            path,
            300
        ));
        assert!(!main_identity("/bin/nfqws2\0--qnum=200", path, 300));
        assert!(!main_identity(
            "/bin/nfqws2\0--qnum=300\0--writable=/tmp/nfqws2-strategy/s",
            path,
            300
        ));
        assert!(main_identity(
            "/bin/nfqws2.real\0-D\0--pidfile=/opt/var/run/nfqws2.pid\0--qnum=700",
            path,
            300
        ));
    }
}
