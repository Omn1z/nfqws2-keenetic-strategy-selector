//! Read-only server status. Keep only validated public measurements in cache.
use super::{active, conf, invalid, read, runtime::Runtime, s};
use nfqws2_store::Store;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub(crate) struct State(Arc<Mutex<Cache>>);
#[derive(Default)]
struct Cache {
    busy: bool,
    worker: Option<std::thread::JoinHandle<()>>,
    latest: HashMap<String, (String, Value)>,
}
fn via(row: &Value) -> String {
    let cfg = &row["config"];
    let c = &cfg["conn"];
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        s(c, "host"),
        c["port"],
        s(c, "user"),
        s(c, "known_key"),
        s(cfg, "interface"),
        s(cfg, "protocol"),
        s(cfg, "native_vpn_tool")
    )
}
fn empty() -> Value {
    json!({"reachable":false,"up":false,"listen_port":0,"peers":null})
}
fn result(st: Value) -> Value {
    if st["error"].is_string() {
        json!({"ok":false,"error":st["error"],"status":st})
    } else {
        json!({"ok":true,"status":st})
    }
}
fn error(msg: &str) -> Value {
    let mut v = empty();
    v["error"] = json!(msg);
    v
}
impl State {
    pub(crate) fn join(&self) -> io::Result<()> {
        let worker = self
            .0
            .lock()
            .map_err(|_| io::Error::other("кеш статуса сервера недоступен"))?
            .worker
            .take();
        if let Some(w) = worker {
            w.join()
                .map_err(|_| io::Error::other("чтение статуса AWG прервано"))?;
        }
        Ok(())
    }
    pub(crate) fn status(&self, row: &Value) -> Option<Value> {
        let identity = via(row);
        self.0
            .lock()
            .ok()?
            .latest
            .get(s(row, "id"))
            .filter(|(key, _)| key == &identity)
            .map(|(_, st)| st.clone())
    }
    fn refresh(
        &self,
        row: &Value,
        fetch: impl FnOnce(Value) -> io::Result<Value> + Send + 'static,
    ) -> io::Result<Value> {
        let cfg = &row["config"];
        if cfg["install"] == "imported" {
            return Ok(result(empty()));
        }
        if let Err(e) = validate(cfg) {
            return Ok(result(error(&e.to_string())));
        }
        let id = s(row, "id").to_owned();
        let key = via(row);
        let mut lock = self
            .0
            .lock()
            .map_err(|_| io::Error::other("кеш статуса сервера недоступен"))?;
        let prior = lock
            .latest
            .get(&id)
            .filter(|(k, _)| k == &key)
            .map(|(_, st)| st.clone())
            .unwrap_or_else(empty);
        if !lock.busy {
            let shared = self.0.clone();
            // Don't copy the stored profiles or any peer private keys to a
            // worker. Only the selected SSH credential and display map travel.
            let task = json!({"conn":cfg["conn"],"interface":cfg["interface"],"native_vpn_tool":crate::deploy::status_tool(cfg),"peers":cfg["peers"].as_array().into_iter().flatten()
                .map(|p|json!({"id":p["id"],"name":p["name"],"public_key":p["public_key"]})).collect::<Vec<_>>()});
            lock.busy = true;
            match std::thread::Builder::new()
                .name("awg-status".into())
                .spawn(move || {
                    let st = fetch(task).unwrap_or_else(|e| error(&e.to_string()));
                    if let Ok(mut c) = shared.lock() {
                        if c.latest.len() >= 32 && !c.latest.contains_key(&id) {
                            c.latest.clear();
                        }
                        c.latest.insert(id, (key, st));
                        c.busy = false;
                    }
                }) {
                Ok(w) => lock.worker = Some(w),
                Err(e) => {
                    lock.busy = false;
                    return Err(e);
                }
            }
        }
        Ok(result(prior))
    }
}
fn validate_address(cfg: &Value) -> io::Result<()> {
    let conn = &cfg["conn"];
    let host = s(conn, "host");
    if host.is_empty() {
        return Err(invalid("не указан SSH-сервер"));
    }
    let port = conn["port"]
        .as_u64()
        .filter(|p| (1..=65535).contains(p))
        .unwrap_or(22);
    let endpoint = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    conf::endpoint(&endpoint)?;
    let user = s(conn, "user");
    if user.is_empty()
        || user.len() > 64
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(invalid("неверное имя SSH-пользователя"));
    }
    let iface = s(cfg, "interface");
    if iface.is_empty()
        || iface.len() > 15
        || iface.starts_with('-')
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(invalid("неверное имя серверного интерфейса"));
    }
    Ok(())
}
pub(crate) fn validate(cfg: &Value) -> io::Result<()> {
    validate_address(cfg)?;
    validate_pin(s(&cfg["conn"], "known_key"))
}
fn validate_pin(key: &str) -> io::Result<()> {
    if key.contains(['\r', '\n', '\0']) {
        return Err(invalid("неверный формат SSH-ключа хоста"));
    }
    let mut parts = key.split_ascii_whitespace();
    let algorithm = parts.next().unwrap_or("");
    let blob = parts.next().unwrap_or("");
    if !matches!(
        algorithm,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || blob.len() < 16
        || blob.len() > 16384
        || !blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        || parts.next().is_some()
    {
        return Err(invalid(
            "для чтения статуса нужен сохранённый публичный ключ SSH-хоста",
        ));
    }
    Ok(())
}
impl Runtime {
    pub fn trust_selected_host(&self, db: &Store, requested: &str) -> io::Result<Value> {
        if self.root != std::path::Path::new("/") {
            return Err(invalid("SSH доступен только в рабочей системе роутера"));
        }
        self.remote.trust(db, requested, learn_key)
    }
    pub fn refresh_status(&self, db: &Store) -> io::Result<Value> {
        let d = read(db)?;
        self.remote.refresh(
            active(&d)?,
            if self.root == std::path::Path::new("/") {
                fetch
            } else {
                |_| Err(invalid("SSH доступен только в рабочей системе роутера"))
            },
        )
    }
}
impl State {
    fn trust(
        &self,
        db: &Store,
        requested: &str,
        connect: impl FnOnce(&Value) -> io::Result<String>,
    ) -> io::Result<Value> {
        let doc = read(db)?;
        let row = active(&doc)?;
        if s(row, "id") != requested || row["config"]["install"] == "imported" {
            return Err(invalid("выберите сохранённый управляемый сервер"));
        }
        let cfg = &row["config"];
        validate_address(cfg)?;
        if !s(&cfg["conn"], "known_key").is_empty() {
            return Err(invalid("ключ SSH-хоста уже закреплён"));
        }
        {
            let mut cache = self
                .0
                .lock()
                .map_err(|_| io::Error::other("кеш статуса сервера недоступен"))?;
            if cache.busy {
                return Err(invalid("проверка SSH уже выполняется"));
            }
            cache.busy = true;
        }
        let result = (|| {
            let key = connect(cfg)?;
            validate_pin(&key)?;
            super::edit_document(db, |updated| {
                let current = active(updated)?;
                let current_cfg = &current["config"];
                if s(current, "id") != requested
                    || current_cfg["conn"] != cfg["conn"]
                    || current_cfg["install"] != cfg["install"]
                    || current_cfg["interface"] != cfg["interface"]
                {
                    return Err(invalid("профиль изменился во время проверки SSH"));
                }
                let row = updated["servers"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r["id"] == requested)
                    .unwrap();
                row["config"]["conn"]["known_key"] = json!(key);
                Ok(())
            })?;
            Ok(json!({"ok":true,"known_key":key}))
        })();
        let mut cache = self
            .0
            .lock()
            .map_err(|_| io::Error::other("кеш статуса сервера недоступен"))?;
        cache.busy = false;
        result
    }
}
#[cfg(not(target_os = "linux"))]
fn learn_key(_: &Value) -> io::Result<String> {
    Err(invalid("SSH доступен только на Linux-роутере"))
}
#[cfg(not(target_os = "linux"))]
fn fetch(_: Value) -> io::Result<Value> {
    Err(invalid("SSH доступен только на Linux-роутере"))
}

#[cfg(any(target_os = "linux", test))]
fn parse(text: &str, cfg: &Value, now: u64) -> io::Result<Value> {
    let mut v = empty();
    v["reachable"] = json!(true);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    if first == "down" {
        return Ok(v);
    }
    let port = first
        .strip_prefix("port ")
        .and_then(|n| n.parse::<u16>().ok())
        .ok_or_else(|| invalid("неожиданный ответ сервера AWG"))?;
    let mut peers = std::collections::BTreeMap::new();
    let mut section = "";
    for line in lines {
        if matches!(line, "endpoints" | "handshakes" | "transfer") {
            section = line;
            continue;
        }
        let mut f = line.split_ascii_whitespace();
        let key = f.next().unwrap_or("");
        conf::key(key, false)?;
        let peer=peers.entry(key).or_insert_with(||{
            let p=cfg["peers"].as_array().into_iter().flatten().find(|p|p["public_key"]==key);
            json!({"id":p.map_or("",|p|s(p,"id")),"name":p.map_or("",|p|s(p,"name")),"public_key":key,"endpoint":"","latest_handshake":0,"rx_bytes":0,"tx_bytes":0,"online":false})
        });
        let parse_num = |v: Option<&str>| {
            v.and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| invalid("неверный счётчик сервера AWG"))
        };
        match section {
            "endpoints" => {
                let ep = f.next().unwrap_or("");
                if ep != "(none)" && ep.parse::<std::net::SocketAddr>().is_err() {
                    return Err(invalid("неверный endpoint пира"));
                }
                peer["endpoint"] = json!(ep);
            }
            "handshakes" => {
                let t = parse_num(f.next())?;
                peer["latest_handshake"] = json!(t);
                peer["online"] = json!(t > 0 && now.checked_sub(t).is_some_and(|age| age < 180));
            }
            "transfer" => {
                peer["rx_bytes"] = json!(parse_num(f.next())?);
                peer["tx_bytes"] = json!(parse_num(f.next())?);
            }
            _ => return Err(invalid("неожиданный формат статуса AWG")),
        }
        if f.next().is_some() {
            return Err(invalid("неожиданные поля статуса AWG"));
        }
    }
    v["up"] = json!(true);
    v["listen_port"] = json!(port);
    v["peers"] = json!(peers.into_values().collect::<Vec<_>>());
    Ok(v)
}
#[cfg(target_os = "linux")]
pub(crate) fn pinned_command(
    cfg: &Value,
) -> io::Result<(tempfile::TempDir, std::process::Command)> {
    validate(cfg)?;
    ssh_command(cfg, false)
}
#[cfg(target_os = "linux")]
fn ssh_command(
    cfg: &Value,
    first_use: bool,
) -> io::Result<(tempfile::TempDir, std::process::Command)> {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        process::Command,
    };
    let c = &cfg["conn"];
    let host = s(c, "host");
    let port = c["port"]
        .as_u64()
        .filter(|p| (1..=65535).contains(p))
        .unwrap_or(22);
    let dir = tempfile::Builder::new()
        .prefix(".n2s-awg-")
        .tempdir_in("/tmp")?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let file = |name: &str, bytes: &[u8], mode: u32| -> io::Result<_> {
        let path = dir.path().join(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)?;
        f.write_all(bytes)?;
        Ok(path)
    };
    let known = if first_use {
        String::new()
    } else {
        format!("n2s-awg-peer {}\n", s(c, "known_key").trim())
    };
    let pin = file("hosts", known.as_bytes(), 0o600)?;
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-F",
        "/dev/null",
        "-T",
        "-o",
        if first_use {
            "StrictHostKeyChecking=accept-new"
        } else {
            "StrictHostKeyChecking=yes"
        },
        "-o",
        "HashKnownHosts=no",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "CheckHostIP=no",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "HostKeyAlias=n2s-awg-peer",
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
    ])
    .arg(format!("UserKnownHostsFile={}", pin.display()));
    let password = match s(c, "auth_kind") {
        "key" => {
            let key = s(c, "key_pem");
            if key.is_empty() {
                return Err(invalid("не указан приватный SSH-ключ"));
            }
            cmd.arg("-i")
                .arg(file("key", key.as_bytes(), 0o600)?)
                .args(["-o", "PreferredAuthentications=publickey"]);
            s(c, "key_pass")
        }
        "" | "password" => {
            cmd.args(["-o", "PreferredAuthentications=password"]);
            s(c, "password")
        }
        _ => return Err(invalid("неизвестный тип SSH-аутентификации")),
    };
    if !password.is_empty() {
        if password.contains(['\0', '\r', '\n']) {
            return Err(invalid("неподдерживаемый формат пароля SSH"));
        }
        let pw = file("credential", password.as_bytes(), 0o600)?;
        let executable=file("askpass",b"#!/bin/sh\ncase \"$1\" in *[Pp]assword:*|*passphrase*) exec cat \"$N2S_AWG_ASKPASS_FILE\";; *) exit 1;; esac\n",0o700)?;
        cmd.env("SSH_ASKPASS", executable)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "awg")
            .env("N2S_AWG_ASKPASS_FILE", pw);
    } else {
        cmd.args(["-o", "BatchMode=yes"]);
    }
    cmd.args(["-l", s(c, "user"), "-p", &port.to_string(), "--", host]);
    Ok((dir, cmd))
}
#[cfg(target_os = "linux")]
fn learn_key(cfg: &Value) -> io::Result<String> {
    use std::time::{Duration, Instant};
    learn_with(cfg, |cmd| {
        nfqws2_router_command::output(cmd, Instant::now() + Duration::from_secs(20), 4096)
            .map(|_| ())
    })
}
#[cfg(target_os = "linux")]
fn learn_with(
    cfg: &Value,
    run: impl FnOnce(&mut std::process::Command) -> io::Result<()>,
) -> io::Result<String> {
    use std::fs;
    let (dir, mut cmd) = ssh_command(cfg, true)?;
    cmd.arg("true");
    run(&mut cmd).map_err(|_| invalid("не удалось подтвердить SSH-доступ к выбранному серверу"))?;
    // accept-new may write this file before authentication. Consume it only
    // after the authenticated remote command has exited successfully.
    let path = dir.path().join("hosts");
    if fs::metadata(&path)?.len() > 16384 {
        return Err(invalid("неверный файл ключа SSH-хоста"));
    }
    let text = fs::read_to_string(path)?;
    let mut parts = text.split_whitespace();
    let (Some("n2s-awg-peer"), Some(alg), Some(blob), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("не удалось прочитать ключ SSH-хоста"));
    };
    Ok(format!("{alg} {blob}"))
}
#[cfg(target_os = "linux")]
fn fetch(cfg: Value) -> io::Result<Value> {
    use std::time::{Duration, Instant};
    let (_dir, mut cmd) = pinned_command(&cfg)?;
    let iface = s(&cfg, "interface");
    let tool = if cfg["native_vpn_tool"] == "wg" {
        "wg"
    } else {
        "awg"
    };
    cmd.arg(format!("test -d /sys/class/net || exit 1; if ! test -e /sys/class/net/{iface}; then echo down; exit; fi; p=$({tool} show {iface} listen-port) || exit 1; echo \"port $p\"; echo endpoints; {tool} show {iface} endpoints && echo handshakes && {tool} show {iface} latest-handshakes && echo transfer && {tool} show {iface} transfer"));
    let text =
        nfqws2_router_command::output(&mut cmd, Instant::now() + Duration::from_secs(20), 1 << 20)
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => invalid("на роутере не найден OpenSSH-клиент"),
                io::ErrorKind::TimedOut => invalid("время ожидания SSH истекло"),
                _ => invalid("не удалось прочитать статус: проверьте SSH-доступ и ключ хоста"),
            })?;
    parse(&text, &cfg, super::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};
    #[test]
    fn explicit_trust_checks_selection_authentication_pin_and_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let conn = json!({"host":"vpn.test","port":2222,"user":"admin","auth_kind":"password","password":"fixture","known_key":""});
        super::super::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["conn"] = conn.clone();
            Ok(())
        })
        .unwrap();
        let state = State::default();
        let id = "awg0";
        assert!(state
            .trust(&db, "other", |_| panic!("wrong profile"))
            .is_err());
        assert!(state
            .trust(&db, id, |_| Err(invalid("authentication failed")))
            .is_err());
        let pin = format!("ssh-ed25519 {}", Base64::encode_string(&[2; 32]));
        assert!(state
            .trust(&db, id, |_| {
                super::super::edit_document(&db, |doc| {
                    doc["servers"][0]["config"]["conn"]["port"] = json!(22);
                    Ok(())
                })?;
                Ok(pin.clone())
            })
            .is_err());
        assert_eq!(
            active(&read(&db).unwrap()).unwrap()["config"]["conn"]["known_key"],
            ""
        );
        assert!(state.trust(&db, id, |_| Ok("invalid".into())).is_err());
        assert_eq!(
            state
                .trust(&db, id, |cfg| {
                    assert_eq!(cfg["conn"]["port"], 22);
                    assert!(state
                        .trust(&db, id, |_| panic!("concurrent trust"))
                        .is_err());
                    Ok(pin.clone())
                })
                .unwrap()["ok"],
            true
        );
        assert_eq!(
            active(&read(&db).unwrap()).unwrap()["config"]["conn"]["known_key"],
            pin
        );
        assert!(state
            .trust(&db, id, |_| panic!("changed pin must be refused"))
            .is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn openssh_uses_private_key_file_and_promotes_only_authenticated_hosts() {
        use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
        let mut cfg = json!({"interface":"wg0","conn":{"host":"owned.test","port":2222,"user":"admin","auth_kind":"password","password":"fixture"}});
        assert!(pinned_command(&cfg).is_err());
        let key = format!("ssh-ed25519 {}", Base64::encode_string(&[7; 32]));
        for success in [false, true] {
            let mut root = PathBuf::new();
            let result = learn_with(&cfg, |cmd| {
                let args: Vec<_> = cmd.get_args().map(|s| s.to_str().unwrap()).collect();
                assert!(args.contains(&"StrictHostKeyChecking=accept-new"));
                assert!(args.ends_with(&["--", "owned.test", "true"]));
                assert!(!args.contains(&"fixture"));
                let file = PathBuf::from(
                    args.iter()
                        .find_map(|v| v.strip_prefix("UserKnownHostsFile="))
                        .unwrap(),
                );
                root = file.parent().unwrap().to_owned();
                assert_eq!(fs::metadata(&file)?.permissions().mode() & 0o777, 0o600);
                fs::write(file, format!("n2s-awg-peer {key}\n"))?;
                if success {
                    Ok(())
                } else {
                    Err(invalid("fixture password denied"))
                }
            });
            assert!(!root.exists());
            if success {
                assert_eq!(result.unwrap(), key);
            } else {
                assert!(!result.unwrap_err().to_string().contains("password"));
            }
        }
        cfg["conn"]["known_key"] = json!(key);
        let (dir, cmd) = pinned_command(&cfg).unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_str().unwrap()).collect();
        assert!(args.contains(&"StrictHostKeyChecking=yes"));
        assert!(args.ends_with(&["--", "owned.test"]));
        assert_eq!(
            fs::read_to_string(dir.path().join("hosts")).unwrap(),
            format!("n2s-awg-peer {key}\n")
        );
    }
    #[test]
    fn public_server_fields_are_mapped_without_private_dump() {
        let pubkey = Base64::encode_string(&[17; 32]);
        let cfg = json!({"peers":[{"id":"test","name":"work","public_key":pubkey}]});
        let text=format!("port 7711\nendpoints\n{pubkey}\t192.0.2.8:22\nhandshakes\n{pubkey}\t170\ntransfer\n{pubkey}\t1000000001\t23\n");
        let st = parse(&text, &cfg, 171).unwrap();
        assert_eq!(st["peers"][0]["name"], "work");
        assert_eq!(st["peers"][0]["rx_bytes"], 1000000001);
        assert_eq!(st["peers"][0]["online"], true);
        assert_eq!(
            parse(&text, &cfg, 350).unwrap()["peers"][0]["online"],
            false
        );
        assert_eq!(parse("down", &cfg, 2).unwrap()["reachable"], true);
        assert!(parse("port 7\nendpoints\nnot-a-key x", &cfg, 2).is_err());
    }
    #[test]
    fn read_only_refresh_uses_selected_identity_and_deduplicates_work() {
        use std::time::Duration;

        let state = State::default();
        let pin = format!("ssh-ed25519 {}", Base64::encode_string(&[11; 32]));
        let row = json!({"id":"srv","config":{"install":"apt","interface":"awg0","conn":{"host":"router.test","user":"root","known_key":pin},"peers":[{"private_key":"hidden","psk":"hidden"}]}});
        let mut other_id = row.clone();
        other_id["id"] = json!("new-id");
        let mut other_owner = row.clone();
        let replacement_pin = format!("ssh-ed25519 {}", Base64::encode_string(&[12; 32]));
        other_owner["config"]["conn"]["known_key"] = json!(replacement_pin);
        let cold = json!({
            "ok":true,"status":{"reachable":false,"up":false,"listen_port":0,"peers":null}
        });
        let measured = json!({"reachable":true,"up":true,"listen_port":42,"peers":[]});
        let first = measured.clone();
        let (started, ack) = std::sync::mpsc::channel();
        let (finish, rx) = std::sync::mpsc::channel();
        assert_eq!(
            state
                .refresh(&row, move |task| {
                    assert!(!task["peers"].to_string().contains("hidden"));
                    started.send(()).unwrap();
                    rx.recv().unwrap();
                    Ok(first)
                })
                .unwrap(),
            cold
        );
        ack.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::scope(|scope| {
            for request in [&row, &other_id, &other_owner].into_iter().cycle().take(9) {
                let state = &state;
                let cold = &cold;
                scope.spawn(move || {
                    let response = state
                        .refresh(request, |_| panic!("duplicate request"))
                        .unwrap();
                    assert_eq!(&response, cold);
                });
            }
        });
        finish.send(()).unwrap();
        state.join().unwrap();
        assert_eq!(state.status(&row), Some(measured.clone()));
        assert!(state.status(&other_id).is_none());
        assert!(state.status(&other_owner).is_none());

        let (started, ack) = std::sync::mpsc::channel();
        let (finish, rx) = std::sync::mpsc::channel();
        assert_eq!(
            state
                .refresh(&other_owner, move |task| {
                    assert_eq!(task["conn"]["known_key"], replacement_pin);
                    started.send(()).unwrap();
                    rx.recv().unwrap();
                    Err(io::Error::other("fixture status failure"))
                })
                .unwrap(),
            cold
        );
        ack.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            state
                .refresh(&row, |_| panic!("duplicate request"))
                .unwrap(),
            json!({"ok":true,"status":measured})
        );
        assert_eq!(
            state
                .refresh(&other_id, |_| panic!("duplicate request"))
                .unwrap(),
            cold
        );
        finish.send(()).unwrap();
        state.join().unwrap();
        assert!(state.status(&row).is_none());
        assert_eq!(
            state.status(&other_owner).unwrap()["error"],
            "fixture status failure"
        );
        assert!(state.status(&other_id).is_none());
        other_owner["config"]["interface"] = json!("awg0;invalid");
        assert!(validate(&other_owner["config"]).is_err());
    }
}
