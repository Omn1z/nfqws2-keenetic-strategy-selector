mod args;
mod diagnostics;
mod transport;

use args::{flags, invalid, Connection, USAGE};
use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::Path,
    process::{ExitCode, ExitStatus, Stdio},
    time::Duration,
};

fn succeeded(status: ExitStatus, action: &str) -> io::Result<()> {
    if status.success() {
        return Ok(());
    }
    let rc = status
        .code()
        .map_or_else(|| "signal".into(), |c| c.to_string());
    Err(io::Error::other(format!(
        "{action} exited with status {rc}"
    )))
}

fn exec(cfg: &Connection, args: &[String]) -> io::Result<()> {
    let mut duration = Duration::from_secs(60);
    let args = flags(args, |key, val| {
        if key != "timeout" {
            return Err(invalid("unknown exec option"));
        }
        duration = args::timeout(val)?;
        Ok(())
    })?;
    let [command] = args else {
        return Err(invalid("usage: router-ssh exec [--timeout 60s] <command>"));
    };
    succeeded(
        cfg.run(command, Stdio::null(), Stdio::inherit(), duration)?,
        "remote command",
    )
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn remote_path(path: &str) -> String {
    if path.starts_with('-') {
        format!("./{path}")
    } else {
        path.to_owned()
    }
}

fn upload(cfg: &Connection, args: &[String]) -> io::Result<()> {
    let mut mode = "0644".to_owned();
    let args = flags(args, |key, val| {
        if key != "mode" {
            return Err(invalid("unknown upload option"));
        }
        mode = val.to_owned();
        Ok(())
    })?;
    let [local, remote] = args else {
        return Err(invalid(
            "usage: router-ssh upload [--mode 0755] <local> <remote>",
        ));
    };
    let path = remote_path(remote);
    let (dir, base) = path.rsplit_once('/').unwrap_or((".", &path));
    let dir = if dir.is_empty() { "/" } else { dir };
    if base.is_empty() || base == "." || base == ".." {
        return Err(invalid("expected a remote file path"));
    }
    let src = File::open(local)?;
    let bytes = src.metadata()?.len();
    let tmpl = quote(&format!(
        "{}/.{base}.upload.XXXXXX",
        dir.trim_end_matches('/')
    ));
    let dir = quote(dir);
    let dst = quote(&path);
    let mode = quote(&mode);
    // -T preserves raw bytes. Length verification prevents a disconnected
    // input stream from publishing a partial replacement on the router.
    let command = format!(
        r#"set -e; mkdir -p {dir}; tmp=$(mktemp {tmpl}); trap 'rm -f "$tmp"' 0; trap 'exit 1' HUP INT TERM; cat > "$tmp"; [ "$(wc -c < "$tmp")" -eq {bytes} ]; chmod -- {mode} "$tmp"; [ ! -d {dst} ]; mv -f "$tmp" {dst}"#
    );
    succeeded(
        cfg.run(
            &command,
            src.into(),
            Stdio::inherit(),
            Duration::from_secs(180),
        )?,
        "remote upload command",
    )?;
    println!("uploaded {local} -> {remote} ({bytes} bytes)");
    Ok(())
}

fn download(cfg: &Connection, args: &[String]) -> io::Result<()> {
    let args = flags(args, |_, _| Err(invalid("unknown download option")))?;
    let [remote, local] = args else {
        return Err(invalid("usage: router-ssh download <remote> <local>"));
    };
    let dest = Path::new(local);
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o644));
    }
    let stage = builder.prefix(".router-ssh-").tempfile_in(dir)?;
    if let Ok(previous) = dest.metadata() {
        stage.as_file().set_permissions(previous.permissions())?;
    }
    let command = format!("cat {}", quote(&remote_path(remote)));
    succeeded(
        cfg.run(
            &command,
            Stdio::null(),
            stage.as_file().try_clone()?.into(),
            Duration::from_secs(120),
        )?,
        "remote download command",
    )?;
    let bytes = stage.as_file().metadata()?.len();
    stage.persist(dest)?;
    println!("downloaded {remote} -> {local} ({bytes} bytes)");
    Ok(())
}

fn diagnose(cfg: &Connection, args: &[String]) -> io::Result<()> {
    let mut only = Vec::new();
    let args = flags(args, |key, val| {
        if key != "only" {
            return Err(invalid("unknown diagnose option"));
        }
        only = val
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(())
    })?;
    only.extend_from_slice(args);
    let mut first_error = None;
    for &(name, command) in diagnostics::SECTIONS {
        if !only.is_empty() && !only.iter().any(|item| item == name) {
            continue;
        }
        println!("\n===== {name} =====");
        io::stdout().flush()?;
        let result = cfg
            .run(
                command,
                Stdio::null(),
                Stdio::inherit(),
                Duration::from_secs(60),
            )
            .and_then(|status| succeeded(status, name));
        if let Err(err) = result {
            first_error.get_or_insert(err);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn run(args: &[String]) -> io::Result<()> {
    if let Some(result) = transport::password_prompt(args) {
        return result;
    }
    if matches!(args, [s] if matches!(s.as_str(), "--help" | "-h" | "-help")) {
        println!("{USAGE}");
        return Ok(());
    }
    let (cfg, cmd, rest) = args::connection(args)?;
    match cmd {
        "exec" => exec(&cfg, rest),
        "upload" => upload(&cfg, rest),
        "download" => download(&cfg, rest),
        "diagnose" => diagnose(&cfg, rest),
        _ => Err(invalid(USAGE)),
    }
}

fn main() -> ExitCode {
    let args = env::args_os()
        .skip(1)
        .map(|s| {
            s.into_string()
                .map_err(|_| invalid("argument is not UTF-8"))
        })
        .collect::<io::Result<Vec<_>>>();
    match args.and_then(|args| run(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
