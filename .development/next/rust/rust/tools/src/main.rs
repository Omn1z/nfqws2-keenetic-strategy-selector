use std::{env, ffi::OsStr, path::Path, process::ExitCode};

fn worker(executable: &Path) -> Option<fn() -> ExitCode> {
    let name = executable.file_name().and_then(OsStr::to_str)?;
    #[cfg(windows)]
    let name = name.strip_suffix(".exe").unwrap_or(name);
    Some(match name {
        "nfqws2-runs" => nfqws2_runs::cli,
        "nfqws2-blockcheck" => nfqws2_blockcheck::cli,
        "nfqws2-strategies" => nfqws2_strategies::cli,
        "nfqws2-geo" => nfqws2_geo::cli,
        _ => return None,
    })
}

fn main() -> ExitCode {
    let executable = env::args_os().next().unwrap_or_default();
    match worker(Path::new(&executable)) {
        Some(run) => run(),
        None => {
            eprintln!("Use the installed nfqws2-runs, nfqws2-blockcheck, nfqws2-strategies or nfqws2-geo command");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_known_installed_names_dispatch() {
        for name in ["runs", "blockcheck", "strategies", "geo"] {
            assert!(worker(
                &Path::new("modules")
                    .join(name)
                    .join(format!("nfqws2-{name}"))
            )
            .is_some());
        }
        for name in ["nfqws2-tools", "geo", "nfqws2-tgws", "nfqws2-geo.old"] {
            assert!(worker(Path::new(name)).is_none());
        }
    }
}
