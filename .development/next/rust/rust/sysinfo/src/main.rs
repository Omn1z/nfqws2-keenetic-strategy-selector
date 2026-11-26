use nfqws2_core::SystemSampler;
use std::{env, io, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| "/proc".into());
    if args.next().is_some() {
        eprintln!("usage: nfqws2-sysinfo [proc-directory]");
        return ExitCode::from(2);
    }
    let result = SystemSampler::new(root)
        .snapshot()
        .and_then(|stats| stats.write_json(&mut io::stdout().lock()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nfqws2-sysinfo: {err}");
            ExitCode::FAILURE
        }
    }
}
