use nfqws2_store::Store;
use std::{
    env,
    io::{self, BufReader, BufWriter, Write},
    path::Path,
    process::ExitCode,
};

fn run() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.first().is_some_and(|v| v == "selftest-catalog") {
        let index = args
            .get(1)
            .and_then(|v| v.to_str())
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| crate::invalid("неверный индекс стратегии"))?;
        let hosts = args
            .into_iter()
            .skip(2)
            .map(|v| {
                v.into_string()
                    .map_err(|_| crate::invalid("неверное имя сервера"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let modules = env::var_os("N2S_MODULE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                nfqws2_config::Resolver::current()
                    .path(nfqws2_config::Key::ModuleDir)
                    .into()
            });
        use std::io::Read;
        let mut catalog = Vec::new();
        std::fs::File::open(modules.join("strategies/catalog.json"))
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    "для selftest установите nfqws2-strategy-strategies",
                )
            })?
            .take(65537)
            .read_to_end(&mut catalog)?;
        if catalog.len() > 65536 {
            return Err(crate::invalid("слишком большой каталог стратегий"));
        }
        let (cfg, _) = nfqws2_config::Config::load("", "");
        let reply = crate::matrix::selftest::run(&cfg, &catalog, index, hosts)?;
        serde_json::to_writer_pretty(io::stdout().lock(), &reply)?;
        println!();
        return Ok(());
    }
    if args.len() == 1 && args[0] == "recover-matrix" {
        return crate::matrix::recover();
    }
    if args.first().is_some_and(|v| v == "selftest") {
        let hosts = args
            .into_iter()
            .skip(1)
            .map(|v| {
                v.into_string()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hostname"))
            })
            .collect::<io::Result<_>>()?;
        serde_json::to_writer_pretty(io::stdout().lock(), &crate::measure::selftest(hosts)?)?;
        println!();
        return Ok(());
    }
    let usage = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected history DATA_DIR [LIVE_ID LIVE_DIR] | get DATA_DIR ID [LIVE_ID LIVE_DIR] | save DATA_DIR | measure DATA_DIR ID LIVE_DIR",
        )
    };
    let [verb, dir, ..] = args.as_slice() else {
        return Err(usage());
    };
    let verb = verb.to_str().ok_or_else(usage)?;
    let mut stdout = BufWriter::new(io::stdout().lock());
    match (verb, &args[2..]) {
        ("measure-matrix", [id, live]) => {
            return crate::matrix::run(
                Path::new(dir),
                id.to_str().ok_or_else(usage)?,
                Path::new(live),
            )
        }
        ("measure", [id, live]) => {
            return crate::measure::run(
                Path::new(dir),
                id.to_str().ok_or_else(usage)?,
                Path::new(live),
            )
        }
        ("history", [id, live]) => crate::write_history_with_live(
            &Store::open(dir)?,
            &mut stdout,
            Some((id.to_str().ok_or_else(usage)?, Path::new(live))),
        )?,
        ("get", [id, active, live]) => serde_json::to_writer(
            &mut stdout,
            &crate::get_with_live(
                &Store::open(dir)?,
                id.to_str().ok_or_else(usage)?,
                Some((active.to_str().ok_or_else(usage)?, Path::new(live))),
            )?,
        )?,
        ("history", []) => crate::write_history(&Store::open(dir)?, &mut stdout)?,
        ("get", [id]) => {
            let run = crate::get(&Store::open(dir)?, id.to_str().ok_or_else(usage)?)?;
            serde_json::to_writer(&mut stdout, &run)?;
        }
        ("save", []) => {
            let mut report = serde_json::from_reader(BufReader::new(io::stdin().lock()))?;
            crate::save_completed(&Store::open(dir)?, &mut report)?;
        }
        _ => return Err(usage()),
    }
    stdout.flush()
}
pub fn cli() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(match e.kind() {
                io::ErrorKind::InvalidInput => 2,
                io::ErrorKind::Interrupted => 130,
                io::ErrorKind::NotFound => 4,
                _ => 1,
            })
        }
    }
}
