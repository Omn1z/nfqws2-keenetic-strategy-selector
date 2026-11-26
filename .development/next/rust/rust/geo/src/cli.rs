use crate::{process, Kind, Query};
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

const USAGE: &str = "nfqws2-geo list <geosite|geoip|text> <file>\n\
nfqws2-geo extract|extract-checked <geosite|geoip|text> <file> <category> [limit]";

fn arguments(args: &[OsString]) -> Option<(Kind, &OsString, Query)> {
    let [op, kind, file, rest @ ..] = args else {
        return None;
    };
    let kind = match kind.to_str()? {
        "geosite" => Kind::Site,
        "geoip" => Kind::Ip,
        "text" => Kind::Text,
        _ => return None,
    };
    let query = match (op.to_str()?, rest) {
        ("list", []) => Query::List,
        (action @ ("extract" | "extract-checked"), [category, tail @ ..]) => {
            let limit = match tail {
                [] => 0,
                [value] => value.to_str()?.parse().ok()?,
                _ => return None,
            };
            let category = category.to_str()?.to_owned();
            if action == "extract-checked" {
                Query::ExtractChecked { category, limit }
            } else {
                Query::Extract { category, limit }
            }
        }
        _ => return None,
    };
    Some((kind, file, query))
}

fn run(kind: Kind, path: &OsString, query: Query) -> io::Result<bool> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular geo file",
        ));
    }
    let mut out = BufWriter::new(io::stdout().lock());
    let found = process(file, metadata.len(), kind, query, &mut out)?;
    out.flush()?;
    Ok(found)
}

pub fn cli() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some((kind, file, query)) = arguments(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match run(kind, file, query) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("category not found");
            ExitCode::from(3)
        }
        Err(err) => {
            eprintln!("geo: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
