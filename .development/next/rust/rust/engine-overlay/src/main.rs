use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{absolute, Component, Path, PathBuf, MAIN_SEPARATOR_STR};
use std::process::ExitCode;

const USAGE: &str = "nfqws2-engine-overlay -source <pinned checkout> -output <overlay directory>";
const QUEUES: &str = "device/queueconstants_default.go";
const CONN: &str = "conn/conn.go";
const QUEUE_CHANGES: &[(&str, &str)] = &[
    (
        "QueueStagedSize            = conn.IdealBatchSize",
        "QueueStagedSize            = 8",
    ),
    (
        "QueueOutboundSize          = 1024",
        "QueueOutboundSize          = 32",
    ),
    (
        "QueueInboundSize           = 1024",
        "QueueInboundSize           = 32",
    ),
    (
        "QueueHandshakeSize         = 1024",
        "QueueHandshakeSize         = 128",
    ),
    (
        "import \"github.com/amnezia-vpn/amneziawg-go/v3/conn\"\n",
        "",
    ),
];
const APPENDED_TESTS: &[(&str, &[u8])] = &[
    (
        "conn/bind_std_test.go",
        include_bytes!("../testdata/conn_memory_tests.go.txt"),
    ),
    (
        "device/device_test.go",
        include_bytes!("../testdata/device_memory_tests.go.txt"),
    ),
];

struct Options {
    source: PathBuf,
    output: PathBuf,
}

fn options(mut args: impl Iterator<Item = OsString>) -> Result<Option<Options>, &'static str> {
    let mut source = None;
    let mut output = None;
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "-help" || arg == "--help" {
            return Ok(None);
        }
        let arg = arg.to_str().ok_or("invalid option")?;
        let (flag, value) = arg
            .split_once('=')
            .map_or((arg, None), |(k, v)| (k, Some(v)));
        let slot = match flag {
            "-source" | "--source" => &mut source,
            "-output" | "--output" => &mut output,
            "--" => break,
            _ if !flag.starts_with('-') => break,
            _ => return Err("unknown option"),
        };
        let path = value
            .map(OsString::from)
            .or_else(|| args.next())
            .ok_or("missing option value")?;
        *slot = Some(PathBuf::from(path));
    }
    Ok(Some(Options {
        source: source
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or("missing -source")?,
        output: output
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or("missing -output")?,
    }))
}

// Resolve existing ancestors first, including symlinks, before creating output.
fn destination(path: &Path) -> io::Result<PathBuf> {
    match path.canonicalize() {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let Some(parent) = path.parent() else {
                return Err(err);
            };
            let parent = destination(parent)?;
            match path.components().next_back() {
                Some(Component::Normal(name)) => Ok(parent.join(name)),
                Some(Component::ParentDir) => Ok(parent.parent().unwrap_or(&parent).to_owned()),
                _ => Err(err),
            }
        }
        result => result,
    }
}

fn read_source(source: &Path, name: &str) -> io::Result<Vec<u8>> {
    fs::read(source.join(name)).map_err(|err| io::Error::new(err.kind(), format!("{name}: {err}")))
}

fn has_original_line(text: &str, expected: &str) -> bool {
    text.matches(expected).count() == 1
        && text.lines().any(|line| {
            let code = line.split_once("//").map_or(line, |(code, _)| code).trim();
            code.strip_prefix("const ").unwrap_or(code) == expected.trim_end()
        })
}

fn patch(source: &Path, name: &str, changes: &[(&str, &str)]) -> io::Result<Vec<u8>> {
    let mut text = String::from_utf8(read_source(source, name)?)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        .replace("\r\n", "\n");
    for &(old, new) in changes {
        if !has_original_line(&text, old) {
            return Err(io::Error::other(format!(
                "{name}: upstream memory constants changed; review the router memory profile"
            )));
        }
        text = text.replacen(old, new, 1);
    }
    Ok(text.into_bytes())
}

fn prepare(options: Options) -> io::Result<PathBuf> {
    // Keep the normal absolute paths in Go's manifest. Windows canonical
    // (verbatim) paths do not match paths in the upstream package loader.
    let source = absolute(options.source)?;
    let output = absolute(options.output)?;
    let canonical_source = source.canonicalize()?;
    let canonical_output = destination(&output)?;
    if canonical_output.starts_with(&canonical_source) {
        return Err(io::Error::other(
            "overlay output must be outside the pinned source checkout",
        ));
    }
    for subdir in ["conn", "device"] {
        let dir = destination(&output.join(subdir))?;
        if !dir.starts_with(&canonical_output) || dir.starts_with(&canonical_source) {
            return Err(io::Error::other(format!(
                "overlay directory {subdir} escapes its output tree"
            )));
        }
    }
    let bind = read_source(&source, "conn/bind_std.go")?;
    if !has_original_line(
        &String::from_utf8_lossy(&bind),
        "udpSegmentMaxDatagrams = 64",
    ) {
        return Err(io::Error::other(
            "upstream UDP segmentation changed; review the router memory profile",
        ));
    }

    let mut files = vec![
        (
            CONN,
            patch(
                &source,
                CONN,
                &[("IdealBatchSize = 128", "IdealBatchSize = 64")],
            )?,
        ),
        (QUEUES, patch(&source, QUEUES, QUEUE_CHANGES)?),
    ];
    for &(name, extra) in APPENDED_TESTS {
        let mut tests = read_source(&source, name)?;
        tests.extend_from_slice(extra);
        files.push((name, tests));
    }
    let replacements: BTreeMap<_, _> = files
        .iter()
        .map(|(name, _)| {
            let native = name.replace('/', MAIN_SEPARATOR_STR);
            (source.join(&native), output.join(&native))
        })
        .collect();
    let mut encoded = serde_json::to_vec_pretty(&BTreeMap::from([("Replace", replacements)]))?;
    encoded.push(b'\n');
    files.push(("overlay.json", encoded));

    // Validate and stage all four inputs before publishing any changes. Each
    // rename replaces the file itself (including any old output symlink).
    // Go discovers the manifest only after all referenced files are present.
    let mut pending = Vec::with_capacity(files.len());
    for (name, data) in files {
        let path = output.join(name);
        let dir = path.parent().expect("fixed overlay filename");
        fs::create_dir_all(dir)?;
        let mut builder = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o644));
        }
        let mut file = builder.prefix(".overlay-").tempfile_in(dir)?;
        file.write_all(&data)?;
        pending.push((file, path));
    }
    for (file, path) in pending {
        file.persist(path)?;
    }
    Ok(output.join("overlay.json"))
}

fn main() -> ExitCode {
    let options = match options(env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match prepare(options) {
        Ok(path) => {
            println!("{}", path.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
