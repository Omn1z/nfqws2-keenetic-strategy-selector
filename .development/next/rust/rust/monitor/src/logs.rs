use serde::Serialize;
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_ENTRIES: usize = 2000;
const MAX_MESSAGE: usize = 2000;
const PROXY_LIMIT: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub t: i64,
    pub module: String,
    pub level: String,
    pub msg: String,
}
#[derive(Debug, Serialize)]
pub struct Logs {
    pub entries: Vec<Entry>,
    pub modules: Option<Vec<String>>,
}

fn proxy(module: &str) -> bool {
    matches!(module, "proxy" | "socks5" | "tgws")
}

fn module_of(line: &str) -> &'static str {
    for (prefix, module) in [
        ("tgws:", "tgws"),
        ("socks5:", "socks5"),
        ("proxy:", "proxy"),
        ("trace", "trace"),
        ("run:", "run"),
        ("blockcheck", "blockcheck"),
        ("dns:", "dns"),
        ("update", "update"),
        ("selfupdate", "update"),
    ] {
        if line.starts_with(prefix) {
            return module;
        }
    }
    if ["GET /", "POST /", "PUT /", "DELETE /", "PATCH /"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
    {
        "http"
    } else {
        "system"
    }
}

// Infer severity from the whole line, even when the displayed message is
// truncated. Keep only its prefix and the overlap needed between input chunks.
const OVERLAP: usize = b"fake-tls verify failed -> masking".len() - 1;
#[derive(Default)]
struct Keywords {
    proxy_error: bool,
    proxy_info: bool,
    proxy_warn: bool,
    error: bool,
    warn: bool,
}
#[derive(Default)]
struct Line {
    prefix: Vec<u8>,
    search: Vec<u8>,
    words: Keywords,
    nonblank: bool,
}

impl Line {
    fn push(&mut self, data: &[u8]) {
        let keep = (MAX_MESSAGE - self.prefix.len()).min(data.len());
        self.prefix.extend_from_slice(&data[..keep]);
        for piece in data.chunks(MAX_MESSAGE) {
            self.nonblank |= !String::from_utf8_lossy(piece).trim().is_empty();
            self.search.extend_from_slice(piece);
            self.search.make_ascii_lowercase();
            let has = |word: &[u8]| self.search.windows(word.len()).any(|w| w == word);
            let k = &mut self.words;
            k.proxy_error = k.proxy_error
                || has(b"autostart:")
                || has(b"no fallback available")
                || has(b"mtproto transport error");
            k.proxy_info =
                k.proxy_info || has(b"session closed") || has(b"fake-tls verify failed -> masking");
            k.proxy_warn = k.proxy_warn || has(b"bad handshake");
            k.error = k.error || has(b"panic") || has(b"fatal") || has(b"error") || has(b"fail");
            k.warn = k.warn || has(b"warn");
            if self.search.len() > OVERLAP {
                let from = self.search.len() - OVERLAP;
                self.search.copy_within(from.., 0);
                self.search.truncate(OVERLAP);
            }
        }
    }

    fn level(&self, module: &str) -> &'static str {
        if proxy(module) {
            if self.words.proxy_error {
                return "error";
            }
            if self.words.proxy_info {
                return "info";
            }
            if self.words.proxy_warn {
                return "warn";
            }
        }
        if self.words.error {
            "error"
        } else if self.words.warn {
            "warn"
        } else {
            "info"
        }
    }
    fn clear(&mut self) {
        self.prefix.clear();
        self.search.clear();
        self.words = Keywords::default();
        self.nonblank = false;
    }
}

struct Output {
    common: Box<dyn Write + Send>,
    proxy: Option<PathBuf>,
}

pub struct LogBuffer {
    enabled: AtomicBool,
    entries: Mutex<VecDeque<Entry>>,
    output: Mutex<Output>,
    partial: Mutex<Line>,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new(Box::new(io::sink()), None)
    }
}

impl LogBuffer {
    pub fn new(writer: Box<dyn Write + Send>, proxy_log: Option<PathBuf>) -> Self {
        if let Some(path) = &proxy_log {
            if let Ok(mut f) = open_proxy(path, false) {
                let _ = retain_tail(&mut f, PROXY_LIMIT);
            }
        }
        Self {
            enabled: AtomicBool::new(true),
            entries: Mutex::new(VecDeque::new()),
            output: Mutex::new(Output {
                common: writer,
                proxy: proxy_log,
            }),
            partial: Mutex::new(Line::default()),
        }
    }
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    pub fn append(&self, module: &str, level: &str, msg: &str) {
        if !self.enabled() || (proxy(module) && !matches!(level, "warn" | "error")) {
            return;
        }
        let msg = msg.trim_end_matches('\n');
        if msg.is_empty() {
            return;
        }
        let msg = String::from_utf8_lossy(&msg.as_bytes()[..msg.len().min(MAX_MESSAGE)]);
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        {
            let mut ring = self.entries.lock().unwrap();
            if ring.len() == MAX_ENTRIES {
                ring.pop_front();
            }
            ring.push_back(Entry {
                t,
                module: module.to_owned(),
                level: level.to_owned(),
                msg: msg.to_string(),
            });
        }
        let mut out = self.output.lock().unwrap();
        let record = format!("{} [{module}] {msg}\n", timestamp(t / 1000));
        if let Some(path) = out.proxy.as_ref().filter(|_| proxy(module)) {
            let _ = append_proxy(path, record.as_bytes());
        } else {
            let _ = out.common.write_all(record.as_bytes());
        }
    }

    pub fn write_bytes(&self, bytes: &[u8]) {
        if !self.enabled() {
            return;
        }
        let mut line = self.partial.lock().unwrap();
        for part in bytes.split_inclusive(|b| *b == b'\n') {
            if let Some(data) = part.strip_suffix(b"\n") {
                line.push(data);
                if line.nonblank {
                    let text = String::from_utf8_lossy(&line.prefix);
                    let module = module_of(&text);
                    self.append(module, line.level(module), &text);
                }
                line.clear();
            } else {
                line.push(part);
            }
        }
    }

    pub fn snapshot(&self, module: &str, limit: i64) -> Logs {
        let ring = self.entries.lock().unwrap();
        let limit = if limit > 0 {
            usize::try_from(limit).unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        let mut entries: Vec<_> = ring
            .iter()
            .rev()
            .filter(|e| module.is_empty() || module == "all" || e.module == module)
            .take(limit)
            .cloned()
            .collect();
        entries.reverse();
        let modules = (!ring.is_empty()).then(|| {
            ring.iter()
                .map(|e| e.module.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect()
        });
        Logs { entries, modules }
    }
}

fn timestamp(seconds: i64) -> String {
    let t = seconds as _;
    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    // Each platform writes to our tm via its thread-safe localtime variant.
    #[cfg(unix)]
    let ok = unsafe { !libc::localtime_r(&t, local.as_mut_ptr()).is_null() };
    #[cfg(windows)]
    let ok = unsafe { libc::localtime_s(local.as_mut_ptr(), &t) == 0 };
    if !ok {
        return seconds.to_string();
    }
    let d = unsafe { local.assume_init() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        d.tm_year + 1900,
        d.tm_mon + 1,
        d.tm_mday,
        d.tm_hour,
        d.tm_min,
        d.tm_sec
    )
}

fn open_proxy(path: &Path, create: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("proxy log path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
}

fn append_proxy(path: &Path, record: &[u8]) -> io::Result<()> {
    if record.len() > PROXY_LIMIT {
        return Err(io::ErrorKind::WriteZero.into());
    }
    let mut file = open_proxy(path, true)?;
    if file.metadata()?.len() > (PROXY_LIMIT - record.len()) as u64 {
        retain_tail(&mut file, (PROXY_LIMIT / 2).min(PROXY_LIMIT - record.len()))?;
    }
    file.seek(SeekFrom::End(0))?;
    file.write_all(record)
}

fn retain_tail(file: &mut File, retain: usize) -> io::Result<()> {
    if file.metadata()?.len() <= retain as u64 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-((retain + 1) as i64)))?;
    let mut bytes = vec![0; retain + 1];
    file.read_exact(&mut bytes)?;
    let start = bytes
        .iter()
        .position(|b| *b == b'\n')
        .map_or(bytes.len(), |i| i + 1);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes[start..])?;
    file.set_len((bytes.len() - start) as u64)
}
