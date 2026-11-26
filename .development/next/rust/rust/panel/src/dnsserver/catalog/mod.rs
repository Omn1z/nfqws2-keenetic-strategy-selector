//! A list is fetched and kept in memory only while that source is selected.
mod fetch;
mod index;
#[cfg(test)]
mod tests;
use super::runtime::Engine;
pub(super) use index::{Index, Verdict};
use nfqws2_store::Store;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Seek},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant, SystemTime},
};
use tempfile::TempPath;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::{watch, Notify};

const CACHE: &str = "adguard-dns.txt";
const METADATA: &str = "dns-blocklists/metadata.json";
const DAY: Duration = Duration::from_secs(86400);
const RETRY: Duration = Duration::from_secs(120);
#[derive(Default)]
pub(super) struct Feed {
    state: RwLock<State>,
    notify: Notify,
    started: AtomicBool,
    restored: watch::Sender<bool>,
}
#[derive(Default)]
struct State {
    index: Option<Arc<Index>>,
    fingerprint: Option<[u8; 32]>,
    modified: Option<SystemTime>,
    updating: bool,
    queued: bool,
    error: String,
    previous: usize,
}
#[derive(Default)]
pub(super) struct Status {
    pub rules: usize,
    pub ignored: usize,
    pub updated: String,
    pub error: String,
    pub updating: bool,
    previous_rules: usize,
}
fn timestamp(t: SystemTime) -> String {
    OffsetDateTime::from(t).format(&Rfc3339).unwrap_or_default()
}
pub(super) fn saved(store: &Store) -> Status {
    let metadata = store
        .read_limited::<serde_json::Value>(METADATA, 64 * 1024)
        .unwrap_or_default();
    let item = &metadata["adguard-dns"];
    Status {
        previous_rules: item["previous_rules"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or_default(),
        rules: item["rules"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or_default(),
        updated: item["last_updated"].as_str().unwrap_or_default().to_owned(),
        error: item["last_error"].as_str().unwrap_or_default().to_owned(),
        ..Status::default()
    }
}
impl Feed {
    #[cfg(test)]
    pub(super) fn restore_fixture(&self, dir: &Path, store: &Store) -> io::Result<()> {
        self.restore(dir, store)
    }

    pub fn snapshot(&self) -> Option<Arc<Index>> {
        self.state.read().unwrap().index.clone()
    }
    pub(super) fn try_snapshot(&self) -> Option<Option<Arc<Index>>> {
        self.state.try_read().ok().map(|state| state.index.clone())
    }
    pub async fn query_snapshot(&self) -> Option<Arc<Index>> {
        // On restart, the first DNS query must see the locally saved list.
        // A missing file releases queries immediately, before network I/O.
        if !*self.restored.borrow() {
            self.restored
                .subscribe()
                .wait_for(|ready| *ready)
                .await
                .ok()?;
        }
        self.snapshot()
    }
    pub fn status(&self) -> Status {
        let s = self.state.read().unwrap();
        Status {
            rules: s.index.as_ref().map_or(0, |v| v.len()),
            ignored: s.index.as_ref().map_or(0, |v| v.ignored),
            updated: s.modified.map(timestamp).unwrap_or_default(),
            error: s.error.clone(),
            updating: s.updating || s.queued,
            previous_rules: s.previous,
        }
    }
    pub fn request(&self) {
        let mut s = self.state.write().unwrap();
        if !s.updating && !s.queued {
            s.queued = true;
            self.notify.notify_one();
        }
    }
    fn begin(&self, last: Option<Instant>) -> bool {
        let mut s = self.state.write().unwrap();
        let due = s
            .modified
            .is_none_or(|t| t.elapsed().map_or(true, |age| age >= DAY));
        if !s.queued && (!due || last.is_some_and(|t| t.elapsed() < RETRY)) {
            return false;
        }
        s.queued = false;
        s.updating = true;
        true
    }
    fn restore(&self, dir: &Path, store: &Store) -> io::Result<()> {
        ensure_directory(dir)?;
        let saved = saved(store);
        let previous = saved.rules;
        self.state.write().unwrap().previous = previous;
        let path = dir.join(CACHE);
        let meta = match path.symlink_metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            r => r?,
        };
        if !meta.is_file() || meta.len() > index::LIMIT as u64 {
            return Err(io::Error::other("неверный формат сохранённого списка DNS"));
        }
        let (file, fingerprint) = catalog_file(&path)?;
        let decoded = Index::read(BufReader::new(file))?;
        // The previous count identifies the old complete file if power failed
        // between committing the small metadata document and renaming the list.
        validate(
            &decoded,
            if decoded.len() == saved.previous_rules {
                saved.previous_rules
            } else {
                previous
            },
        )?;
        let mut s = self.state.write().unwrap();
        s.modified = (saved.rules == decoded.len())
            .then(|| {
                OffsetDateTime::parse(&saved.updated, &Rfc3339)
                    .ok()
                    .map(SystemTime::from)
            })
            .flatten()
            .or_else(|| meta.modified().ok());
        s.index = Some(Arc::new(decoded));
        s.fingerprint = Some(fingerprint);
        Ok(())
    }
    fn install(
        &self,
        staged: TempPath,
        dir: &Path,
        store: &Store,
        stop: &watch::Receiver<bool>,
    ) -> io::Result<bool> {
        let (file, fingerprint) = catalog_file(&staged)?;
        let existing = {
            let s = self.state.read().unwrap();
            s.index
                .clone()
                .filter(|_| s.fingerprint == Some(fingerprint))
        };
        let candidate = if let Some(existing) = existing {
            drop(file);
            existing
        } else {
            Arc::new(Index::read(BufReader::new(file))?)
        };
        let now = SystemTime::now();
        store.transaction(|tx| {
            // The service synchronously signals this watch before starting its
            // successor. Guard only the commit, never the download or parsing.
            if *stop.borrow() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let (existing, prior) = {
                let state = self.state.read().unwrap();
                (
                    state.index.clone().filter(|_| state.fingerprint == Some(fingerprint)),
                    state.index.as_ref().map_or(state.previous, |index| index.len()),
                )
            };
            let changed = existing.is_none();
            let decoded = existing.unwrap_or(candidate);
            validate(&decoded, prior)?;
            let original=match store.read_limited::<serde_json::Value>(METADATA,64*1024){
                Ok(value) if value.is_object()=>Some(value),
                Ok(_)=>return Err(io::Error::new(io::ErrorKind::InvalidData,"повреждены метаданные каталога DNS")),
                Err(e) if e.kind()==io::ErrorKind::NotFound=>None,
                Err(e)=>return Err(e),
            };
            let mut meta=original.clone().unwrap_or_else(||serde_json::json!({}));
            meta["adguard-dns"]=serde_json::json!({
                "rules":decoded.len(),"previous_rules":prior,"last_updated":timestamp(now),"last_error":""
            });
            tx.save(METADATA,&meta)?;
            let stopped=stop.borrow();
            let publication=if *stopped {Err(io::Error::from(io::ErrorKind::Interrupted))} else {
                staged.persist(dir.join(CACHE)).map_err(io::Error::other)
            };
            if let Err(error)=publication{
                drop(stopped);
                let rollback=match original { Some(previous)=>tx.save(METADATA,&previous), None=>tx.delete(METADATA) };
                rollback.map_err(|e|io::Error::other(format!("{error}; восстановление метаданных DNS: {e}")))?;
                return Err(error);
            }
            {
                let mut state = self.state.write().unwrap();
                state.index = Some(decoded.clone());
                state.fingerprint = Some(fingerprint);
                state.modified = Some(now);
                state.previous = decoded.len();
            }
            drop(stopped);
            #[cfg(unix)]
            File::open(dir)?.sync_all()?;
            Ok(changed)
        })
    }

    fn publish_download(
        &self,
        staged: TempPath,
        dir: &Path,
        store: &Store,
        stop: &watch::Receiver<bool>,
        cache: &nfqws2_dns::Resolver,
    ) -> io::Result<()> {
        if self.install(staged, dir, store, stop)? {
            cache.clear();
        }
        Ok(())
    }
}
fn catalog_file(path: &Path) -> io::Result<(File, [u8; 32])> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let limit = index::LIMIT as u64;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(io::Error::other("неверный формат списка DNS"));
    }
    let mut content = (&mut file).take(limit + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = content.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    if content.limit() == 0 {
        return Err(io::Error::other("превышен размер списка DNS"));
    }
    file.rewind()?;
    Ok((file, hash.finalize().into()))
}
fn ensure_directory(dir: &Path) -> io::Result<()> {
    match fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.symlink_metadata()?.is_dir() => {
            Ok(())
        }
        Err(e) => Err(e),
    }
}
fn validate(index: &Index, previous: usize) -> io::Result<()> {
    let n = index.len();
    if n < 1000 || n < previous / 2 {
        return Err(io::Error::other(format!(
            "подозрительно мало правил DNS: {n} (ранее {previous})"
        )));
    }
    Ok(())
}
pub(super) fn start(engine: &Arc<Engine>, dir: &Path, store: &Store) {
    let Some(feed) = engine.filter.as_ref().and_then(|f| f.feed.clone()) else {
        return;
    };
    if feed.started.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut stop = engine.stopped.subscribe();
    let engine = Arc::downgrade(engine);
    let catalog = dir.to_path_buf();
    let store = store.clone();
    tokio::spawn(async move {
        let (f, d, s) = (feed.clone(), catalog.clone(), store.clone());
        let loaded = tokio::task::spawn_blocking(move || f.restore(&d, &s)).await;
        if let Err(e) = loaded.map_err(io::Error::other).and_then(|v| v) {
            feed.state.write().unwrap().error = e.to_string();
        }
        feed.restored.send_replace(true);
        let mut last = None;
        loop {
            if *stop.borrow() {
                return;
            }
            if feed.begin(last) {
                let Some(engine) = engine.upgrade() else {
                    return;
                };
                let guard = stop.clone();
                let update = refresh(&engine, &feed, &catalog, &store, &guard);
                let result = tokio::select! {biased; _=stop.changed()=>return,r=update=>r};
                let mut s = feed.state.write().unwrap();
                s.updating = false;
                s.error = result.err().map(|e| e.to_string()).unwrap_or_default();
                last = Some(Instant::now());
            }
            tokio::select! {biased;_=stop.changed()=>return,_=feed.notify.notified()=>{},_=tokio::time::sleep(Duration::from_secs(60))=>{}}
        }
    });
}
async fn refresh(
    e: &Arc<Engine>,
    feed: &Arc<Feed>,
    dir: &Path,
    store: &Store,
    stop: &watch::Receiver<bool>,
) -> io::Result<()> {
    ensure_directory(dir)?;
    let staged = tokio::time::timeout(Duration::from_secs(90), fetch::download(e, dir))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let (engine, feed, dir, store, stop) = (
        e.clone(),
        feed.clone(),
        dir.to_path_buf(),
        store.clone(),
        stop.clone(),
    );
    tokio::task::spawn_blocking(move || {
        feed.publish_download(staged, &dir, &store, &stop, &engine.cache)
    })
    .await
    .map_err(io::Error::other)?
}
