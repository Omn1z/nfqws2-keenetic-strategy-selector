use super::{
    framing, Budget, Failure, H2Terminal, Lane, Reply, PARTIAL_UPLOAD_BYTES, REQUEST_TIME,
};
use crate::{
    crypto::{Cipher, Transport},
    Stats,
};
use bytes::Bytes;
use ctr::cipher::StreamCipher;
use futures_util::{
    future::{AbortHandle, Abortable, BoxFuture},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at, Instant},
};

const UPLOAD_IDLE: Duration = Duration::from_secs(180);
const WAITING_FOR_REQUEST: usize = usize::MAX;
const CHANNEL_BYTES: usize = 8 << 20;
const REPLY_QUEUE: usize = 16;

struct Limits {
    requests: Arc<Semaphore>,
    upload: Arc<Semaphore>,
    download: Arc<Semaphore>,
    waiting: AtomicUsize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: Arc::new(Semaphore::new(8)),
            upload: Arc::new(Semaphore::new(CHANNEL_BYTES)),
            download: Arc::new(Semaphore::new(CHANNEL_BYTES)),
            waiting: AtomicUsize::new(0),
        }
    }
}
struct Upload {
    _channel_bytes: OwnedSemaphorePermit,
    _lane_bytes: OwnedSemaphorePermit,
}
impl Upload {
    async fn reserve(l: &Limits, budget: &Budget, n: usize) -> io::Result<Self> {
        let gone = |_| io::ErrorKind::BrokenPipe;
        Ok(Self {
            _channel_bytes: l
                .upload
                .clone()
                .acquire_many_owned(n as u32)
                .await
                .map_err(gone)?,
            _lane_bytes: budget
                .upload
                .clone()
                .acquire_many_owned(n as u32)
                .await
                .map_err(gone)?,
        })
    }
}
struct Ticket {
    _channel: OwnedSemaphorePermit,
    _lane: OwnedSemaphorePermit,
    _upload: Upload,
}
impl Ticket {
    async fn reserve(l: &Limits, budget: &Budget, upload: Upload) -> io::Result<Self> {
        let gone = |_| io::ErrorKind::BrokenPipe;
        Ok(Self {
            _channel: l.requests.clone().acquire_owned().await.map_err(gone)?,
            _lane: budget
                .requests
                .clone()
                .acquire_owned()
                .await
                .map_err(gone)?,
            _upload: upload,
        })
    }
    fn try_acquire(l: &Limits, lane: &Lane, n: usize) -> Option<Self> {
        let budget = &lane.budget;
        Some(Self {
            _channel: l.requests.clone().try_acquire_owned().ok()?,
            _lane: budget.requests.clone().try_acquire_owned().ok()?,
            _upload: Upload {
                _channel_bytes: l.upload.clone().try_acquire_many_owned(n as u32).ok()?,
                _lane_bytes: budget
                    .upload
                    .clone()
                    .try_acquire_many_owned(n as u32)
                    .ok()?,
            },
        })
    }
}
async fn read_legacy_body(
    reader: &mut (impl AsyncRead + Unpin),
    bytes: &mut [u8],
    partial_uploads: &Semaphore,
) -> io::Result<()> {
    // At most one maximum padded packet or 64 small partial uploads can wait
    // indefinitely at an origin. All allocated bytes also hold its upload quota.
    let charge = bytes.len().max(PARTIAL_UPLOAD_BYTES.div_ceil(64));
    if let Ok(_partial) = partial_uploads.try_acquire_many(charge as u32) {
        reader.read_exact(bytes).await?;
        return Ok(());
    }
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let n = timeout(UPLOAD_IDLE, reader.read(remaining))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        remaining = &mut remaining[n..];
    }
    Ok(())
}
async fn input(
    mut reader: impl AsyncRead + Unpin,
    mut cipher: Cipher,
    tag: u8,
    l: &Limits,
    budget: &Budget,
    tx: mpsc::Sender<(Bytes, Ticket)>,
) -> io::Result<()> {
    loop {
        let n = framing::length(&mut reader, &mut cipher, tag).await?;
        let admission_deadline = Instant::now() + REQUEST_TIME;
        l.waiting.store(n, Ordering::Release);
        let upload = timeout_at(admission_deadline, Upload::reserve(l, budget, n))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        let mut bytes = vec![0; n];
        let deadline = if let Some(partials) = &budget.partial_uploads {
            l.waiting.store(0, Ordering::Release);
            read_legacy_body(&mut reader, &mut bytes, partials).await?;
            Instant::now() + REQUEST_TIME
        } else {
            admission_deadline
        };
        l.waiting.store(WAITING_FOR_REQUEST, Ordering::Release);
        let ticket = timeout_at(deadline, Ticket::reserve(l, budget, upload))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        l.waiting.store(0, Ordering::Release);
        if budget.partial_uploads.is_none() {
            timeout(REQUEST_TIME, reader.read_exact(&mut bytes))
                .await
                .map_err(|_| io::ErrorKind::TimedOut)??;
        }
        cipher.apply_keystream(&mut bytes);
        bytes.truncate(framing::packet_size(&bytes, tag)?);
        tx.send((bytes.into(), ticket))
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
    }
}
struct Entry {
    id: u64,
    body: Bytes,
    created: Instant,
    last: Option<Instant>,
    attempts: u8,
    retired: bool,
    reply_id: Vec<u8>,
}
struct Pending {
    entry: Option<u64>,
    replay: bool,
    start: Instant,
    stage: Arc<AtomicU8>,
    abort: AbortHandle,
}
impl Pending {
    fn rotatable_replay(&self, now: Instant) -> bool {
        self.replay
            && !self.abort.is_aborted()
            && self.stage.load(Ordering::Acquire) == 1
            && now - self.start >= Duration::from_secs(30)
    }
}
#[derive(Clone)]
struct Candidate {
    start: Instant,
    expires: Option<Instant>,
    replay: bool,
    stage: Arc<AtomicU8>,
    abort: AbortHandle,
}
type Offer = std::sync::Mutex<Option<Candidate>>;
#[derive(Default)]
pub(super) struct Retirement(std::sync::Mutex<Vec<std::sync::Weak<Offer>>>);
impl Retirement {
    fn register(&self) -> Arc<Offer> {
        let offer = Arc::new(Offer::default());
        let mut list = self.0.lock().unwrap();
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(&offer));
        offer
    }
    fn make_room(&self, now: Instant) {
        let candidate = self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .filter_map(|v| v.lock().unwrap().clone())
            .filter(|c| {
                !c.abort.is_aborted()
                    && c.stage.load(Ordering::Acquire) == 1
                    && c.expires.is_none_or(|t| now <= t)
            })
            .min_by_key(|c| (!c.replay, c.start));
        if let Some(c) = candidate {
            c.abort.abort();
        }
    }
}
#[derive(Default)]
struct Recovery {
    entries: VecDeque<Entry>,
    pending: BTreeMap<u64, Pending>,
    sequence: u64,
    last_progress: Option<Instant>,
}
impl Recovery {
    fn remember(&mut self, body: &Bytes, now: Instant) -> Option<u64> {
        if body.len() < 24 || body[..8] == [0; 8] {
            return None;
        }
        if self
            .entries
            .back()
            .is_some_and(|e| e.body[..8] != body[..8])
        {
            self.entries.clear();
        }
        if body.len() > 64 << 10 {
            return None;
        }
        if let Some(e) = self.entries.iter().find(|e| e.body == *body) {
            return Some(e.id);
        }
        self.sequence += 1;
        self.entries.push_back(Entry {
            id: self.sequence,
            body: body.clone(),
            created: now,
            last: None,
            attempts: 0,
            retired: false,
            reply_id: vec![],
        });
        while self.entries.len() > 16
            || self.entries.iter().map(|e| e.body.len()).sum::<usize>() > 64 << 10
        {
            let evict = self
                .entries
                .iter()
                .position(|e| {
                    !self.pending.values().any(|p| p.entry == Some(e.id))
                        && !(e.retired
                            && e.attempts < 3
                            && now - e.created <= Duration::from_secs(30))
                })
                .unwrap_or(0);
            self.entries.remove(evict);
        }
        self.entries
            .back()
            .filter(|e| e.id == self.sequence)
            .map(|e| e.id)
    }
    fn candidate(&self, now: Instant) -> Option<Candidate> {
        self.pending
            .values()
            .filter(|p| {
                !p.abort.is_aborted()
                    && p.stage.load(Ordering::Acquire) == 1
                    && now - p.start >= Duration::from_secs(3)
            })
            .filter_map(|p| {
                let expires = if p.replay {
                    None
                } else {
                    let entry = self.entries.iter().find(|e| {
                        Some(e.id) == p.entry
                            && e.attempts < 3
                            && now - e.created <= Duration::from_secs(30)
                    })?;
                    Some(entry.created + Duration::from_secs(30))
                };
                Some(Candidate {
                    start: p.start,
                    expires,
                    replay: p.replay,
                    stage: p.stage.clone(),
                    abort: p.abort.clone(),
                })
            })
            .min_by_key(|c| (!c.replay, c.start))
    }
    fn due(&self, now: Instant) -> Option<u64> {
        let latest = self.entries.back()?.id;
        let mut idle = None;
        for e in &self.entries {
            if e.attempts >= 3
                || now - e.created > Duration::from_secs(30)
                || e.last.is_some_and(|t| now - t < Duration::from_secs(2))
            {
                continue;
            }
            let same = || self.pending.values().filter(|p| p.entry == Some(e.id));
            if same().any(|p| {
                p.stage.load(Ordering::Acquire) == 2 || p.replay && !p.rotatable_replay(now)
            }) {
                continue;
            }
            if e.retired
                || same().any(|p| {
                    !p.replay
                        && p.stage.load(Ordering::Acquire) == 1
                        && now - p.start >= Duration::from_secs(3)
                })
            {
                return Some(e.id);
            }
            if e.id == latest
                && self
                    .pending
                    .values()
                    .all(|p| p.replay && p.entry == Some(e.id))
                && (e.last.is_none()
                    || self
                        .last_progress
                        .is_none_or(|t| now - t >= Duration::from_secs(1)))
            {
                idle = Some(e.id);
            }
        }
        idle
    }
    fn next(&self, now: Instant) -> Option<u64> {
        // An idle long poll may still deliver a reply until the HTTP deadline.
        // Rotate it only when a due request needs this entry or one of the two slots.
        let entry = self.due(now)?;
        let replays = || self.pending.values().filter(|p| p.replay);
        if let Some(p) = replays().find(|p| p.entry == Some(entry)) {
            if p.rotatable_replay(now) {
                p.abort.abort();
            }
            return None;
        }
        if replays().count() >= 2 {
            if let Some(p) = replays()
                .filter(|p| p.rotatable_replay(now))
                .min_by_key(|p| p.start)
            {
                p.abort.abort();
            }
            return None;
        }
        Some(entry)
    }
    fn completed(&mut self, request: u64, reply: Option<&Reply>, now: Instant) {
        let Some(p) = self.pending.remove(&request) else {
            return;
        };
        if !p.replay && p.abort.is_aborted() {
            if let Some(e) = self.entries.iter_mut().find(|e| Some(e.id) == p.entry) {
                e.retired = true;
            }
        }
        if let Some(reply) = reply {
            self.last_progress = Some(now);
            if !reply.data.is_empty() {
                if let Some(e) = self.entries.iter_mut().find(|e| Some(e.id) == p.entry) {
                    let prefix = &reply.data[..reply.data.len().min(24)];
                    if prefix != e.reply_id {
                        e.reply_id = prefix.to_vec();
                        e.attempts = 0;
                    }
                }
            }
        }
    }
}
type Job<'a> = BoxFuture<'a, (u64, Option<Result<Reply, Failure>>)>;
struct Channel<'a> {
    lane: &'a Lane,
    limits: &'a Limits,
    stats: &'a Stats,
    jobs: FuturesUnordered<Job<'a>>,
    recovery: Recovery,
}
impl<'a> Channel<'a> {
    fn start(&mut self, body: Bytes, ticket: Ticket, entry: Option<u64>, replay: bool) {
        let now = Instant::now();
        self.recovery.sequence += 1;
        let id = self.recovery.sequence;
        let (abort, reg) = AbortHandle::new_pair();
        let stage = Arc::new(AtomicU8::new(0));
        self.recovery.pending.insert(
            id,
            Pending {
                entry,
                replay,
                start: now,
                stage: stage.clone(),
                abort,
            },
        );
        self.stats.h2_requests.fetch_add(1, Ordering::Relaxed);
        self.stats
            .up
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        if replay {
            self.stats.h2_replays.fetch_add(1, Ordering::Relaxed);
        }
        let lane = self.lane;
        let down = self.limits.download.clone();
        self.jobs.push(
            async move {
                let _ticket = ticket;
                let run = async {
                    timeout(REQUEST_TIME, lane.post(body, &stage, &down))
                        .await
                        .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut).into()))
                };
                (id, Abortable::new(run, reg).await.ok())
            }
            .boxed(),
        );
    }
    fn recover(&mut self) {
        let now = Instant::now();
        let waiting = self.limits.waiting.load(Ordering::Acquire);
        if waiting > 0 {
            let full = |requests: &Semaphore, upload: &Semaphore| {
                if waiting == WAITING_FOR_REQUEST {
                    requests.available_permits() == 0
                } else {
                    upload.available_permits() < waiting
                }
            };
            if full(&self.limits.requests, &self.limits.upload) {
                if let Some(p) = self.recovery.candidate(now) {
                    p.abort.abort();
                }
            } else if full(&self.lane.budget.requests, &self.lane.budget.upload) {
                self.lane.budget.retirement.make_room(now);
            }
            return;
        }
        // This session is still receiving or delivering another response.
        if self.limits.download.available_permits() < CHANNEL_BYTES {
            return;
        }
        if let Some(id) = self.recovery.next(now) {
            let e = self
                .recovery
                .entries
                .iter_mut()
                .find(|e| e.id == id)
                .unwrap();
            if let Some(ticket) = Ticket::try_acquire(self.limits, self.lane, e.body.len()) {
                e.attempts += 1;
                e.last = Some(now);
                let body = e.body.clone();
                self.start(body, ticket, Some(id), true);
            }
        }
    }
}
async fn write(
    w: &mut (impl AsyncWrite + Unpin),
    cipher: &mut Cipher,
    tag: u8,
    body: &[u8],
    stats: &Stats,
) -> io::Result<()> {
    let mut bytes = framing::frame(body, tag)?;
    cipher.apply_keystream(&mut bytes);
    w.write_all(&bytes).await?;
    stats.down.fetch_add(body.len() as u64, Ordering::Relaxed);
    Ok(())
}

#[derive(Default)]
struct Replies {
    pending: VecDeque<Reply>,
    delivered: Option<Instant>,
}

pub(crate) async fn bridge(
    socket: impl AsyncRead + AsyncWrite + Unpin,
    session: Transport,
    lane: Arc<Lane>,
    stats: &Stats,
    report_transport_error: impl FnOnce(H2Terminal),
) -> io::Result<()> {
    let (r, mut w) = tokio::io::split(socket);
    let (tx, mut rx) = mpsc::channel(1);
    let limits = Limits::default();
    let tag = session.tag;
    let mut out = session.client_out;
    let input = input(r, session.client_in, tag, &limits, &lane.budget, tx);
    let replies = std::sync::Mutex::new(Replies::default());
    let reply_ready = Notify::new();
    let (finish, mut terminal) = oneshot::channel::<i32>();
    let driver = async {
        let offer = lane.budget.retirement.register();
        let mut c = Channel {
            lane: &lane,
            limits: &limits,
            stats,
            jobs: FuturesUnordered::new(),
            recovery: Recovery::default(),
        };
        let mut clock = tokio::time::interval(Duration::from_millis(250));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            *offer.lock().unwrap() = c.recovery.candidate(Instant::now());
            tokio::select! {
                Some((id,res))=c.jobs.next(),if !c.jobs.is_empty()=>{
                    c.recovery.completed(id,res.as_ref().and_then(|r|r.as_ref().ok()),Instant::now());
                    match res {
                        Some(Ok(reply)) if !reply.data.is_empty() => {
                            let mut ready = replies.lock().unwrap();
                            if ready.pending.len() == REPLY_QUEUE {
                                return Err(io::Error::other("HTTP/2 reply queue exhausted"));
                            }
                            ready.pending.push_back(reply);
                            reply_ready.notify_one();
                        }
                        Some(Err(error))=>{
                            stats.h2_errors.fetch_add(1,Ordering::Relaxed);
                            return match error {
                                Failure::Transport(error) => Ok(Some(error)),
                                Failure::ReplyBufferFull => Err(io::Error::other("HTTP/2 reply budget exhausted")),
                                Failure::Network(e)=>{
                                    *lane.cooldown.lock().unwrap()=Some(Instant::now()+Duration::from_secs(30));
                                    if e.kind()==io::ErrorKind::TimedOut && Arc::strong_count(&lane)==2 {lane.driver.abort();}
                                    Err(e)
                                },
                            };
                        },
                        _=>{}
                    }
                }
                next=rx.recv()=>match next {
                    Some((body,ticket))=>{let id=c.recovery.remember(&body,Instant::now());c.start(body,ticket,id,false);}
                    None=>return Ok(None)
                },
                _=clock.tick()=> {
                    let last_delivery = replies.lock().unwrap().delivered.take();
                    c.recovery.last_progress = c.recovery.last_progress.max(last_delivery);
                    c.recover();
                }
            }
        }
    };
    let output = async {
        loop {
            let next_reply = async {
                loop {
                    let reply = replies.lock().unwrap().pending.pop_front();
                    if let Some(reply) = reply {
                        return reply;
                    }
                    reply_ready.notified().await;
                }
            };
            let reply = tokio::select! {
                biased;
                code = &mut terminal => {
                    return match code {
                        Ok(code) => write(&mut w, &mut out, tag, &code.to_le_bytes(), stats).await,
                        Err(_) => Ok(()),
                    };
                }
                reply = next_reply => reply,
            };
            write(&mut w, &mut out, tag, &reply.data, stats).await?;
            replies.lock().unwrap().delivered = Some(Instant::now());
        }
    };
    tokio::pin!(output);
    let transport_error = tokio::select! {
        biased;
        // An observed native EOF must not poll the HTTP driver again.
        result = input => return result,
        result = driver => result?,
        result = &mut output => return result,
    };
    if let Some(error) = transport_error {
        replies.lock().unwrap().pending.clear();
        report_transport_error(error);
        let _ = finish.send(error.code());
        // A partially written native frame owns its cipher position. Finish
        // it and the terminal reply within one lease, ahead of queued replies.
        let _ = timeout(Duration::from_secs(2), output).await;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn slow_authenticated_h2_upload_survives_only_in_a_go_profile() {
        for (legacy, stall) in [(true, false), (true, true), (false, false)] {
            let (head, mut encrypt, _) = crate::crypto::client_fixture(&[5; 16], -2, 0xee);
            let session = Transport::client(head, &[5; 16]).unwrap();
            let body = [7; 24];
            let mut wire = framing::frame(&body, session.tag).unwrap();
            encrypt.apply_keystream(&mut wire);
            let (mut client, reader) = tokio::io::duplex(64);
            let (tx, mut rx) = mpsc::channel(1);
            let limits = Limits::default();
            let budget = super::super::Origins::for_profile(legacy)
                .shared_budget
                .unwrap_or_default();
            let pressure = stall.then(|| {
                budget
                    .partial_uploads
                    .as_ref()
                    .unwrap()
                    .try_acquire_many(PARTIAL_UPLOAD_BYTES as u32)
                    .unwrap()
            });
            client.write_all(&wire[..5]).await.unwrap();
            let task = input(reader, session.client_in, session.tag, &limits, &budget, tx);
            tokio::pin!(task);
            assert!((&mut task).now_or_never().is_none());
            assert_eq!(
                budget.requests.available_permits(),
                if legacy { 64 } else { 63 }
            );
            tokio::time::advance(REQUEST_TIME + Duration::from_secs(1)).await;
            if legacy {
                assert!((&mut task).now_or_never().is_none());
                client.write_all(&wire[5..6]).await.unwrap();
                assert!((&mut task).now_or_never().is_none());
                if stall {
                    tokio::time::advance(UPLOAD_IDLE).await;
                    assert_eq!(task.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
                } else {
                    tokio::time::advance(Duration::from_secs(3_600)).await;
                    assert!((&mut task).now_or_never().is_none());
                    client.write_all(&wire[6..]).await.unwrap();
                    client.shutdown().await.unwrap();
                    assert_eq!(task.await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
                    let (packet, ticket) = rx.recv().await.unwrap();
                    assert_eq!(&packet[..], &body);
                    drop(ticket);
                }
            } else {
                assert_eq!(task.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
            }
            drop(pressure);
            assert_eq!(budget.requests.available_permits(), 64);
            assert_eq!(budget.upload.available_permits(), 32 << 20);
            if let Some(partials) = &budget.partial_uploads {
                assert_eq!(partials.available_permits(), PARTIAL_UPLOAD_BYTES);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn one_incomplete_maximum_packet_leaves_the_last_http_request_for_another_client() {
        let budget = Budget::default();
        let _busy = budget.requests.clone().try_acquire_many_owned(63).unwrap();
        let limits = Limits::default();
        let (head, mut cipher, _) = crate::crypto::client_fixture(&[7; 16], -2, 0xdd);
        let slow = Transport::client(head, &[7; 16]).unwrap();
        let (mut client, reader) = tokio::io::duplex(64);
        let mut header = (PARTIAL_UPLOAD_BYTES as u32).to_le_bytes();
        cipher.apply_keystream(&mut header);
        client.write_all(&header).await.unwrap();
        let (tx, _rx) = mpsc::channel(1);
        {
            let waiting = input(reader, slow.client_in, slow.tag, &limits, &budget, tx);
            tokio::pin!(waiting);
            assert!((&mut waiting).now_or_never().is_none());
            assert_eq!(
                budget.partial_uploads.as_ref().unwrap().available_permits(),
                0
            );
            assert_eq!(
                budget.upload.available_permits(),
                (32 << 20) - PARTIAL_UPLOAD_BYTES
            );
            assert_eq!(budget.requests.available_permits(), 1);

            let (head, mut cipher, _) = crate::crypto::client_fixture(&[8; 16], -2, 0xee);
            let fast = Transport::client(head, &[8; 16]).unwrap();
            let body = [4; 24];
            let mut wire = framing::frame(&body, fast.tag).unwrap();
            cipher.apply_keystream(&mut wire);
            let (tx, mut rx) = mpsc::channel(1);
            let other_limits = Limits::default();
            let result = input(
                wire.as_slice(),
                fast.client_in,
                fast.tag,
                &other_limits,
                &budget,
                tx,
            )
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
            let (packet, ticket) = rx.recv().await.unwrap();
            assert_eq!(&packet[..], &body);
            assert_eq!(budget.requests.available_permits(), 0);
            drop(ticket);
            tokio::time::advance(Duration::from_secs(3_600)).await;
            assert!((&mut waiting).now_or_never().is_none());
        }
        assert_eq!(budget.requests.available_permits(), 1);
        assert_eq!(budget.upload.available_permits(), 32 << 20);
        assert_eq!(
            budget.partial_uploads.as_ref().unwrap().available_permits(),
            PARTIAL_UPLOAD_BYTES
        );
    }

    #[test]
    fn due_replay_uses_a_free_slot_then_rotates_only_the_oldest_waiting_poll() {
        let mut recovery = Recovery::default();
        let now = Instant::now();
        let due = recovery
            .remember(&Bytes::from_static(&[1; 24]), now)
            .unwrap();
        recovery.entries.back_mut().unwrap().retired = true;
        let poll = |age| Pending {
            entry: None,
            replay: true,
            start: now - Duration::from_secs(age),
            stage: Arc::new(AtomicU8::new(1)),
            abort: AbortHandle::new_pair().0,
        };
        recovery.pending.insert(10, poll(31));
        assert_eq!(recovery.next(now), Some(due));
        assert!(!recovery.pending[&10].abort.is_aborted());
        recovery.pending.insert(11, poll(36));
        assert_eq!(recovery.next(now), None);
        assert!(recovery.pending[&11].abort.is_aborted());
        assert!(!recovery.pending[&10].abort.is_aborted());
        recovery.pending.remove(&11);
        assert_eq!(recovery.next(now), Some(due));
    }

    #[test]
    fn shared_budget_retires_one_waiting_replay_before_an_original_and_preserves_receiving_data() {
        let directory = Retirement::default();
        let now = Instant::now();
        let offer = |replay, age, stage| {
            let (abort, _) = AbortHandle::new_pair();
            let offer = directory.register();
            *offer.lock().unwrap() = Some(Candidate {
                start: now - Duration::from_secs(age),
                expires: None,
                replay,
                stage: Arc::new(AtomicU8::new(stage)),
                abort: abort.clone(),
            });
            (offer, abort)
        };
        let (_receiving, a) = offer(true, 25, 2);
        let (_original, b) = offer(false, 20, 1);
        let (_replay, c) = offer(true, 6, 1);
        let (_recent, d) = offer(true, 4, 1);
        directory.make_room(now);
        assert!(c.is_aborted());
        assert!(!a.is_aborted() && !b.is_aborted() && !d.is_aborted());
        directory.make_room(now);
        assert!(d.is_aborted());
        assert!(!a.is_aborted() && !b.is_aborted());
    }
    #[test]
    fn recovery_excludes_plaintext_limits_history_and_only_replays_eligible_encrypted_packets() {
        let mut r = Recovery::default();
        let now = Instant::now();
        assert!(r.remember(&Bytes::from_static(&[0; 24]), now).is_none());
        let body = Bytes::from_static(&[1; 24]);
        let id = r.remember(&body, now).unwrap();
        assert_eq!(r.remember(&body, now), Some(id));
        assert_eq!(r.next(now), Some(id));
        let (abort, _) = AbortHandle::new_pair();
        let stage = Arc::new(AtomicU8::new(1));
        r.pending.insert(
            9,
            Pending {
                entry: Some(id),
                replay: false,
                start: now,
                stage: stage.clone(),
                abort,
            },
        );
        assert!(r.next(now + Duration::from_secs(2)).is_none());
        assert_eq!(r.next(now + Duration::from_secs(3)), Some(id));
        stage.store(2, Ordering::Release);
        assert!(r.next(now + Duration::from_secs(10)).is_none());
        r.pending.clear();
        r.entries.back_mut().unwrap().attempts = 3;
        assert!(r.next(now).is_none());
        for n in 0..25 {
            let mut v = vec![2; 4096];
            v[10] = n;
            r.remember(&v.into(), now);
        }
        assert!(r.entries.len() <= 16);
        assert!(!r.entries.iter().any(|e| e.id == id));
        assert!(r.next(now + Duration::from_secs(31)).is_none());
    }
}
