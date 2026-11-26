//! The SOCKS listener and the worker share four in-flight upstream upgrades.
//! Keep stable kernel lock identities across worker restarts.
use std::{fs::File, io, path::Path, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore},
    time::{sleep, timeout},
};
mod files;

const COUNT: usize = 4;
type Slot = Arc<Mutex<Option<File>>>;
#[derive(Clone)]
pub struct Handshakes {
    local: Arc<Semaphore>,
    slots: Option<Arc<[Slot; COUNT]>>,
}
impl Default for Handshakes {
    fn default() -> Self {
        Self {
            local: Arc::new(Semaphore::new(COUNT)),
            slots: None,
        }
    }
}
impl Handshakes {
    /// The panel creates missing files; a spawned worker may only adopt them.
    pub fn prepare(runtime: &Path) -> io::Result<Self> {
        Self::open(runtime, true)
    }
    pub fn adopt(runtime: &Path) -> io::Result<Self> {
        Self::open(runtime, false)
    }
    fn open(runtime: &Path, create: bool) -> io::Result<Self> {
        let files = files::open(runtime, create)?;
        Ok(Self {
            slots: Some(Arc::new(files.map(|file| Arc::new(Mutex::new(Some(file)))))),
            ..Self::default()
        })
    }
    pub async fn acquire(&self) -> io::Result<Permit> {
        timeout(Duration::from_secs(1), async {
            let local = self
                .local
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            let Some(slots) = &self.slots else {
                return Ok(Permit {
                    _local: local,
                    slot: None,
                });
            };
            loop {
                for slot in slots.iter() {
                    let Ok(guard) = slot.clone().try_lock_owned() else {
                        continue;
                    };
                    let file = guard
                        .as_ref()
                        .ok_or_else(|| io::Error::other("handshake file lock failed"))?;
                    match file.try_lock() {
                        Ok(()) => {
                            return Ok(Permit {
                                _local: local,
                                slot: Some(guard),
                            })
                        }
                        Err(std::fs::TryLockError::WouldBlock) => (),
                        Err(std::fs::TryLockError::Error(e)) => return Err(e),
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| io::ErrorKind::WouldBlock)?
    }
}
pub struct Permit {
    _local: OwnedSemaphorePermit,
    slot: Option<OwnedMutexGuard<Option<File>>>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(guard) = self.slot.as_mut() {
            if guard.as_ref().is_some_and(|file| file.unlock().is_err()) {
                // Closing also releases the OS lock. Do not reuse a handle
                // whose lock state the kernel could not confirm.
                guard.take();
            }
        }
    }
}

#[cfg(test)]
mod tests;
