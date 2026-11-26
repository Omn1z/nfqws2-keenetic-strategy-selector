use super::*;
use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, Stdio};

const CHILD: &str = "N2S_TEST_HANDSHAKE_DIRECTORY";
#[test]
fn process_holding_two_files() {
    let Some(runtime) = std::env::var_os(CHILD) else {
        return;
    };
    let slots = Handshakes::adopt(Path::new(&runtime)).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let _a = slots.acquire().await.unwrap();
            let _b = slots.acquire().await.unwrap();
            println!("N2S_TEST_SLOTS_READY");
            std::io::stdout().flush().unwrap();
            let mut byte = [0];
            let _ = std::io::stdin().read(&mut byte);
        });
}

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn store(root: &Path) -> std::path::PathBuf {
    let dir = root.join(".store");
    std::fs::create_dir(&dir).unwrap();
    dir.join("runtime")
}
#[tokio::test]
async fn panel_and_child_share_four_slots_and_os_releases_them_after_a_crash() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = store(temp.path());
    assert!(Handshakes::adopt(&runtime).is_err());
    let slots = Handshakes::prepare(&runtime).unwrap();
    let _first = slots.acquire().await.unwrap();
    let _second = slots.acquire().await.unwrap();
    // Minimal test chroots can have no /proc/self/exe; the harness is
    // invoked with its absolute path inside the private root.
    let executable = std::env::current_exe()
        .or_else(|err| {
            std::env::args_os()
                .next()
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_absolute() && p.is_file())
                .ok_or(err)
        })
        .unwrap();
    let mut child = Worker(
        Command::new(executable)
            .args([
                "--exact",
                "handshakes::tests::process_holding_two_files",
                "--nocapture",
            ])
            .env(CHILD, &runtime)
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pipe = child.0.stdout.take().unwrap();
    let ready = tokio::task::spawn_blocking(move || {
        io::BufReader::new(pipe)
            .lines()
            .map_while(Result::ok)
            .any(|s| s.contains("N2S_TEST_SLOTS_READY"))
    });
    assert!(timeout(Duration::from_secs(10), ready)
        .await
        .unwrap()
        .unwrap());
    let start = tokio::time::Instant::now();
    assert_eq!(
        slots.acquire().await.err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(start.elapsed() >= Duration::from_millis(950));
    drop(child);
    let next = Handshakes::adopt(&runtime).unwrap();
    let _third = next.acquire().await.unwrap();
    let owner = next.clone();
    let (ready, seen) = tokio::sync::oneshot::channel();
    let cancelled = tokio::spawn(async move {
        let _fourth = owner.acquire().await.unwrap();
        let _ = ready.send(());
        std::future::pending::<()>().await;
    });
    seen.await.unwrap();
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let _fourth = slots.acquire().await.unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_and_hardlink_are_never_adopted_as_empty_lock_files() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = store(temp.path());
    drop(Handshakes::prepare(&runtime).unwrap());
    let lock = runtime.join("tgws-handshake-0.lock");
    let other = temp.path().join("elsewhere");
    std::fs::rename(&lock, &other).unwrap();
    std::os::unix::fs::symlink(&other, &lock).unwrap();
    assert!(Handshakes::prepare(&runtime).is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::hard_link(&other, &lock).unwrap();
    assert!(Handshakes::adopt(&runtime).is_err());
    assert!(std::fs::read(other).unwrap().is_empty());
}
