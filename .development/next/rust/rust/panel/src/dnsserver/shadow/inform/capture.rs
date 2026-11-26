use std::future::Future;
use tokio::sync::watch;

#[cfg(target_os = "linux")]
pub(super) mod linux;

/// The request future owns its optional observer. Disabling diagnostics revokes
/// only the observer while preserving the pinned exchange and its deadline.
pub(super) async fn during<T, C>(
    exchange: impl Future<Output = T>,
    observer: C,
    mut scope: watch::Receiver<()>,
    finish: impl FnOnce(C, &watch::Receiver<()>),
) -> T {
    tokio::pin!(exchange);
    tokio::select! {
        biased;
        _ = scope.changed() => {
            drop(observer);
            exchange.await
        }
        result = &mut exchange => {
            if scope.has_changed().is_ok() {
                finish(observer, &scope);
            }
            result
        }
    }
}

#[cfg(test)]
mod tests;
