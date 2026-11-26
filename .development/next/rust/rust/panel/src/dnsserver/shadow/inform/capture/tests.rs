use super::*;
use crate::dnsserver::shadow::Diagnostics;
use std::future::pending;
use tokio::sync::oneshot;

struct Owner(Option<oneshot::Sender<()>>);

impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(closed) = self.0.take() {
            let _ = closed.send(());
        }
    }
}

#[tokio::test]
async fn shadow_wire_scope_disable_drops_only_observer_even_when_reenabled() {
    let diagnostics = Diagnostics::default();
    let disabled = diagnostics.begin("dhcp.start", "fixture");
    assert!(disabled.trace().wire_scope().is_none());
    diagnostics.set(true);
    let event = diagnostics.begin("dhcp.start", "fixture");
    let trace = event.trace();
    let scope = trace.wire_scope().unwrap();
    let (started, running) = oneshot::channel();
    let (stop, closed) = oneshot::channel();
    let (reply, response) = oneshot::channel();
    let task = tokio::spawn(during(
        async move {
            started.send(()).unwrap();
            response.await.unwrap()
        },
        Owner(Some(stop)),
        scope,
        |_, _| panic!("disabled observer must not read or publish"),
    ));
    running.await.unwrap();
    diagnostics.set(false);
    diagnostics.set(true);
    let replacement = diagnostics.begin("dhcp.start", "fixture");
    assert!(trace.wire_scope().is_none());
    assert!(replacement.trace().wire_scope().is_some());
    closed.await.unwrap();
    assert!(!task.is_finished());
    reply.send(7).unwrap();
    assert_eq!(task.await.unwrap(), 7);
}

#[tokio::test]
async fn shadow_wire_scope_cancel_leaves_no_observer_or_drain_handler() {
    let diagnostics = Diagnostics::default();
    diagnostics.set(true);
    let event = diagnostics.begin("dhcp.start", "fixture");
    let scope = event.trace().wire_scope().unwrap();
    let (close, closed) = oneshot::channel();
    let mut stalled = Box::pin(during(
        pending::<()>(),
        Owner(Some(close)),
        scope,
        |_, _| panic!("canceled request must not drain"),
    ));
    tokio::select! {
        _ = &mut stalled => panic!("fixture request must remain pending"),
        _ = tokio::task::yield_now() => (),
    }
    drop(stalled);
    closed.await.unwrap();
}
