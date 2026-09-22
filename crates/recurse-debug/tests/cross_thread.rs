//! Regression: on Linux the ptrace tracer is the *exact thread* that forked
//! the debuggee, so ops issued from different threads used to fail with
//! `ESRCH`. The session now owns a dedicated worker thread, so any caller can
//! drive it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use recurse_debug::model::{LaunchOptions, StopReason};
use recurse_debug::Debugger;

#[test]
fn ops_from_different_threads() {
    let dbg = Arc::new(match Debugger::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping: {e}");
            return;
        }
    });

    // Launch on one thread…
    let d = dbg.clone();
    let launched = std::thread::spawn(move || {
        d.launch(&LaunchOptions {
            path: "/bin/true".into(),
            ..Default::default()
        })
        .map(|s| s.reason)
    })
    .join()
    .unwrap();
    assert!(matches!(launched, Ok(StopReason::Started)));

    // …and continue on another. Before the worker thread this returned ESRCH.
    let d = dbg.clone();
    let resumed = std::thread::spawn(move || d.resume().map(|s| s.reason))
        .join()
        .unwrap();
    assert!(
        matches!(resumed, Ok(StopReason::Exited { .. })),
        "cross-thread continue: {resumed:?}"
    );
}
