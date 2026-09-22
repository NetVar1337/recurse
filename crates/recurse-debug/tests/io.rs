//! Debuggee stdio: stepping at the entry must not fault, and input written to
//! the debuggee's stdin while a `continue` is blocked must reach the program.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use recurse_debug::model::{LaunchOptions, StepKind};
use recurse_debug::Debugger;

/// A crackme that prompts on stdout and reads a flag from stdin.
const FIXTURE: &str = "crates/recurse-eval/corpus/5b81014933c5d41f5c6ba944/just see";

#[test]
fn step_at_entry_and_feed_stdin() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(FIXTURE);
    if !path.is_file() {
        return;
    }
    let dbg = match Debugger::new() {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("skipping: {e}");
            return;
        }
    };
    dbg.launch(&LaunchOptions {
        path: path.to_string_lossy().to_string(),
        ..Default::default()
    })
    .expect("launch");

    // Stepping over at the loader entry used to fault: the top of the stack is
    // `argc`, not a return address.
    for _ in 0..4 {
        dbg.step(StepKind::Over).expect("step at entry");
    }

    // Start the program; it prints its prompt and blocks on input. Because the
    // debuggee runs on a tty, the prompt is line-buffered and must appear
    // *before* we send anything.
    let writer = dbg.clone();
    let cont = std::thread::spawn(move || writer.resume().map(|s| s.reason));
    let mut prompt = String::new();
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(50));
        prompt = String::from_utf8_lossy(&dbg.output()).to_string();
        if prompt.contains("Give Me Your Flag") {
            break;
        }
    }
    assert!(
        prompt.contains("Give Me Your Flag"),
        "prompt appeared before input: {prompt:?}"
    );

    // Now answer the prompt and let it finish.
    dbg.write_stdin(b"hunter2\n").expect("write stdin");
    let _ = cont.join().unwrap();
    let output = String::from_utf8_lossy(&dbg.output()).to_string();
    assert!(
        output.contains("Bad"),
        "debuggee output captured: {output:?}"
    );

    let _ = dbg.kill();
}
