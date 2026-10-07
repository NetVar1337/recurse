//! Debuggee stdio: stepping at the entry must not fault, and input written to
//! the debuggee's stdin while a `continue` is blocked must reach the program.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use recurse_debug::model::{LaunchOptions, ProcessState, StepKind, StopReason};
use recurse_debug::{Debugger, SessionEvent};

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

#[test]
fn snapshot_is_live_while_running() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(FIXTURE);
    if !path.is_file() {
        return;
    }
    let dbg = match Debugger::new() {
        Ok(d) => Arc::new(d),
        Err(_) => return,
    };
    dbg.launch(&LaunchOptions {
        path: path.to_string_lossy().to_string(),
        ..Default::default()
    })
    .expect("launch");
    assert_eq!(dbg.snapshot().state, ProcessState::Stopped);

    // Run the target (it blocks on input). The snapshot must report it is
    // running *while* the `continue` is still blocked, so a UI can follow.
    let runner = dbg.clone();
    let cont = std::thread::spawn(move || runner.resume());
    let mut saw_running = false;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(50));
        if dbg.snapshot().state == ProcessState::Running {
            saw_running = true;
            break;
        }
    }
    assert!(saw_running, "snapshot reports running while blocked");

    dbg.write_stdin(b"x\n").expect("stdin");
    let _ = cont.join();
    assert_eq!(dbg.snapshot().state, ProcessState::Exited);
}

#[test]
fn disassembles_live_memory() {
    let dbg = match Debugger::new() {
        Ok(d) => Arc::new(d),
        Err(_) => return,
    };
    let stop = match dbg.launch(&LaunchOptions {
        path: "/bin/true".into(),
        ..Default::default()
    }) {
        Ok(s) => s,
        Err(_) => return,
    };
    // The instruction at the entry point must decode from the live process.
    let insns = dbg.disasm(stop.registers.pc, 4).expect("disasm");
    assert_eq!(insns.len(), 4);
    assert_eq!(insns[0].addr, stop.registers.pc);
    assert!(!insns[0].text.is_empty());
    assert!(!insns[0].bytes.is_empty());
    let _ = dbg.kill();
}

#[test]
fn sets_a_register() {
    let dbg = match Debugger::new() {
        Ok(d) => Arc::new(d),
        Err(_) => return,
    };
    if dbg
        .launch(&LaunchOptions {
            path: "/bin/true".into(),
            ..Default::default()
        })
        .is_err()
    {
        return;
    }
    let updated = dbg.set_register("rax", 0xdead_beef).expect("setreg");
    assert_eq!(updated.values.get("rax"), Some(&0xdead_beef));
    // The write must be visible on the next read.
    let again = dbg.registers(None).expect("regs");
    assert_eq!(again.values.get("rax"), Some(&0xdead_beef));
    let _ = dbg.kill();
}

#[test]
fn pause_interrupts_a_running_target() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(FIXTURE);
    if !path.is_file() {
        return;
    }
    let dbg = match Debugger::new() {
        Ok(d) => Arc::new(d),
        Err(_) => return,
    };
    if dbg
        .launch(&LaunchOptions {
            path: path.to_string_lossy().to_string(),
            ..Default::default()
        })
        .is_err()
    {
        return;
    }

    // The target blocks reading stdin, so `continue` never reaches a stop.
    let runner = dbg.clone();
    let cont = std::thread::spawn(move || runner.resume());

    // Wait until it is actually running, then pause it.
    let mut running = false;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(50));
        if dbg.snapshot().state == ProcessState::Running {
            running = true;
            break;
        }
    }
    assert!(running, "target should be running");

    dbg.interrupt().expect("interrupt");
    let stop = cont.join().unwrap().expect("resume returns a stop");
    assert!(
        matches!(stop.reason, StopReason::Paused),
        "pause stop: {:?}",
        stop.reason
    );

    let _ = dbg.kill();
}

/// A prompt the program prints *before* it blocks on a read must reach a
/// subscriber, with nobody asking for it.
///
/// The UI no longer polls for output, so this is the only way a prompt can
/// appear: the session pushes it as the debuggee's reader thread sees it. The
/// read is the point — the program is stopped in `read` and will produce nothing
/// else for as long as the analyst takes to type, so a prompt that is not pushed
/// is a prompt the analyst never sees, with a target that looks hung.
#[test]
fn a_prompt_before_a_read_is_pushed_to_a_subscriber() {
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

    // Subscribed before the run, the way the window's forwarder is: nothing is
    // replayed, so an event missed here would have to wait for a later one.
    let events = dbg.subscribe();
    let runner = dbg.clone();
    let cont = std::thread::spawn(move || runner.resume().map(|s| s.reason));

    let mut seen = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline && !seen.contains("Give Me Your Flag") {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(remaining) {
            // The `output` op is deliberately never called: draining the buffer
            // is the poll's job, and this is the push's.
            Ok(SessionEvent::Output { text }) => seen.push_str(&text),
            Ok(SessionEvent::Snapshot { .. }) => {}
            Err(e) => panic!("no prompt pushed: {seen:?} ({e})"),
        }
    }
    assert!(
        seen.contains("Give Me Your Flag"),
        "prompt pushed before input: {seen:?}"
    );

    // The target is blocked in `read`, and only the interrupt can end that, so
    // this is also the check that a run in progress is still answerable.
    dbg.interrupt().expect("interrupt");
    let stop = cont.join().unwrap().expect("resume returns a stop");
    assert!(matches!(stop, StopReason::Paused), "pause stop: {stop:?}");

    let _ = dbg.kill();
}
