//! End-to-end smoke test for the pure-Rust native backend: parse, discover,
//! disassemble, and reference a real binary (the test executable itself).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use librecurse::engine::{Engine, Target, XrefDirection};

#[test]
fn native_backend_parses_discovers_and_disassembles() {
    let exe = std::env::current_exe().expect("test executable path");
    let engine = librecurse::native::NativeEngine::open(&exe).expect("open native engine");

    let info = engine.info().expect("info");
    assert!(info["bin"]["arch"].is_string());
    assert!(info["bin"]["bits"].as_u64().unwrap_or(0) > 0);

    engine.analyze().expect("analyze");
    let funcs = engine.functions().expect("functions");
    assert!(!funcs.is_empty(), "at least the entry point is discovered");

    // Disassemble the first discovered function; it must yield real text.
    let entry = funcs[0].addr;
    let dis = engine.function_disasm(entry).expect("function disasm");
    assert!(
        !dis.ops.is_empty(),
        "function at {entry:#x} has instructions"
    );
    assert!(
        dis.ops.iter().any(|o| !o.disasm.is_empty()),
        "instructions are formatted"
    );

    // Xrefs must be answerable in both directions without erroring.
    engine
        .xrefs(&Target::Addr(entry), XrefDirection::To)
        .expect("xrefs to");
    engine
        .xrefs(&Target::Addr(entry), XrefDirection::From)
        .expect("xrefs from");

    // A test binary always carries some strings.
    let strings = engine.strings().expect("strings");
    assert!(!strings.is_empty());
}

#[test]
fn native_backend_reports_missing_decompiler_clearly() {
    let exe = std::env::current_exe().expect("test executable path");
    let engine = librecurse::native::NativeEngine::open(&exe).expect("open native engine");
    assert!(!engine.capabilities().decompile);
    let err = engine.decompile(0).expect_err("no decompiler");
    assert!(err.contains("no decompiler"));
}
