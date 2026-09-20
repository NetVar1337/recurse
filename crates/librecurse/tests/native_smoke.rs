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

    // Names the tool itself emits must resolve back to an address, even when
    // they are not ELF symbols (`fcn_1080`), or the model's follow-up calls
    // fail with "could not resolve symbol".
    for f in funcs.iter().take(5) {
        assert_eq!(
            engine.resolve(&f.name).expect("resolve"),
            Some(f.addr),
            "discovered name {} resolves to {:#x}",
            f.name,
            f.addr
        );
    }
    assert_eq!(
        engine
            .resolve(&format!("fcn_{:x}", entry))
            .expect("resolve hex"),
        Some(entry)
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

#[test]
fn native_resolves_demangled_cpp_names() {
    // The eval corpus is gitignored, so skip when it isn't fetched.
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/5c8e1a9533c5d4776a837ecf/crack1_by_D4RK_FL0W");
    if !bin.is_file() {
        return;
    }
    let engine = librecurse::native::NativeEngine::open(&bin).expect("open");
    engine.analyze().expect("analyze");
    // The binary has `_Z9readInputv` etc.; the model types the base name it
    // saw in the demangled function list, so resolve must be loose.
    for name in ["main", "readInput", "success", "failed", "readInput()"] {
        assert!(
            engine.resolve(name).expect("resolve").is_some(),
            "{name} should resolve"
        );
    }
    assert_eq!(
        engine.resolve("readInput").unwrap(),
        engine.resolve("_Z9readInputv").unwrap()
    );
}
