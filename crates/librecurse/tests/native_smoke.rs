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
    // fail with "could not resolve symbol". Shortened C++ names can collide
    // (`foo(int)`/`foo(char*)` -> `foo`), so require resolution, not equality.
    for f in funcs.iter().take(5) {
        assert!(
            engine.resolve(&f.name).expect("resolve").is_some(),
            "discovered name {} resolves",
            f.name
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

#[test]
fn native_annotates_disassembly_and_names_imports() {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/5c8e1a9533c5d4776a837ecf/crack1_by_D4RK_FL0W");
    if !bin.is_file() {
        return;
    }
    let engine = librecurse::native::NativeEngine::open(&bin).expect("open");
    engine.analyze().expect("analyze");
    // PLT stubs are named after the import they forward to, like r2's imp.*.
    assert!(
        engine
            .functions()
            .expect("functions")
            .iter()
            .any(|f| f.name.starts_with("imp.")),
        "PLT stubs are named"
    );
    // Disassembly carries string/symbol comments and named call targets.
    let main = engine.resolve("main").expect("resolve").expect("main");
    let ops = engine.function_disasm(main).expect("disasm").ops;
    assert!(
        ops.iter().any(|o| o.disasm.contains("; \"")),
        "string reference annotated"
    );
    assert!(
        ops.iter().any(|o| {
            o.disasm.contains("; failed")
                || o.disasm.contains("; readInput")
                || o.disasm.contains("; main")
        }),
        "call target annotated"
    );
    // A data address gives an actionable error, not a bare rejection.
    let err = engine
        .disassemble(&Target::Addr(0), Some(1))
        .expect_err("0 is not code");
    assert!(err.contains("not in an executable section"), "got: {err}");
}

#[test]
fn native_instructions_carry_bytes_but_the_agent_tool_strips_them() {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/5c8e1a9533c5d4776a837ecf/crack1_by_D4RK_FL0W");
    if !bin.is_file() {
        return;
    }
    let engine = librecurse::native::NativeEngine::open(&bin).expect("open");
    engine.analyze().expect("analyze");
    let main = engine.resolve("main").expect("resolve").expect("main");
    // UI-facing disassembly carries hex bytes (parity with r2).
    let ops = engine.function_disasm(main).expect("disasm").ops;
    assert!(
        ops.iter()
            .all(|o| o.bytes.as_deref().is_some_and(|b| !b.is_empty())),
        "every UI instruction has bytes"
    );
    assert!(
        ops.iter().any(|o| o.bytes.as_deref() == Some("55")),
        "push rbp is 0x55"
    );
    // The agent tool strips them (bulky, re-derivable).
    let out = librecurse::engine::execute_tool(
        &engine,
        &serde_json::json!({"op": "disasm", "addr": main}),
    )
    .expect("agent disasm");
    assert!(
        !out.contains("\"bytes\""),
        "agent disasm has no bytes: {out}"
    );
    let g = librecurse::engine::execute_tool(
        &engine,
        &serde_json::json!({"op": "graph", "addr": main}),
    )
    .expect("agent graph");
    assert!(!g.contains("\"bytes\""), "agent graph has no bytes");
}

#[test]
fn native_reports_data_xrefs_and_import_stubs() {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/5c8e1a9533c5d4776a837ecf/crack1_by_D4RK_FL0W");
    if !bin.is_file() {
        return;
    }
    let engine = librecurse::native::NativeEngine::open(&bin).expect("open");
    engine.analyze().expect("analyze");
    // Each import forwards through a discovered stub, whose address is carried.
    assert!(
        engine
            .imports()
            .expect("imports")
            .iter()
            .any(|i| i.plt.is_some()),
        "an import carries its stub address"
    );
    // A referenced string is reachable by a data cross-reference.
    let strings = engine.strings().expect("strings");
    let s = strings
        .iter()
        .find(|s| s.string.contains("Crackme"))
        .expect("a referenced string");
    let refs = engine
        .xrefs(&Target::Addr(s.addr), XrefDirection::To)
        .expect("xrefs");
    assert!(
        refs.iter().any(|x| x.kind == "DATA"),
        "data xref to {:#x}: {refs:?}",
        s.addr
    );
}

#[test]
fn native_strings_by_address_and_mangled_resolve() {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/5c8e1a9533c5d4776a837ecf/crack1_by_D4RK_FL0W");
    if !bin.is_file() {
        return;
    }
    let engine = librecurse::native::NativeEngine::open(&bin).expect("open");
    engine.analyze().expect("analyze");
    // A mangled C++ query (`_Z4mainiPPc`) resolves like its base name.
    assert_eq!(
        engine.resolve("_Z4mainiPPc").expect("resolve mangled"),
        engine.resolve("main").expect("resolve main")
    );
    // `strings` with an address reads the string at/containing it.
    let strings = engine.strings().expect("strings");
    let s = strings
        .iter()
        .find(|s| s.string.len() > 4)
        .expect("a string");
    let inside = s.addr + 1;
    let out = librecurse::engine::execute_tool(
        &engine,
        &serde_json::json!({"op": "strings", "addr": inside}),
    )
    .expect("strings by addr");
    let env: serde_json::Value = serde_json::from_str(&out).expect("envelope");
    assert!(
        env["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["string"] == s.string),
        "string at {inside:#x} returned: {out}"
    );
}
