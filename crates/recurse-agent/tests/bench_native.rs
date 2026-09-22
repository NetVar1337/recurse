//! Ignored benchmark for the native backend. Run with:
//!
//! ```sh
//! cargo test -p recurse_agent --test bench_native -- --ignored --nocapture
//! ```
//!
//! Times every analysis method on the eval corpus (tiny crackmes) and on the
//! test executable itself (a large, symbol-rich binary), so a compute
//! regression is visible separately from agent-turn counts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use recurse_agent::engine::{Engine, Target, XrefDirection};
use recurse_agent::native::NativeEngine;

fn corpus() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../recurse-eval/corpus");
    let mut out = Vec::new();
    let Ok(dirs) = std::fs::read_dir(&root) else {
        return out;
    };
    for e in dirs.flatten() {
        let d = e.path();
        if !d.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&d) else {
            continue;
        };
        for f in files.flatten() {
            let p = f.path();
            if p.is_file() && p.file_name().map(|n| n != ".fetched").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn ms_since(t: Instant) -> u128 {
    t.elapsed().as_millis()
}

#[test]
#[ignore = "benchmark; run explicitly with --ignored --nocapture"]
fn bench_native_methods() {
    let mut paths: Vec<PathBuf> = corpus();
    // A large, symbol-rich case exposes scaling that the tiny crackmes hide.
    paths.push(std::env::current_exe().unwrap());

    for path in &paths {
        let t = Instant::now();
        let Ok(engine) = NativeEngine::open(path) else {
            continue;
        };
        let open = ms_since(t);

        let t = Instant::now();
        engine.analyze().unwrap();
        let analyze = ms_since(t);

        let t = Instant::now();
        let funcs = engine.functions().unwrap();
        let functions = ms_since(t);
        let first = funcs.first().map(|f| f.addr).unwrap_or(0);

        let t = Instant::now();
        let _ = engine.function_at(first).unwrap();
        let function_at = ms_since(t);

        let t = Instant::now();
        let dis = engine.disassemble(&Target::Addr(first), Some(40)).unwrap();
        let disasm = ms_since(t);

        let t = Instant::now();
        let fdis = engine.function_disasm(first).unwrap();
        let function_disasm = ms_since(t);

        let t = Instant::now();
        let _ = engine.function_graph(first).unwrap();
        let graph = ms_since(t);

        let t = Instant::now();
        let strings = engine.strings().unwrap();
        let strings_ms = ms_since(t);

        let t = Instant::now();
        let imports = engine.imports().unwrap();
        let imports_ms = ms_since(t);

        let t = Instant::now();
        let xrefs = engine
            .xrefs(&Target::Addr(first), XrefDirection::To)
            .unwrap();
        let xrefs_ms = ms_since(t);

        // Repeat one disasm to show per-call cost (the agent calls it many times).
        let t = Instant::now();
        for _ in 0..10 {
            let _ = engine.disassemble(&Target::Addr(first), Some(20)).unwrap();
        }
        let disasm_x10 = ms_since(t);

        println!(
            "{:<34} size={:>7} funcs={:>5} ops={:>5} str={:>5} | open={open} analyze={analyze} \
             functions={functions} fn_at={function_at} disasm={disasm} fn_disasm={function_disasm} \
             graph={graph} strings={strings_ms} imports={imports_ms} xrefs={xrefs_ms} disasm_x10={disasm_x10} \
             [fdis_ops={}]",
            path.file_name().unwrap().to_string_lossy(),
            std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            funcs.len(),
            dis.ops.len(),
            strings.len(),
            fdis.ops.len(),
        );
        let _ = imports;
        let _ = xrefs;
    }
}
