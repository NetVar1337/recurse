//! Analyst renames: `Engine::set_renames` overrides names in listings, lookup,
//! and `resolve`, and clearing restores the discovered names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use librecurse::engine::Engine;
use librecurse::native::NativeEngine;

#[test]
fn renames_override_names_and_resolve() {
    let path = std::env::current_exe().unwrap();
    let engine = NativeEngine::open(&path).unwrap();
    engine.analyze().unwrap();

    let target = engine.functions().unwrap().into_iter().next().unwrap();
    let original = target.name.clone();

    let mut renames = HashMap::new();
    renames.insert(target.addr, "decrypt_flag".to_string());
    engine.set_renames(renames);

    // Lookup, listing, and resolve all see the new name.
    assert_eq!(
        engine.function_at(target.addr).unwrap().unwrap().name,
        "decrypt_flag"
    );
    assert!(engine
        .functions()
        .unwrap()
        .iter()
        .any(|f| f.addr == target.addr && f.name == "decrypt_flag"));
    assert_eq!(engine.resolve("decrypt_flag").unwrap(), Some(target.addr));

    // Clearing restores the discovered name.
    engine.set_renames(HashMap::new());
    let restored = engine.function_at(target.addr).unwrap().unwrap().name;
    assert_ne!(restored, "decrypt_flag");
    assert_eq!(restored, original);
}

#[test]
fn renames_show_in_disassembly_annotations() {
    let path = std::env::current_exe().unwrap();
    let engine = NativeEngine::open(&path).unwrap();
    engine.analyze().unwrap();

    let funcs = engine.functions().unwrap();
    let addrs: std::collections::HashSet<u64> = funcs.iter().map(|f| f.addr).collect();
    // Find a function that directly calls another function.
    let mut pair = None;
    for f in funcs.iter().take(80) {
        for op in engine.function_disasm(f.addr).unwrap().ops {
            if let Some(t) = op.jump {
                if t != f.addr && addrs.contains(&t) {
                    pair = Some((f.addr, t));
                    break;
                }
            }
        }
        if pair.is_some() {
            break;
        }
    }
    let Some((caller, callee)) = pair else {
        return;
    };

    let mut renames = HashMap::new();
    renames.insert(callee, "RENAMED_CALLEE".to_string());
    engine.set_renames(renames);

    let ops = engine.function_disasm(caller).unwrap().ops;
    assert!(
        ops.iter().any(|o| o.disasm.contains("; RENAMED_CALLEE")),
        "renamed callee appears in the caller's annotation"
    );
}
