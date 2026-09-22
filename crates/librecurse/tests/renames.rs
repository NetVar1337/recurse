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
