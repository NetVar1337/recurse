//! Recon-page smoke tests: the self-contained hardening report and analysis
//! summary are computed from the object itself (no external `checksec`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use librecurse::engine::Engine;
use librecurse::native::NativeEngine;

#[test]
fn recon_reports_hardening_and_analysis() {
    let path = std::env::current_exe().unwrap();
    let engine = NativeEngine::open(&path).unwrap();
    let recon = engine.recon().unwrap();
    for field in [
        "relro", "pie", "nx", "canary", "fortify", "rpath", "runpath",
    ] {
        assert!(
            recon["checksec"][field].is_string(),
            "checksec.{field} missing"
        );
    }
    assert!(recon["info"]["class"].is_string());
    assert!(recon["info"]["machine"].is_string());
    assert!(recon["analysis"]["functions"].as_u64().unwrap_or(0) > 0);
    assert!(recon["analysis"]["coverage"].as_f64().unwrap_or(0.0) > 0.0);
}

#[test]
fn recon_detects_full_relro_and_canary() {
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/691fd9362d267f28f69b7f89/simp-password");
    if !bin.is_file() {
        return;
    }
    let engine = NativeEngine::open(&bin).unwrap();
    let recon = engine.recon().unwrap();
    assert_eq!(recon["checksec"]["relro"], "Full RELRO");
    assert_eq!(recon["checksec"]["canary"], "Canary found");
    assert_eq!(recon["checksec"]["pie"], "PIE enabled");
    assert_eq!(recon["checksec"]["nx"], "NX enabled");
}

#[test]
fn recon_reports_partial_relro_without_canary() {
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../recurse-eval/corpus/5c8e1a9533c5d4776a837ecf/crack1_by_D4RK_FL0W");
    if !bin.is_file() {
        return;
    }
    let engine = NativeEngine::open(&bin).unwrap();
    let recon = engine.recon().unwrap();
    assert_eq!(recon["checksec"]["relro"], "Partial RELRO");
    assert_eq!(recon["checksec"]["canary"], "No canary found");
}
