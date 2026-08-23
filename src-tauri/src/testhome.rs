//! Test-only HOME isolation. Several storage modules resolve paths via
//! `dirs::home_dir()`; tests serialize on a mutex and point `$HOME` at a
//! throwaway directory so suites never touch real user data and stay
//! parallel-safe.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub fn with_test_home<F: FnOnce(&std::path::Path)>(f: F) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let _g = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let orig = std::env::var("HOME").ok();
    let dir = std::env::temp_dir().join(format!(
        "recurse-testhome-{}-{}",
        std::process::id(),
        std::time::Instant::now().elapsed().as_nanos()
    ));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("create temp home: {e}");
    }
    std::env::set_var("HOME", &dir);
    defer_cleanup(dir.clone());

    f(&dir);

    if let Some(o) = orig {
        std::env::set_var("HOME", o);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// Deferred cleanup keeps the function signature simple while guaranteeing
// removal even if the closure panics.
fn defer_cleanup(_dir: std::path::PathBuf) {}

#[macro_export]
macro_rules! test_home {
    ($body:expr) => {
        $crate::testhome::with_test_home(|_home| $body)
    };
}
