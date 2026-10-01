// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Choose the platform webview renderer before the webview is created — see
    // [`recurse_lib::webkit`] for the policy. Applied here first so a packaged
    // binary gets it, and again inside `run()` for direct library use. A no-op
    // on Windows and macOS.
    recurse_lib::webkit::configure();
    recurse_lib::run()
}
