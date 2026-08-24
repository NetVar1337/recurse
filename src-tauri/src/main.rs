// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Cross-platform Wayland fix: WebKitGTK 2.48+ with DMA-BUF renderer
    // crashes on Hyprland/Wayland (Error 71 dispatching to Wayland display).
    // PopOS (X11) was unaffected; this makes `npm run tauri dev` work on
    // both X11 and Wayland without manual env setup.
    // Respect explicit user overrides.
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WEBKIT_DISABLE_DMABUF_RENDERER").is_err() {
            // SAFETY: called at startup, single-threaded before any GTK init.
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            }
        }
        // Fallback for compositors where DMABUF alone is insufficient.
        // Uncomment if you still see `Gdk-Message: Error 71`:
        // if std::env::var("WEBKIT_DISABLE_COMPOSITING_MODE").is_err() {
        //     unsafe { std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1"); }
        // }
    }
    recurse_lib::run()
}
