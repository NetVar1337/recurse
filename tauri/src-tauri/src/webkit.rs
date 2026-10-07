//! Platform webview-rendering configuration.
//!
//! Tauri renders through a different engine per platform: WebKitGTK on Linux,
//! WebView2 (Chromium) on Windows, and WKWebView on macOS. Only WebKitGTK needs
//! the workarounds here — the others composite through their platform
//! compositor and have no equivalent failure — so callers invoke
//! [`configure`] unconditionally and the platform handling lives in one place
//! instead of as `cfg` at every call site.

/// Apply the platform's webview rendering configuration.
///
/// Must run before the webview is created. On Linux that means before GTK or
/// WebKit initialize, because every setting below is an environment variable
/// WebKit reads once at init.
///
/// Windows and macOS are no-ops.
///
/// # Example
///
/// Called at the top of the process, before the Tauri app is built:
///
/// ```no_run
/// recurse_lib::webkit::configure();
/// ```
pub fn configure() {
    #[cfg(target_os = "linux")]
    configure_linux();
}

/// Linux/WebKitGTK configuration.
///
/// WebKitGTK's DMA-BUF renderer is its accelerated path. Two NVIDIA-specific
/// faults can make it unusable, and the two need opposite fixes:
///
/// * **Wayland** — the surface enables the Wayland explicit-sync protocol but
///   does not always set an acquire point before committing. Strict
///   compositors (Hyprland/wlroots) answer with
///   `Gdk-Message: Error 71 (Protocol error) dispatching to Wayland display`
///   and kill the connection. Disabling *explicit sync* removes the trigger
///   while leaving the renderer on the GPU — the fast path.
/// * **X11** — the DMA-BUF renderer can present a blank window. There is no
///   narrower switch, so the whole renderer is disabled; that is the one case
///   where software rendering is the deliberate choice.
///
/// AMD and Intel have neither fault, so nothing is set and the accelerated
/// path is used as-is. A user's explicit `WEBKIT_DISABLE_DMABUF_RENDERER` is
/// always respected, and `RECURSE_WEBKIT_SOFT=1` forces software rendering as
/// an escape hatch.
#[cfg(target_os = "linux")]
fn configure_linux() {
    // A user's explicit choice wins over any detection here.
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some() {
        return;
    }
    if std::env::var("RECURSE_WEBKIT_SOFT").is_ok_and(|v| v != "0") {
        set_env("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        return;
    }
    if !nvidia_present() {
        // AMD/Intel: no known blocker on the accelerated path.
        return;
    }
    if on_wayland() {
        set_env("__NV_DISABLE_EXPLICIT_SYNC", "1");
    } else {
        set_env("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

/// Whether the running session is Wayland, by either signal a process inherits:
/// the compositor socket, or the session type. Falls back to X11 when neither
/// says Wayland, which is the conservative assumption for the X11 workaround.
#[cfg(target_os = "linux")]
fn on_wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE").is_ok_and(|v| v == "wayland")
}

/// Whether an NVIDIA driver is loaded. Both the proprietary and the open kernel
/// module create one of these; AMD and Intel create neither.
#[cfg(target_os = "linux")]
fn nvidia_present() -> bool {
    std::path::Path::new("/proc/driver/nvidia/version").exists()
        || std::path::Path::new("/sys/module/nvidia").exists()
}

/// Set one environment variable before WebKit initializes.
///
/// # Safety
/// The caller guarantees this runs on the startup thread before GTK/WebKit
/// initialize, so no other thread can be reading the environment concurrently.
#[cfg(target_os = "linux")]
fn set_env(key: &str, value: &str) {
    // SAFETY: startup only, before WebKit reads the environment.
    unsafe {
        std::env::set_var(key, value);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    /// The detection helpers read the environment and the filesystem only, so
    /// they are safe to call from a test thread. `configure` itself is not
    /// tested here: it writes the process environment, which would race the
    /// other tests' threads. Its behaviour is exercised by the startup path.
    #[test]
    fn detection_helpers_are_callable() {
        let _ = super::on_wayland();
        let _ = super::nvidia_present();
    }
}
