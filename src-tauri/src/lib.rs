pub mod agent;
pub mod cli;
pub mod commands;
pub mod config;
pub mod debugger;
pub mod engine;
pub mod memory;
pub mod process;
pub mod project;
pub mod sandbox;
pub mod session;
pub mod sessions;
pub mod shell;
/// Test-only helpers (HOME isolation). Hidden from docs but compiled so the
/// integration tests can share it.
#[doc(hidden)]
pub mod testhome;
pub mod tools;

use std::sync::{atomic::AtomicBool, atomic::AtomicU32, Arc, Mutex};

use agent::{Agent, LlmConfig, ModelInfo};

/// WebKitGTK registers a `GtkGestureZoom` on the web view under the data key
/// `"wk-view-zoom-gesture"` that scales the whole page on trackpad pinch. Tauri
/// exposes no setting to disable it (upstream limitation) and JS/CSS cannot
/// cancel it, so we destroy that gesture's signal handlers. The app keeps its
/// own Ctrl+/−/0 keyboard zoom via the `set_zoom` command.
#[cfg(target_os = "linux")]
fn disable_pinch_zoom(app: &tauri::App) {
    use glib::prelude::ObjectExt;
    use tauri::Manager;

    let Some(webview) = app.get_webview_window("main") else {
        eprintln!("[recurse] no main webview; skipping pinch-zoom disable");
        return;
    };
    let _ = webview.with_webview(|wv| unsafe {
        let inner = wv.inner();
        if let Some(gesture) = inner.data::<()>("wk-view-zoom-gesture") {
            glib::gobject_ffi::g_signal_handlers_destroy(
                gesture.as_ptr() as *mut glib::gobject_ffi::GObject
            );
            eprintln!("[recurse] disabled WebKitGTK pinch-zoom gesture");
        } else {
            eprintln!("[recurse] wk-view-zoom-gesture not found");
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn disable_pinch_zoom(_app: &tauri::App) {}

pub struct AppState {
    pub session: Arc<Mutex<Option<session::R2Session>>>,
    pub debug: Arc<Mutex<Option<session::R2Session>>>,
    pub debug_stdin: Arc<Mutex<Option<std::fs::File>>>,
    /// True while a `dc` (continue) is in flight. Gates inspection commands
    /// (fail fast) and guarantees a single concurrent continue.
    pub debug_busy: Arc<AtomicBool>,
    /// PID of the r2 process backing the debug session, published by
    /// `debug_start` before the session becomes visible and cleared on
    /// teardown. Lets stop/interrupt reach a blocked continue without needing
    /// the debug mutex it holds.
    pub debug_pid: Arc<AtomicU32>,
    /// Stop flag for the live debuggee-stdout pump thread.
    pub debug_output_done: Arc<AtomicBool>,
    /// Rolling console buffer of raw debuggee output (capped).
    pub debug_output: Arc<Mutex<Vec<u8>>>,
    pub agent: Arc<Mutex<Agent>>,
    pub llm: Mutex<LlmConfig>,
    pub models: Mutex<Option<Vec<ModelInfo>>>,
    pub project: Mutex<Option<project::Project>>,
    pub current_session: Mutex<Option<String>>,
    pub shell: shell::ShellManager,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Belt-and-suspenders Wayland fix for direct `cargo run` / tests
    // without going through `main.rs`. Mirrors the env setup in `main.rs`.
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WEBKIT_DISABLE_DMABUF_RENDERER").is_err() {
            // SAFETY: still before GTK/WebKit init, single-threaded setup path.
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            }
        }
    }
    // Startup failure is unrecoverable by design: without an event loop
    // there is no app. This is the one sanctioned expect().
    #[allow(clippy::expect_used)]
    fn die_on_failure(result: tauri::Result<()>) {
        result.expect("error while running tauri application");
    }

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            sessions::cleanup_legacy();
            disable_pinch_zoom(app);
            Ok(())
        })
        .manage(AppState {
            session: Arc::new(Mutex::new(None)),
            debug: Arc::new(Mutex::new(None)),
            debug_stdin: Arc::new(Mutex::new(None)),
            debug_busy: Arc::new(AtomicBool::new(false)),
            debug_pid: Arc::new(AtomicU32::new(0)),
            debug_output_done: Arc::new(AtomicBool::new(false)),
            debug_output: Arc::new(Mutex::new(Vec::new())),
            agent: Arc::new(Mutex::new(Agent::new())),
            llm: Mutex::new(LlmConfig::default()),
            models: Mutex::new(None),
            project: Mutex::new(None),
            current_session: Mutex::new(None),
            shell: shell::ShellManager::new(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::open_binary,
            commands::analyze,
            commands::close_binary,
            commands::binary_info,
            commands::functions,
            commands::disassemble,
            commands::function_at,
            commands::function_disasm,
            commands::function_graph,
            commands::strings,
            commands::imports,
            commands::xrefs_to,
            commands::decompile,
            commands::raw,
            commands::set_zoom,
            commands::agent_chat,
            commands::agent_cancel_run,
            commands::agent_reset,
            commands::agent_history,
            commands::sessions_list,
            commands::sessions_create,
            commands::sessions_select,
            commands::sessions_delete,
            commands::sessions_rename,
            commands::debug_start,
            commands::debug_command,
            commands::debug_interrupt,
            commands::debug_stop,
            commands::debug_stdin,
            commands::debug_registers,
            commands::debug_output_get,
            commands::sandbox_status,
            commands::debug_disassemble,
            commands::debug_breakpoints,
            commands::llm_status,
            commands::set_model,
            commands::save_api_key,
            commands::list_models,
            commands::list_projects,
            commands::create_project,
            commands::open_project,
            commands::delete_project,
            commands::project_read_file,
            commands::project_write_file,
            commands::project_list_files,
            commands::shell_spawn,
            commands::shell_write,
            commands::shell_resize,
            commands::shell_kill,
            commands::shell_list,
        ]);

    die_on_failure(builder.run(tauri::generate_context!()));
}
