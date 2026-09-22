//! Debugger glue for the host.
//!
//! The debugger crate is engine-agnostic, so the host supplies the
//! [`Symbols`] implementation (over the live analysis [`Engine`]) and owns the
//! session handle. Commands and the agent tool both route through
//! [`recurse_debug::tool`], so the UI and the agent share one debugger.
//!
//! The debugger blocks in `waitpid` while running, so [`run_op`] is meant to be
//! called from a blocking thread; the handles it needs are `Arc`s precisely so
//! they can be moved there.

use std::sync::{Arc, Mutex, MutexGuard};

use librecurse::engine::Engine;
use recurse_debug::symbols::Symbols;
use recurse_debug::Debugger;
use serde_json::Value;

/// The shared analysis session the host holds (`AppState::session`).
pub type Session = Arc<Mutex<Option<Box<dyn Engine>>>>;

/// The shared debug-session handle (`AppState::debug`).
pub type DebugHandle = Arc<Mutex<Option<Arc<Debugger>>>>;

/// A [`Symbols`] source backed by the live analysis engine.
///
/// Names and addresses come from the engine's discovered functions; the PIE /
/// ASLR load bias is the runtime entry point minus the engine's static entry
/// point (known exactly at the initial stop after a launch).
pub struct EngineSymbols {
    session: Session,
}

impl EngineSymbols {
    /// Wrap the shared analysis session.
    pub fn new(session: Session) -> Self {
        Self { session }
    }

    /// Lock the session, returning `None` when poisoned.
    fn engine(&self) -> Option<MutexGuard<'_, Option<Box<dyn Engine>>>> {
        self.session.lock().ok()
    }
}

impl Symbols for EngineSymbols {
    fn name_at(&self, addr: u64) -> Option<String> {
        let guard = self.engine()?;
        let engine = guard.as_ref()?;
        engine.function_at(addr).ok().flatten().map(|f| f.name)
    }

    fn resolve(&self, name: &str) -> Option<u64> {
        let guard = self.engine()?;
        let engine = guard.as_ref()?;
        engine.resolve(name).ok().flatten()
    }

    fn load_bias(&self, _pid: u32, runtime_entry: Option<u64>) -> Option<u64> {
        let runtime_entry = runtime_entry?;
        let guard = self.engine()?;
        let engine = guard.as_ref()?;
        let static_entry = engine.info().ok()?.get("bin")?.get("entry")?.as_u64()?;
        if static_entry == 0 {
            return Some(0);
        }
        Some(runtime_entry.wrapping_sub(static_entry))
    }
}

/// Build a debugger whose symbols come from the analysis session.
///
/// # Errors
/// [`recurse_debug::Error::Unsupported`] on a platform with no backend.
pub fn build(session: &Session) -> Result<Debugger, String> {
    let symbols = Arc::new(EngineSymbols::new(session.clone()));
    Debugger::with_symbols(symbols).map_err(|e| e.to_string())
}

/// The active debugger, if a session exists.
///
/// # Errors
/// A message when no debug session has been started.
pub fn current(debug: &DebugHandle) -> Result<Arc<Debugger>, String> {
    debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?
        .clone()
        .ok_or_else(|| "no debug session; call `launch` or `attach` first".to_string())
}

/// Store a freshly created debugger as the active session.
///
/// # Errors
/// A message when the lock is poisoned.
pub fn store(debug: &DebugHandle, dbg: Arc<Debugger>) -> Result<(), String> {
    *debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))? = Some(dbg);
    Ok(())
}

/// Clear the active debugger.
///
/// # Errors
/// A message when the lock is poisoned.
pub fn clear(debug: &DebugHandle) -> Result<(), String> {
    *debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))? = None;
    Ok(())
}

/// Run one `debug` op, creating the session for `launch`/`attach` and clearing
/// it for `detach`/`kill`.
///
/// Blocking (the debugger waits in `waitpid`), so call it from a blocking
/// thread.
///
/// # Errors
/// The debugger's own error, or a lock error.
pub fn run_op(
    session: Session,
    debug: DebugHandle,
    op: &str,
    args: &Value,
) -> Result<String, String> {
    if op == "launch" || op == "attach" {
        let dbg = Arc::new(build(&session)?);
        let out = recurse_debug::tool::execute_tool(&dbg, op, args).map_err(|e| e.to_string())?;
        store(&debug, dbg)?;
        return Ok(out);
    }
    let dbg = current(&debug)?;
    let out = recurse_debug::tool::execute_tool(&dbg, op, args).map_err(|e| e.to_string())?;
    if op == "detach" || op == "kill" {
        clear(&debug)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn engine_symbols_resolve_functions() {
        let exe = std::env::current_exe().unwrap();
        let engine: Box<dyn Engine> =
            Box::new(librecurse::native::NativeEngine::open(&exe).unwrap());
        engine.analyze().unwrap();
        let first = engine.functions().unwrap().into_iter().next().unwrap();

        let session: Session = Arc::new(Mutex::new(Some(engine)));
        let symbols = EngineSymbols::new(session);

        // The debugger resolves static addresses through the engine.
        assert_eq!(
            symbols.name_at(first.addr).as_deref(),
            Some(first.name.as_str())
        );
        assert_eq!(symbols.resolve(&first.name), Some(first.addr));
        // The bias needs the engine's static entry point.
        assert!(symbols.load_bias(0, Some(0)).is_some());
    }
}
