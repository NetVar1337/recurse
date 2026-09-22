//! Symbol resolution, supplied by the host.
//!
//! The debugger is symbol-agnostic: internally it works in addresses. The host
//! implements [`Symbols`] over its analysis engine, so the debugger can accept
//! symbol names and name stack frames without depending on `librecurse`.

/// Resolves between names and addresses and reports the load bias.
pub trait Symbols: Send + Sync {
    /// Static (link-time) name for a static address, if known.
    fn name_at(&self, addr: u64) -> Option<String>;

    /// Static address for a symbol name, if known.
    fn resolve(&self, name: &str) -> Option<u64>;

    /// `runtime - static` address for a process (the ASLR/PIE load bias).
    ///
    /// `runtime_entry` is the program counter at the initial stop after a
    /// launch (the entry point as loaded); `None` when attaching, where the
    /// host falls back to a best-effort guess. Returning `None` makes the
    /// session assume a bias of `0`.
    fn load_bias(&self, pid: u32, runtime_entry: Option<u64>) -> Option<u64>;
}

/// A [`Symbols`] that knows nothing — addresses only, frames unnamed.
///
/// ```
/// use recurse_debug::symbols::{NoSymbols, Symbols};
/// assert!(NoSymbols.resolve("main").is_none());
/// assert!(NoSymbols.name_at(0x401000).is_none());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSymbols;

impl Symbols for NoSymbols {
    fn name_at(&self, _addr: u64) -> Option<String> {
        None
    }

    fn resolve(&self, _name: &str) -> Option<u64> {
        None
    }

    fn load_bias(&self, _pid: u32, _runtime_entry: Option<u64>) -> Option<u64> {
        None
    }
}
