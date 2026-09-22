//! librecurse: the agent framework — the LLM run loop ([agent]), its tool
//! runtime ([tools]), and the agent's SQLite-backed memory ([memory] with
//! FTS5/BM25 retrieval).
//!
//! `librecurse` is *only the agent*. Static binary analysis lives in
//! [`recurse_static`] (re-exported here as [`engine`], [`native`], [`r2`],
//! [`r2_backend`], [`signals`] for convenience) and the debugger lives in
//! `recurse-debug`; neither is a reason for the agent to depend on systems
//! code it does not use.
//!
//! The library is storage-agnostic: it never resolves project paths or reads
//! configuration storage itself. Hosts pass everything in through plain
//! interfaces ([agent::LlmConfig], [agent::PromptTarget], tool schemas, file
//! names and directories) and persist whatever they need on their own side.
//!
//! Async throughout (tokio): hosts drive the framework from their own
//! runtime — the library never creates one.

pub mod agent;
pub mod memory;
pub mod tools;

// Static analysis, re-exported so `librecurse::engine` and friends keep
// working for hosts and the eval harness.
pub use recurse_static::{engine, native, r2, r2_backend, signals};
