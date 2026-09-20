//! librecurse: independent agent framework — the LLM run loop ([agent]),
//! its tool runtime ([tools]), native radare2 access ([r2]), and the agent's
//! SQLite-backed memory ([memory] with FTS5/BM25 retrieval).
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
pub mod r2;
pub mod tools;
