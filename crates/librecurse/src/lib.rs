//! librecurse: independent agent framework — the LLM run loop ([agent])
//! and its tool runtime ([tools]).
//!
//! The library is storage-agnostic: it never touches the filesystem for
//! configuration or state. Hosts pass everything in through plain interfaces
//! ([agent::LlmConfig], tool schemas, file-name arguments) and persist
//! whatever they need on their own side.

pub mod agent;
pub mod tools;
