//! librecurse: independent agent framework — the LLM run loop ([agent]),
//! its tool runtime ([tools]), and the agent's file-backed memory ([memory]).
//!
//! The library is storage-agnostic: it never resolves project paths or reads
//! configuration storage itself. Hosts pass everything in through plain
//! interfaces ([agent::LlmConfig], [agent::PromptTarget], tool schemas, file
//! names and directories) and persist whatever they need on their own side.

pub mod agent;
pub mod memory;
pub mod tools;
