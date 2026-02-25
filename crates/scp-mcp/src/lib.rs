//! MCP (Model Context Protocol) adapter for SCP.
//!
//! This crate provides the translation layer between MCP-compatible AI models
//! and SCP contexts. It implements:
//!
//! - [`protocol`] -- JSON-RPC 2.0 types and MCP-specific message types
//!   (`Initialize`, `ToolsList`, `ToolsCall`, `ResourcesList`, etc.).
//! - [`namespace`] -- Context namespace parsing (`context_id/tool_name`
//!   splitting) and built-in tool definitions (`send_message`, `read_messages`,
//!   `list_members`).
//!
//! Any MCP-compatible model (Claude, GPT, Gemini, open-source models) can
//! participate in SCP contexts without knowing SCP exists -- it sees MCP tools
//! namespaced by context, calls them, and gets results.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

#![forbid(unsafe_code)]

pub mod namespace;
pub mod protocol;
