#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
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
//! - [`translator`] -- Purely lexical `outlet` ↔ `tool` boundary translation
//!   per §8.5 / ADR-049. MCP messages inbound are rewritten to SCP outlet
//!   vocabulary; SCP messages outbound are rewritten to MCP tool vocabulary.
//!   Only ENVELOPE identifiers and field names are translated (method names,
//!   `tool.name` ↔ `outlet_id`, schema field names, the error envelope); opaque
//!   caller payloads (`arguments`, `_meta`) pass through VERBATIM. Wire shape is
//!   preserved in both directions; each message is translated in isolation (no
//!   state is kept across translations).
//! - [`server`] -- MCP server: tool listing with capability filtering,
//!   outlet invocation routing, resource listing/reading/subscriptions, and
//!   MCP lifecycle handling. Uses SCP outlet vocabulary internally; the MCP
//!   wire boundary goes through [`translator`].
//! - [`client`] -- MCP client used by an SCP agent to consume tools from
//!   external MCP servers. It speaks MCP directly on the wire (the external
//!   server owns its tool naming); [`client::McpClient::list_outlets`] and
//!   [`client::McpClient::invoke_outlet`] expose an SCP-vocabulary surface that
//!   carries each tool's verbatim `tool.name` and an advisory outlet `kind`.
//!   Payloads are not envelope-translated on this path.
//!
//! Any MCP-compatible model (Claude, GPT, Gemini, open-source models) can
//! participate in SCP contexts without knowing SCP exists — it sees MCP tools
//! namespaced by context, calls them, and gets results.
//!
//! # Example: outbound tools/list round-trip
//!
//! ```
//! use scp_mcp::translator::{mcp_to_scp, scp_to_mcp};
//! use serde_json::json;
//!
//! // An MCP client sends tools/list; the SCP agent translates it to
//! // outlet list before routing.
//! let mcp = json!({
//!     "jsonrpc": "2.0",
//!     "method": "tools/list",
//!     "id": 1
//! });
//! let scp = mcp_to_scp(mcp.clone());
//! assert_eq!(scp["method"], "outlet list");
//!
//! // The reverse converts an SCP message back to MCP wire format.
//! let mcp_again = scp_to_mcp(scp);
//! assert_eq!(mcp_again["method"], "tools/list");
//! ```
//!
//! # Example: kind-aware tools/call round-trip
//!
//! ```
//! use scp_mcp::translator::{mcp_to_scp, OutletKind};
//! use serde_json::json;
//!
//! let mcp = json!({
//!     "jsonrpc": "2.0",
//!     "method": "tools/call",
//!     "params": { "name": "query.lookup_users", "arguments": { "q": "alice" } },
//!     "id": 42
//! });
//! let scp = mcp_to_scp(mcp);
//! assert_eq!(scp["params"]["outlet_id"], "lookup_users");
//! assert_eq!(scp["params"]["kind"], "Query");
//! # let _ = OutletKind::Query;
//! ```
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` and ADR-049 §8.5 for the full
//! design.

#![forbid(unsafe_code)]

pub mod allowlist;
pub mod client;
pub mod namespace;
pub mod protocol;
pub mod server;
pub mod sse;
pub mod stdio;
pub mod translator;
