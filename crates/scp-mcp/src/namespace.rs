//! Context namespace parsing and built-in tool definitions.
//!
//! MCP tools are namespaced by context: `context_id/tool_name`. This module
//! provides parsing, formatting, and built-in tool definitions for the three
//! standard context operations every context exposes:
//!
//! - `{context}/send_message` -- Send a message to the context.
//! - `{context}/read_messages` -- Read messages from the context.
//! - `{context}/list_members` -- List members of the context.
//!
//! Context-registered tools follow the same pattern: `{context}/{tool_name}`
//! for each tool in the context's tool registry.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use crate::protocol::ToolDefinition;

/// A context identifier string.
///
/// Represented as a plain `String`, matching `scp-core`'s convention.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// Namespace separator
// ---------------------------------------------------------------------------

/// The separator between context ID and tool name in namespaced tool names.
const NAMESPACE_SEPARATOR: char = '/';

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by namespace parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    /// The namespaced tool name is missing the separator.
    #[error("invalid namespaced tool name \"{name}\": missing '/' separator")]
    MissingSeparator {
        /// The invalid tool name.
        name: String,
    },

    /// The context ID portion is empty.
    #[error("invalid namespaced tool name \"{name}\": empty context ID")]
    EmptyContextId {
        /// The invalid tool name.
        name: String,
    },

    /// The tool name portion is empty.
    #[error("invalid namespaced tool name \"{name}\": empty tool name")]
    EmptyToolName {
        /// The invalid tool name.
        name: String,
    },
}

// ---------------------------------------------------------------------------
// Parsing and formatting
// ---------------------------------------------------------------------------

/// Splits a namespaced tool name into `(context_id, tool_name)`.
///
/// The format is `context_id/tool_name`. The first `/` is the split point,
/// so context IDs must not contain `/` but tool names may.
///
/// # Errors
///
/// Returns [`NamespaceError`] if the name is missing the separator, or if
/// either the context ID or tool name portion is empty.
///
/// # Examples
///
/// ```
/// # use scp_mcp::namespace::parse_namespaced_tool;
/// let (ctx, tool) = parse_namespaced_tool("context_a/send_message").unwrap();
/// assert_eq!(ctx, "context_a");
/// assert_eq!(tool, "send_message");
/// ```
pub fn parse_namespaced_tool(name: &str) -> Result<(ContextId, &str), NamespaceError> {
    let sep_pos =
        name.find(NAMESPACE_SEPARATOR)
            .ok_or_else(|| NamespaceError::MissingSeparator {
                name: name.to_owned(),
            })?;

    let context_id = &name[..sep_pos];
    let tool_name = &name[sep_pos + 1..];

    if context_id.is_empty() {
        return Err(NamespaceError::EmptyContextId {
            name: name.to_owned(),
        });
    }

    if tool_name.is_empty() {
        return Err(NamespaceError::EmptyToolName {
            name: name.to_owned(),
        });
    }

    Ok((context_id.to_owned(), tool_name))
}

/// Formats a context ID and tool name into a namespaced tool name.
///
/// # Examples
///
/// ```
/// # use scp_mcp::namespace::format_namespaced_tool;
/// let name = format_namespaced_tool("context_a", "send_message");
/// assert_eq!(name, "context_a/send_message");
/// ```
#[must_use]
pub fn format_namespaced_tool(context_id: &str, tool_name: &str) -> String {
    format!("{context_id}{NAMESPACE_SEPARATOR}{tool_name}")
}

// ---------------------------------------------------------------------------
// Built-in tools
// ---------------------------------------------------------------------------

/// The three built-in tools every SCP context exposes via MCP.
///
/// These are the fundamental context operations that any participant can use
/// (subject to capability checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinTool {
    /// Send a message to the context.
    SendMessage,
    /// Read messages from the context.
    ReadMessages,
    /// List members of the context.
    ListMembers,
}

/// All built-in tool variants for iteration.
pub const BUILTIN_TOOLS: &[BuiltinTool] = &[
    BuiltinTool::SendMessage,
    BuiltinTool::ReadMessages,
    BuiltinTool::ListMembers,
];

impl BuiltinTool {
    /// Returns the tool name suffix (without context prefix).
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::SendMessage => "send_message",
            Self::ReadMessages => "read_messages",
            Self::ListMembers => "list_members",
        }
    }

    /// Returns a human-readable description of the tool.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::SendMessage => "Send a message to this context",
            Self::ReadMessages => "Read messages from this context",
            Self::ListMembers => "List members of this context",
        }
    }

    /// Returns the JSON Schema for the tool's input parameters.
    #[must_use]
    pub fn input_schema(self) -> serde_json::Value {
        match self {
            Self::SendMessage => serde_json::json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The message content to send"
                    }
                },
                "required": ["content"]
            }),
            Self::ReadMessages => serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of messages to return",
                        "default": 50
                    },
                    "before": {
                        "type": "string",
                        "description": "Return messages before this cursor/timestamp"
                    }
                }
            }),
            Self::ListMembers => serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    /// Creates an MCP [`ToolDefinition`] for this built-in tool, namespaced
    /// with the given context ID.
    #[must_use]
    pub fn to_tool_definition(self, context_id: &str) -> ToolDefinition {
        ToolDefinition {
            name: format_namespaced_tool(context_id, self.tool_name()),
            description: Some(self.description().to_owned()),
            input_schema: self.input_schema(),
        }
    }

    /// Attempts to match a tool name suffix to a built-in tool.
    ///
    /// Returns `None` if the name does not match any built-in tool.
    #[must_use]
    pub fn from_tool_name(name: &str) -> Option<Self> {
        match name {
            "send_message" => Some(Self::SendMessage),
            "read_messages" => Some(Self::ReadMessages),
            "list_members" => Some(Self::ListMembers),
            _ => None,
        }
    }
}

/// Returns the MCP [`ToolDefinition`]s for all built-in tools in a context.
///
/// Every SCP context exposes these three tools:
/// - `{context_id}/send_message`
/// - `{context_id}/read_messages`
/// - `{context_id}/list_members`
#[must_use]
pub fn builtin_tool_definitions(context_id: &str) -> Vec<ToolDefinition> {
    BUILTIN_TOOLS
        .iter()
        .map(|tool| tool.to_tool_definition(context_id))
        .collect()
}

/// Creates an MCP [`ToolDefinition`] for a context-registered tool.
///
/// Context-registered tools are namespaced as `{context_id}/{tool_name}`.
/// This is the format for custom tools added to a context's tool registry.
#[must_use]
pub fn context_tool_definition(
    context_id: &str,
    tool_name: &str,
    description: Option<&str>,
    input_schema: serde_json::Value,
) -> ToolDefinition {
    ToolDefinition {
        name: format_namespaced_tool(context_id, tool_name),
        description: description.map(String::from),
        input_schema,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- parse_namespaced_tool ----------------------------------------------

    #[test]
    fn parse_simple_namespaced_tool() {
        let (ctx, tool) = parse_namespaced_tool("context_a/send_message").unwrap();
        assert_eq!(ctx, "context_a");
        assert_eq!(tool, "send_message");
    }

    #[test]
    fn parse_namespaced_tool_with_complex_context_id() {
        let (ctx, tool) = parse_namespaced_tool("did:dht:z6Mk123/read_messages").unwrap();
        assert_eq!(ctx, "did:dht:z6Mk123");
        assert_eq!(tool, "read_messages");
    }

    #[test]
    fn parse_namespaced_tool_splits_on_first_slash() {
        let (ctx, tool) = parse_namespaced_tool("context/sub/tool").unwrap();
        assert_eq!(ctx, "context");
        assert_eq!(tool, "sub/tool");
    }

    #[test]
    fn parse_namespaced_tool_rejects_missing_separator() {
        let err = parse_namespaced_tool("no_separator").unwrap_err();
        assert!(matches!(err, NamespaceError::MissingSeparator { .. }));
    }

    #[test]
    fn parse_namespaced_tool_rejects_empty_context_id() {
        let err = parse_namespaced_tool("/tool_name").unwrap_err();
        assert!(matches!(err, NamespaceError::EmptyContextId { .. }));
    }

    #[test]
    fn parse_namespaced_tool_rejects_empty_tool_name() {
        let err = parse_namespaced_tool("context/").unwrap_err();
        assert!(matches!(err, NamespaceError::EmptyToolName { .. }));
    }

    #[test]
    fn parse_namespaced_tool_rejects_bare_slash() {
        let err = parse_namespaced_tool("/").unwrap_err();
        assert!(matches!(err, NamespaceError::EmptyContextId { .. }));
    }

    #[test]
    fn parse_namespaced_tool_rejects_empty_string() {
        let err = parse_namespaced_tool("").unwrap_err();
        assert!(matches!(err, NamespaceError::MissingSeparator { .. }));
    }

    // -- format_namespaced_tool ---------------------------------------------

    #[test]
    fn format_namespaced_tool_basic() {
        let name = format_namespaced_tool("context_a", "send_message");
        assert_eq!(name, "context_a/send_message");
    }

    #[test]
    fn format_namespaced_tool_with_did_context() {
        let name = format_namespaced_tool("did:dht:z6Mk123", "list_members");
        assert_eq!(name, "did:dht:z6Mk123/list_members");
    }

    // -- parse/format roundtrip ---------------------------------------------

    #[test]
    fn parse_format_roundtrip() {
        let original = "my_context/my_tool";
        let (ctx, tool) = parse_namespaced_tool(original).unwrap();
        let formatted = format_namespaced_tool(&ctx, tool);
        assert_eq!(formatted, original);
    }

    // -- BuiltinTool --------------------------------------------------------

    #[test]
    fn builtin_tool_names() {
        assert_eq!(BuiltinTool::SendMessage.tool_name(), "send_message");
        assert_eq!(BuiltinTool::ReadMessages.tool_name(), "read_messages");
        assert_eq!(BuiltinTool::ListMembers.tool_name(), "list_members");
    }

    #[test]
    fn builtin_tool_descriptions_are_nonempty() {
        for tool in BUILTIN_TOOLS {
            assert!(
                !tool.description().is_empty(),
                "{:?} has empty description",
                tool
            );
        }
    }

    #[test]
    fn builtin_tool_schemas_are_objects() {
        for tool in BUILTIN_TOOLS {
            let schema = tool.input_schema();
            assert!(schema.is_object(), "{:?} schema is not an object", tool);
            assert_eq!(
                schema["type"], "object",
                "{:?} schema type is not 'object'",
                tool
            );
        }
    }

    #[test]
    fn send_message_schema_requires_content() {
        let schema = BuiltinTool::SendMessage.input_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("content")));
    }

    #[test]
    fn read_messages_schema_has_limit_property() {
        let schema = BuiltinTool::ReadMessages.input_schema();
        assert!(schema["properties"]["limit"].is_object());
    }

    #[test]
    fn list_members_schema_has_no_required_fields() {
        let schema = BuiltinTool::ListMembers.input_schema();
        assert!(schema.get("required").is_none());
    }

    #[test]
    fn builtin_tool_to_tool_definition() {
        let def = BuiltinTool::SendMessage.to_tool_definition("ctx_123");
        assert_eq!(def.name, "ctx_123/send_message");
        assert!(def.description.is_some());
        assert_eq!(def.input_schema["type"], "object");
    }

    #[test]
    fn from_tool_name_matches_all_builtins() {
        assert_eq!(
            BuiltinTool::from_tool_name("send_message"),
            Some(BuiltinTool::SendMessage)
        );
        assert_eq!(
            BuiltinTool::from_tool_name("read_messages"),
            Some(BuiltinTool::ReadMessages)
        );
        assert_eq!(
            BuiltinTool::from_tool_name("list_members"),
            Some(BuiltinTool::ListMembers)
        );
    }

    #[test]
    fn from_tool_name_returns_none_for_unknown() {
        assert_eq!(BuiltinTool::from_tool_name("unknown_tool"), None);
        assert_eq!(BuiltinTool::from_tool_name(""), None);
    }

    // -- builtin_tool_definitions -------------------------------------------

    #[test]
    fn builtin_tool_definitions_returns_three_tools() {
        let defs = builtin_tool_definitions("my_context");
        assert_eq!(defs.len(), 3);
    }

    #[test]
    fn builtin_tool_definitions_all_namespaced_correctly() {
        let defs = builtin_tool_definitions("ctx_abc");
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"ctx_abc/send_message"));
        assert!(names.contains(&"ctx_abc/read_messages"));
        assert!(names.contains(&"ctx_abc/list_members"));
    }

    #[test]
    fn builtin_tool_definitions_parseable() {
        let defs = builtin_tool_definitions("test_ctx");
        for def in &defs {
            let (ctx, _tool) = parse_namespaced_tool(&def.name).unwrap();
            assert_eq!(ctx, "test_ctx");
        }
    }

    // -- context_tool_definition --------------------------------------------

    #[test]
    fn context_tool_definition_basic() {
        let def = context_tool_definition(
            "ctx_a",
            "guide_assistant",
            Some("Guide the assistant"),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );
        assert_eq!(def.name, "ctx_a/guide_assistant");
        assert_eq!(def.description.as_deref(), Some("Guide the assistant"));
    }

    #[test]
    fn context_tool_definition_without_description() {
        let def = context_tool_definition(
            "ctx_b",
            "custom_tool",
            None,
            serde_json::json!({"type": "object"}),
        );
        assert!(def.description.is_none());
    }

    #[test]
    fn context_tool_definition_parseable() {
        let def = context_tool_definition(
            "my_ctx",
            "schedule_meeting",
            Some("Schedule a meeting"),
            serde_json::json!({"type": "object"}),
        );
        let (ctx, tool) = parse_namespaced_tool(&def.name).unwrap();
        assert_eq!(ctx, "my_ctx");
        assert_eq!(tool, "schedule_meeting");
    }

    // -- NamespaceError Display ---------------------------------------------

    #[test]
    fn namespace_error_display_missing_separator() {
        let err = NamespaceError::MissingSeparator {
            name: "no_sep".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "invalid namespaced tool name \"no_sep\": missing '/' separator"
        );
    }

    #[test]
    fn namespace_error_display_empty_context_id() {
        let err = NamespaceError::EmptyContextId {
            name: "/tool".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "invalid namespaced tool name \"/tool\": empty context ID"
        );
    }

    #[test]
    fn namespace_error_display_empty_tool_name() {
        let err = NamespaceError::EmptyToolName {
            name: "ctx/".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "invalid namespaced tool name \"ctx/\": empty tool name"
        );
    }

    // -- Serialization roundtrip for tool definitions -----------------------

    #[test]
    fn builtin_tool_definition_serialization_roundtrip() {
        let def = BuiltinTool::SendMessage.to_tool_definition("ctx_ser");
        let json = serde_json::to_string(&def).unwrap();
        let parsed: ToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "ctx_ser/send_message");
        assert!(parsed.description.is_some());
        assert_eq!(parsed.input_schema["type"], "object");
    }

    #[test]
    fn all_builtin_definitions_serialize_to_valid_json() {
        let defs = builtin_tool_definitions("test");
        for def in &defs {
            let json = serde_json::to_value(def).unwrap();
            assert!(json["name"].is_string());
            assert!(json["inputSchema"].is_object());
        }
    }
}
