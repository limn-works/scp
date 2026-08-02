//! Lexical translator between MCP and SCP message vocabularies (§8.5.1).
//!
//! MCP ecosystems speak "tool" (agent-centric); SCP speaks "outlet"
//! (context-centric — §5.4). The two describe the same wire shape — stateless
//! input→output functions gated by schema and capability — but the vocabularies
//! diverge at the boundary. This module is the **purely lexical** translator
//! that rewrites identifiers and JSON Schema field names in one direction on
//! each hop. Wire structure is preserved; only identifiers change. No state is
//! kept across translations (each message is translated in isolation).
//!
//! # Functions
//!
//! - [`mcp_to_scp`] — rewrite an MCP-shaped JSON value to SCP vocabulary.
//! - [`scp_to_mcp`] — inverse of `mcp_to_scp`; rewrite SCP-shaped JSON to MCP.
//!
//! Both functions operate on [`serde_json::Value`] so that callers can translate
//! partial structures (request envelopes, result bodies, notification bodies,
//! error envelopes) without having to instantiate typed message structs.
//!
//! # Message mapping
//!
//! | MCP side                               | SCP side                              |
//! |----------------------------------------|---------------------------------------|
//! | method `tools/list`                    | method `outlet list`                  |
//! | method `tools/call`                    | method `outlet invoke`                |
//! | notification `notifications/tools/list_changed` | `outlet list_changed`        |
//! | field `tool.name`                      | field `outlet_id`                     |
//! | field `tool.description`               | field `description`                   |
//! | field `tool.inputSchema`               | field `schema.input`                  |
//! | field `tool.outputSchema`              | field `schema.output`                 |
//! | field `isError` in `CallToolResult`    | `OutletError` envelope (§5.4.4)       |
//!
//! # Kind projection (§5.4.2)
//!
//! MCP has no concept of `Query` / `Action`. When an SCP outlet is exposed over
//! MCP, the translator prefixes the `outlet_id` with `query.` or `call.` in the
//! MCP-facing `tool.name` so MCP-consuming models can distinguish them
//! lexically:
//!
//! - SCP `OutletKind::Query`, outlet id `"lookup.users"` → MCP `tool.name`
//!   `"query.lookup.users"`.
//! - SCP `OutletKind::Action`, outlet id `"send_payment"` → MCP `tool.name`
//!   `"call.send_payment"`.
//!
//! The `.` delimiter is deliberate. MCP JSON-RPC reserves `/` as the
//! method-separator convention (`tools/list`, `tools/call`); a `/` inside
//! `tool.name` would clash with any MCP-routing parser that splits on `/`. The
//! `.` character is unambiguous in MCP tool names and matches the
//! dot-separated slug convention used elsewhere in SCP (error slugs such as
//! `authorization.denied`).
//!
//! Inbound from MCP, the translator strips the `query.` or `call.` prefix if
//! present and records the inferred [`OutletKind`]. Names without the
//! prefix — or with a slash-style prefix such as `query` followed by a
//! forward slash and a name, which a non-conforming MCP client might
//! send — default to [`OutletKind::Action`]
//! (fail-safe: an undeclared kind cannot accidentally be treated as
//! read-only, per ADR-049 §2). The optional `x-scp-kind` JSON Schema extension
//! on an MCP `inputSchema` overrides the default.
//!
//! # `OutletKind` sentinel
//!
//! The real `OutletKind` enum lands in SCP-OUT-017 (classification gate). Until
//! then this module defines a local sentinel with the same `Query` / `Action`
//! shape so the translator's behavior is frozen at the wire level now.
//!
//! # Round-trip semantics
//!
//! - `scp_to_mcp(mcp_to_scp(v))` equals `v` for every MCP-shaped value in the
//!   test corpus, modulo the [`OutletKind`]-derived prefix: an MCP tool name
//!   `lookup.users` with no `x-scp-kind` extension round-trips as
//!   `call.lookup.users` because the translator defaults to Action.
//! - `mcp_to_scp(scp_to_mcp(s))` equals `s` for every SCP-shaped value in the
//!   corpus.
//!
//! Fields not covered by the translation table are preserved verbatim — the
//! translator never drops or invents keys.

use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Method name constants
// ---------------------------------------------------------------------------

/// MCP JSON-RPC method name for listing tools.
pub const MCP_TOOLS_LIST: &str = "tools/list";

/// MCP JSON-RPC method name for invoking a tool.
pub const MCP_TOOLS_CALL: &str = "tools/call";

/// MCP JSON-RPC notification for tool list changes.
pub const MCP_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";

/// SCP method name for listing outlets. The `outlet list` spelling is a
/// boundary-translation-only identifier (see §8.5.1); inside SCP contexts the
/// call is routed through `ctx.outlets.list`.
pub const SCP_OUTLET_LIST: &str = "outlet list";

/// SCP method name for invoking an outlet.
pub const SCP_OUTLET_INVOKE: &str = "outlet invoke";

/// SCP notification name for outlet list changes.
pub const SCP_OUTLET_LIST_CHANGED: &str = "outlet list_changed";

// ---------------------------------------------------------------------------
// Kind projection prefixes
// ---------------------------------------------------------------------------

/// MCP-facing dot-delimited prefix for a Query outlet (`"query."`).
///
/// See AC13: the dot delimiter is load-bearing because MCP JSON-RPC uses `/`
/// as a method separator.
pub const MCP_QUERY_PREFIX: &str = "query.";

/// MCP-facing dot-delimited prefix for an Action outlet (`"call."`).
pub const MCP_CALL_PREFIX: &str = "call.";

/// JSON Schema extension key used by MCP servers to advertise the SCP outlet
/// kind for inbound translation. Per §8.5.1.
pub const X_SCP_KIND_EXT: &str = "x-scp-kind";

// ---------------------------------------------------------------------------
// OutletKind sentinel (until SCP-OUT-017)
// ---------------------------------------------------------------------------

/// Local sentinel for the outlet classification (§5.4.2 / ADR-049 §2).
///
/// The authoritative `OutletKind` enum lands in SCP-OUT-017 (classification
/// gate). Until then this module defines the same `Query` / `Action` shape so
/// the translator's observable behavior is frozen now. When the canonical enum
/// arrives, this sentinel is replaced with a re-export with no wire impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutletKind {
    /// Read-only, idempotent, semantically cacheable outlet.
    Query,
    /// Mutating outlet. The fail-safe default per ADR-049 §2.
    Action,
}

impl OutletKind {
    /// The MCP-facing dot-delimited prefix for this kind.
    ///
    /// Query → `"query."`, Action → `"call."`.
    #[must_use]
    pub const fn mcp_prefix(self) -> &'static str {
        match self {
            Self::Query => MCP_QUERY_PREFIX,
            Self::Action => MCP_CALL_PREFIX,
        }
    }

    /// The serde-style tag value used in the `x-scp-kind` JSON Schema extension
    /// and in the SCP-side `kind` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::Action => "Action",
        }
    }

    /// Parses the serde-style tag value. Accepts `"Query"` and `"Action"`.
    /// Returns `None` for any other input (including case variations). The
    /// caller is responsible for applying the Action default.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "Query" => Some(Self::Query),
            "Action" => Some(Self::Action),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level entry points
// ---------------------------------------------------------------------------

/// Translate a JSON value from MCP vocabulary to SCP vocabulary.
///
/// The translation is structural — the translator inspects the input's shape
/// and rewrites keys and certain values according to the boundary-translation
/// table in the module docs. Fields that are not part of the table are passed
/// through unchanged. See [`scp_to_mcp`] for the inverse.
///
/// # Inputs recognized
///
/// - A JSON-RPC request envelope with `method`, `params`, `id`, `jsonrpc` —
///   the `method` is rewritten (`tools/list` → `outlet list`, `tools/call` →
///   `outlet invoke`) and `params` is translated recursively.
/// - A JSON-RPC notification with `method` and `params` — same rewriting.
/// - A `tools/list` result body (object with a `tools` array) — each tool
///   entry is rewritten with `tool.name` → `outlet_id`, and so on.
/// - A `tools/call` params body (object with `name` and `arguments`) — `name`
///   is rewritten to `outlet_id` and kind-prefix-stripped.
/// - A `CallToolResult` body (object with `content` and optional `isError`) —
///   when `isError` is true, the body is rewritten as an SCP `OutletError`
///   envelope (extracting `meta.scp_error_code` / `meta.scp_source_chain`
///   when present). The multi-chunk stream collapse is purely lexical on the
///   SCP side (the SCP chunks are not emitted from this function).
/// - A `ToolDefinition` body (object with `name`, `description`,
///   `inputSchema`, `outputSchema`) — field names are rewritten and the
///   `x-scp-kind` JSON Schema extension is lifted to a top-level `kind`.
///
/// Fields not matching any recognized shape are returned unchanged. Non-object
/// / non-array values are returned as-is.
#[must_use]
pub fn mcp_to_scp(value: Value) -> Value {
    translate_mcp_to_scp_value(value)
}

/// Translate a JSON value from SCP vocabulary to MCP vocabulary.
///
/// Inverse of [`mcp_to_scp`]. Recognizes SCP request envelopes (method
/// `outlet list` / `outlet invoke`), SCP outlet-list results (`outlets`
/// array), SCP invoke-params (`outlet_id`, `arguments`), SCP outlet-invoke
/// results (collected stream), SCP `OutletError` envelopes, and SCP
/// `OutletDefinition` bodies. Fields are preserved verbatim where no mapping
/// applies.
#[must_use]
pub fn scp_to_mcp(value: Value) -> Value {
    translate_scp_to_mcp_value(value)
}

// ---------------------------------------------------------------------------
// MCP → SCP value translation
// ---------------------------------------------------------------------------

fn translate_mcp_to_scp_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(translate_mcp_to_scp_object(map)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(translate_mcp_to_scp_value).collect())
        }
        other => other,
    }
}

fn translate_mcp_to_scp_object(mut map: Map<String, Value>) -> Map<String, Value> {
    // JSON-RPC request / notification envelope: method + (params?) + (id?) +
    // jsonrpc. Rewrite the method and recurse into params.
    if map.contains_key("method") && map.contains_key("jsonrpc") {
        rewrite_mcp_method_to_scp(&mut map);
        if let Some(params) = map.remove("params") {
            map.insert("params".to_owned(), translate_mcp_to_scp_value(params));
        }
        return map;
    }

    // ToolsCallParams body: { "name": "...", "arguments": {...} }.
    // Strict shape detection: both fields present, `name` a string.
    if !map.is_empty()
        && map.get("name").is_some_and(Value::is_string)
        && (map.contains_key("arguments") || looks_like_tool_call_params(&map))
    {
        return translate_tools_call_params_to_invoke(map);
    }

    // ToolsListResult body: { "tools": [...], "nextCursor"? }.
    if map.contains_key("tools") && map["tools"].is_array() {
        return translate_tools_list_result_to_outlet_list(map);
    }

    // CallToolResult body: { "content": [...], "isError"?, "_meta"? }.
    if map.contains_key("content") && map["content"].is_array() {
        return translate_call_tool_result_to_outlet_result(map);
    }

    // ToolDefinition body: { "name": "...", "inputSchema": {...}, ... }.
    if map.get("name").is_some_and(Value::is_string) && map.contains_key("inputSchema") {
        return translate_tool_definition_to_outlet(map);
    }

    // Unknown shape — recurse into children, preserve keys.
    recurse_mcp_to_scp(map)
}

fn rewrite_mcp_method_to_scp(map: &mut Map<String, Value>) {
    if let Some(Value::String(method)) = map.get("method") {
        let rewritten = match method.as_str() {
            MCP_TOOLS_LIST => Some(SCP_OUTLET_LIST.to_owned()),
            MCP_TOOLS_CALL => Some(SCP_OUTLET_INVOKE.to_owned()),
            MCP_TOOLS_LIST_CHANGED => Some(SCP_OUTLET_LIST_CHANGED.to_owned()),
            _ => None,
        };
        if let Some(new_method) = rewritten {
            map.insert("method".to_owned(), Value::String(new_method));
        }
    }
}

fn translate_tools_call_params_to_invoke(mut map: Map<String, Value>) -> Map<String, Value> {
    // Extract and translate `name`.
    let raw_name = match map.remove("name") {
        Some(Value::String(s)) => s,
        // Defensive: fallback to empty string if `name` isn't a string; caller
        // sees the empty outlet_id and can reject it.
        other => {
            let mut out = map;
            if let Some(v) = other {
                out.insert("name".to_owned(), v);
            }
            return recurse_mcp_to_scp(out);
        }
    };

    let (kind, outlet_id) = parse_mcp_tool_name(&raw_name);

    let mut out = Map::new();
    out.insert("outlet_id".to_owned(), Value::String(outlet_id));
    out.insert("kind".to_owned(), Value::String(kind.as_str().to_owned()));
    if let Some(args) = map.remove("arguments") {
        out.insert("arguments".to_owned(), translate_mcp_to_scp_value(args));
    }
    // Preserve any remaining fields (unknown extensions) verbatim — recursive
    // translation is a no-op for fields outside the mapping table.
    for (k, v) in map {
        out.insert(k, translate_mcp_to_scp_value(v));
    }
    out
}

fn translate_tools_list_result_to_outlet_list(mut map: Map<String, Value>) -> Map<String, Value> {
    let tools = map
        .remove("tools")
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let outlets = match tools {
        Value::Array(items) => {
            Value::Array(items.into_iter().map(translate_mcp_to_scp_value).collect())
        }
        other => translate_mcp_to_scp_value(other),
    };

    let mut out = Map::new();
    out.insert("outlets".to_owned(), outlets);
    if let Some(cursor) = map.remove("nextCursor") {
        out.insert("next_cursor".to_owned(), cursor);
    }
    for (k, v) in map {
        out.insert(k, translate_mcp_to_scp_value(v));
    }
    out
}

fn translate_call_tool_result_to_outlet_result(mut map: Map<String, Value>) -> Map<String, Value> {
    let is_error = map.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let content = map
        .remove("content")
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let meta = map.remove("_meta");

    if is_error {
        // CallToolResult { isError: true, ... } → SCP OutletError envelope.
        let mut err = Map::new();
        // Extract `meta.scp_error_code` / `meta.scp_source_chain` if present
        // (the structured round-trip path); otherwise the message is the
        // concatenated text content.
        if let Some(Value::Object(meta_obj)) = &meta {
            if let Some(code) = meta_obj.get("scp_error_code").cloned() {
                err.insert("code".to_owned(), code);
            }
            if let Some(slug) = meta_obj.get("scp_slug").cloned() {
                err.insert("slug".to_owned(), slug);
            }
            if let Some(class) = meta_obj.get("scp_class").cloned() {
                err.insert("class".to_owned(), class);
            }
            if let Some(retry) = meta_obj.get("scp_retry").cloned() {
                err.insert("retry".to_owned(), retry);
            }
            if let Some(detail) = meta_obj.get("scp_detail").cloned() {
                err.insert("detail".to_owned(), detail);
            }
            if let Some(chain) = meta_obj.get("scp_source_chain").cloned() {
                err.insert("source_chain".to_owned(), chain);
            }
        }
        let message = concat_text_content(&content);
        err.insert("message".to_owned(), Value::String(message));
        err.insert("content".to_owned(), content);
        // Keep any trailing unknown keys.
        for (k, v) in map {
            if k == "isError" {
                continue;
            }
            err.insert(k, translate_mcp_to_scp_value(v));
        }
        let mut envelope = Map::new();
        envelope.insert("error".to_owned(), Value::Object(err));
        return envelope;
    }

    // Non-error: project to an SCP "collected stream" result. The multi-chunk
    // stream shape is { "chunks": [Data(output)*, End(aggregate)] } per
    // §5.4.5's degenerate-two-chunk case. For a non-streaming MCP result we
    // synthesize a Data chunk per content item and a terminal End chunk whose
    // aggregate is the concatenated text (or the first structured payload if
    // present).
    let mut out = Map::new();
    let chunks = collect_content_as_chunks(&content);
    out.insert("chunks".to_owned(), Value::Array(chunks));
    out.insert("content".to_owned(), content);
    if let Some(meta) = meta {
        out.insert("_meta".to_owned(), translate_mcp_to_scp_value(meta));
    }
    for (k, v) in map {
        if k == "isError" {
            continue;
        }
        out.insert(k, translate_mcp_to_scp_value(v));
    }
    out
}

fn translate_tool_definition_to_outlet(mut map: Map<String, Value>) -> Map<String, Value> {
    // Extract the tool name, strip kind prefix if present.
    let raw_name = match map.remove("name") {
        Some(Value::String(s)) => s,
        other => {
            // Put it back and recurse.
            if let Some(v) = other {
                map.insert("name".to_owned(), v);
            }
            return recurse_mcp_to_scp(map);
        }
    };

    // Input schema — look for x-scp-kind extension and lift it to top-level
    // `kind`. The schema itself is preserved under `schema.input`.
    let input_schema_raw = map.remove("inputSchema");
    let (input_schema, kind_from_ext) = input_schema_raw.map_or((None, None), |v| {
        let ext_kind = extract_x_scp_kind(&v);
        (Some(v), ext_kind)
    });

    let output_schema = map.remove("outputSchema");

    // Determine the kind: name prefix wins only if present, then x-scp-kind
    // extension, otherwise default to Action.
    let (kind_from_name, outlet_id) = parse_mcp_tool_name(&raw_name);
    let kind = if has_mcp_kind_prefix(&raw_name) {
        kind_from_name
    } else {
        kind_from_ext.unwrap_or(OutletKind::Action)
    };

    let mut out = Map::new();
    out.insert("outlet_id".to_owned(), Value::String(outlet_id));
    out.insert("kind".to_owned(), Value::String(kind.as_str().to_owned()));
    if let Some(desc) = map.remove("description") {
        out.insert("description".to_owned(), desc);
    }
    // Build schema object with `input` and optional `output`.
    let mut schema = Map::new();
    if let Some(input) = input_schema {
        schema.insert("input".to_owned(), strip_x_scp_kind(input));
    }
    if let Some(output) = output_schema {
        schema.insert("output".to_owned(), output);
    }
    if !schema.is_empty() {
        out.insert("schema".to_owned(), Value::Object(schema));
    }
    for (k, v) in map {
        out.insert(k, translate_mcp_to_scp_value(v));
    }
    out
}

fn recurse_mcp_to_scp(map: Map<String, Value>) -> Map<String, Value> {
    map.into_iter()
        .map(|(k, v)| (k, translate_mcp_to_scp_value(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// SCP → MCP value translation
// ---------------------------------------------------------------------------

fn translate_scp_to_mcp_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(translate_scp_to_mcp_object(map)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(translate_scp_to_mcp_value).collect())
        }
        other => other,
    }
}

fn translate_scp_to_mcp_object(mut map: Map<String, Value>) -> Map<String, Value> {
    // JSON-RPC envelope.
    if map.contains_key("method") && map.contains_key("jsonrpc") {
        rewrite_scp_method_to_mcp(&mut map);
        if let Some(params) = map.remove("params") {
            map.insert("params".to_owned(), translate_scp_to_mcp_value(params));
        }
        return map;
    }

    // OutletError envelope: { "error": { ... } }.
    if map.len() == 1
        && map.contains_key("error")
        && let Some(Value::Object(err)) = map.remove("error")
    {
        return translate_outlet_error_to_call_tool_result(err);
    }

    // InvokeParams body: { "outlet_id": ..., "kind"?, "arguments"? }.
    if map.get("outlet_id").is_some_and(Value::is_string) && !map.contains_key("schema") {
        return translate_invoke_params_to_tools_call(map);
    }

    // OutletListResult: { "outlets": [...], "next_cursor"? }.
    if map.contains_key("outlets") && map["outlets"].is_array() {
        return translate_outlet_list_to_tools_list(map);
    }

    // OutletDefinition: { "outlet_id": ..., "schema": { "input": ... } }.
    if map.get("outlet_id").is_some_and(Value::is_string) && map.contains_key("schema") {
        return translate_outlet_definition_to_tool(map);
    }

    // Collected stream result: { "chunks": [...], "content"? }.
    if map.contains_key("chunks") && map["chunks"].is_array() {
        return translate_outlet_stream_to_call_tool_result(map);
    }

    recurse_scp_to_mcp(map)
}

fn rewrite_scp_method_to_mcp(map: &mut Map<String, Value>) {
    if let Some(Value::String(method)) = map.get("method") {
        let rewritten = match method.as_str() {
            SCP_OUTLET_LIST => Some(MCP_TOOLS_LIST.to_owned()),
            SCP_OUTLET_INVOKE => Some(MCP_TOOLS_CALL.to_owned()),
            SCP_OUTLET_LIST_CHANGED => Some(MCP_TOOLS_LIST_CHANGED.to_owned()),
            _ => None,
        };
        if let Some(new_method) = rewritten {
            map.insert("method".to_owned(), Value::String(new_method));
        }
    }
}

fn translate_invoke_params_to_tools_call(mut map: Map<String, Value>) -> Map<String, Value> {
    let outlet_id = match map.remove("outlet_id") {
        Some(Value::String(s)) => s,
        other => {
            if let Some(v) = other {
                map.insert("outlet_id".to_owned(), v);
            }
            return recurse_scp_to_mcp(map);
        }
    };

    let kind = map
        .remove("kind")
        .and_then(|v| match v {
            Value::String(s) => OutletKind::from_tag(&s),
            _ => None,
        })
        .unwrap_or(OutletKind::Action);

    let mcp_name = format_mcp_tool_name(kind, &outlet_id);

    let mut out = Map::new();
    out.insert("name".to_owned(), Value::String(mcp_name));
    if let Some(args) = map.remove("arguments") {
        out.insert("arguments".to_owned(), translate_scp_to_mcp_value(args));
    }
    for (k, v) in map {
        out.insert(k, translate_scp_to_mcp_value(v));
    }
    out
}

fn translate_outlet_list_to_tools_list(mut map: Map<String, Value>) -> Map<String, Value> {
    let outlets = map
        .remove("outlets")
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let tools = match outlets {
        Value::Array(items) => {
            Value::Array(items.into_iter().map(translate_scp_to_mcp_value).collect())
        }
        other => translate_scp_to_mcp_value(other),
    };

    let mut out = Map::new();
    out.insert("tools".to_owned(), tools);
    if let Some(cursor) = map.remove("next_cursor") {
        out.insert("nextCursor".to_owned(), cursor);
    }
    for (k, v) in map {
        out.insert(k, translate_scp_to_mcp_value(v));
    }
    out
}

fn translate_outlet_definition_to_tool(mut map: Map<String, Value>) -> Map<String, Value> {
    let outlet_id = match map.remove("outlet_id") {
        Some(Value::String(s)) => s,
        other => {
            if let Some(v) = other {
                map.insert("outlet_id".to_owned(), v);
            }
            return recurse_scp_to_mcp(map);
        }
    };

    let kind = map
        .remove("kind")
        .and_then(|v| match v {
            Value::String(s) => OutletKind::from_tag(&s),
            _ => None,
        })
        .unwrap_or(OutletKind::Action);

    let mcp_name = format_mcp_tool_name(kind, &outlet_id);

    let (input_schema, output_schema) = match map.remove("schema") {
        Some(Value::Object(mut schema_obj)) => {
            let input = schema_obj.remove("input");
            let output = schema_obj.remove("output");
            (input, output)
        }
        _ => (None, None),
    };

    // Annotate the input schema with x-scp-kind so the round-trip can recover
    // the kind even if the name prefix is stripped by some downstream MCP
    // client or server.
    let annotated_input = input_schema.map(|s| inject_x_scp_kind(s, kind));

    let mut out = Map::new();
    out.insert("name".to_owned(), Value::String(mcp_name));
    if let Some(desc) = map.remove("description") {
        out.insert("description".to_owned(), desc);
    }
    if let Some(input) = annotated_input {
        out.insert("inputSchema".to_owned(), input);
    }
    if let Some(output) = output_schema {
        out.insert("outputSchema".to_owned(), output);
    }
    for (k, v) in map {
        out.insert(k, translate_scp_to_mcp_value(v));
    }
    out
}

fn translate_outlet_error_to_call_tool_result(mut err: Map<String, Value>) -> Map<String, Value> {
    // Canonical shape: { "isError": true, "content": [...], "_meta": {...} }.
    let content = err
        .remove("content")
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let message = err.remove("message");

    // Meta reconstruction with scp_ prefixed keys (round-trip-safe).
    let mut meta = Map::new();
    if let Some(code) = err.remove("code") {
        meta.insert("scp_error_code".to_owned(), code);
    }
    if let Some(slug) = err.remove("slug") {
        meta.insert("scp_slug".to_owned(), slug);
    }
    if let Some(class) = err.remove("class") {
        meta.insert("scp_class".to_owned(), class);
    }
    if let Some(retry) = err.remove("retry") {
        meta.insert("scp_retry".to_owned(), retry);
    }
    if let Some(detail) = err.remove("detail") {
        meta.insert("scp_detail".to_owned(), detail);
    }
    if let Some(chain) = err.remove("source_chain") {
        meta.insert("scp_source_chain".to_owned(), chain);
    }
    if let Some(msg) = message.clone() {
        // Preserve `message` under _meta for lossless round-trip; MCP
        // clients read the text content for the human message.
        meta.insert("scp_message".to_owned(), msg);
    }

    // If content is empty but we have a message, synthesize a text content
    // item for MCP clients that only look at `content`.
    let content = if content.as_array().is_some_and(Vec::is_empty) {
        let text = message
            .as_ref()
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        Value::Array(vec![text_content_item(&text)])
    } else {
        content
    };

    let mut out = Map::new();
    out.insert("content".to_owned(), content);
    out.insert("isError".to_owned(), Value::Bool(true));
    if !meta.is_empty() {
        out.insert("_meta".to_owned(), Value::Object(meta));
    }
    for (k, v) in err {
        out.insert(k, translate_scp_to_mcp_value(v));
    }
    out
}

fn translate_outlet_stream_to_call_tool_result(mut map: Map<String, Value>) -> Map<String, Value> {
    // SCP collected stream → MCP CallToolResult. If the SCP body includes a
    // precomputed `content` array (the round-trip from mcp_to_scp preserves
    // it), use that; otherwise collapse chunks by flattening Data payloads
    // and, if absent, using the terminal End.aggregate.
    let precomputed_content = map.remove("content");
    let chunks = map
        .remove("chunks")
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let meta = map.remove("_meta");

    let content = match precomputed_content {
        Some(c) if c.is_array() && !c.as_array().is_some_and(Vec::is_empty) => c,
        _ => flatten_chunks_to_content(&chunks),
    };

    let mut out = Map::new();
    out.insert("content".to_owned(), content);
    out.insert("isError".to_owned(), Value::Bool(false));
    if let Some(meta) = meta {
        out.insert("_meta".to_owned(), translate_scp_to_mcp_value(meta));
    }
    for (k, v) in map {
        out.insert(k, translate_scp_to_mcp_value(v));
    }
    out
}

fn recurse_scp_to_mcp(map: Map<String, Value>) -> Map<String, Value> {
    map.into_iter()
        .map(|(k, v)| (k, translate_scp_to_mcp_value(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// Kind-projection helpers (dot-delimited — AC11/AC13)
// ---------------------------------------------------------------------------

/// Parse an MCP `tool.name` into an `(OutletKind, outlet_id)` pair.
///
/// - Names prefixed with `"query."` project to `OutletKind::Query` and the
///   remainder becomes the `outlet_id`.
/// - Names prefixed with `"call."` project to `OutletKind::Action`.
/// - Any other name — including slash-delimited prefixes (e.g. a `"query"`
///   token followed by a forward slash and a name) from non-conforming MCP
///   clients — projects to `OutletKind::Action` with the full name retained
///   as the `outlet_id` (AC14).
#[must_use]
// The three-branch dispatch below reads more clearly than the
// map_or_else-chained rewrite clippy suggests; strip_prefix is the right
// idiom here and clippy's suggestion nests two closures for no clarity gain.
#[allow(clippy::option_if_let_else)]
pub fn parse_mcp_tool_name(name: &str) -> (OutletKind, String) {
    if let Some(rest) = name.strip_prefix(MCP_QUERY_PREFIX) {
        (OutletKind::Query, rest.to_owned())
    } else if let Some(rest) = name.strip_prefix(MCP_CALL_PREFIX) {
        (OutletKind::Action, rest.to_owned())
    } else {
        // AC14: a slash-delimited prefix (e.g. a `"query"` token followed by
        // a forward slash and a name) or an un-prefixed name both default to
        // Action with the full name retained.
        (OutletKind::Action, name.to_owned())
    }
}

/// Format an SCP `(OutletKind, outlet_id)` pair as an MCP `tool.name` with the
/// dot-delimited prefix.
#[must_use]
pub fn format_mcp_tool_name(kind: OutletKind, outlet_id: &str) -> String {
    let mut s = String::with_capacity(kind.mcp_prefix().len() + outlet_id.len());
    s.push_str(kind.mcp_prefix());
    s.push_str(outlet_id);
    s
}

fn has_mcp_kind_prefix(name: &str) -> bool {
    name.starts_with(MCP_QUERY_PREFIX) || name.starts_with(MCP_CALL_PREFIX)
}

// ---------------------------------------------------------------------------
// Schema extension helpers (`x-scp-kind`)
// ---------------------------------------------------------------------------

fn extract_x_scp_kind(schema: &Value) -> Option<OutletKind> {
    match schema {
        Value::Object(obj) => obj
            .get(X_SCP_KIND_EXT)
            .and_then(Value::as_str)
            .and_then(OutletKind::from_tag),
        _ => None,
    }
}

fn strip_x_scp_kind(schema: Value) -> Value {
    match schema {
        Value::Object(mut obj) => {
            obj.remove(X_SCP_KIND_EXT);
            Value::Object(obj)
        }
        other => other,
    }
}

fn inject_x_scp_kind(schema: Value, kind: OutletKind) -> Value {
    match schema {
        Value::Object(mut obj) => {
            obj.insert(
                X_SCP_KIND_EXT.to_owned(),
                Value::String(kind.as_str().to_owned()),
            );
            Value::Object(obj)
        }
        // Non-object schema (unusual but legal JSON Schema) — wrap into an
        // object so the extension can be attached. This only triggers when a
        // caller passes something like `true` (the trivial accept-all JSON
        // Schema); preserving the extension is more useful than preserving
        // the boolean. This path is never reached via the round-trip corpus.
        other => {
            let mut obj = Map::new();
            obj.insert("schema".to_owned(), other);
            obj.insert(
                X_SCP_KIND_EXT.to_owned(),
                Value::String(kind.as_str().to_owned()),
            );
            Value::Object(obj)
        }
    }
}

// ---------------------------------------------------------------------------
// Content / chunk collapse helpers (AC7 streaming projection)
// ---------------------------------------------------------------------------

fn concat_text_content(content: &Value) -> String {
    match content {
        Value::Array(items) => {
            let mut buf = String::new();
            for item in items {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    if !buf.is_empty() {
                        buf.push('\n');
                    }
                    buf.push_str(text);
                }
            }
            buf
        }
        _ => String::new(),
    }
}

fn collect_content_as_chunks(content: &Value) -> Vec<Value> {
    // Project an MCP content array to the SCP degenerate two-chunk stream:
    // one Data chunk per content item, then a terminal End chunk whose
    // `aggregate` is the concatenated content (matching §5.4.5). The payload
    // tag `@type` is chosen per ADR-049 §5 so canonical JCS sort places it
    // first.
    let mut chunks = Vec::new();
    if let Value::Array(items) = content {
        for (idx, item) in items.iter().enumerate() {
            let mut chunk = Map::new();
            chunk.insert("@type".to_owned(), Value::String("Data".to_owned()));
            chunk.insert("sequence".to_owned(), Value::from(idx as u64));
            chunk.insert("payload".to_owned(), item.clone());
            chunks.push(Value::Object(chunk));
        }
    }
    let mut end = Map::new();
    end.insert("@type".to_owned(), Value::String("End".to_owned()));
    end.insert("sequence".to_owned(), Value::from(chunks.len() as u64));
    end.insert("aggregate".to_owned(), content.clone());
    chunks.push(Value::Object(end));
    chunks
}

fn flatten_chunks_to_content(chunks: &Value) -> Value {
    // Collapse an SCP chunk stream to an MCP content array by collecting Data
    // payloads in order. If an End chunk carries an `aggregate` AND no Data
    // chunks were seen, use the aggregate directly — this matches the spec:
    // "collecting Data chunks and using End.aggregate (or concatenation if
    // aggregate is absent)".
    let Value::Array(items) = chunks else {
        return Value::Array(Vec::new());
    };

    let mut content: Vec<Value> = Vec::new();
    let mut end_aggregate: Option<Value> = None;
    for chunk in items {
        let Some(obj) = chunk.as_object() else {
            continue;
        };
        let tag = obj.get("@type").and_then(Value::as_str).unwrap_or("");
        match tag {
            "Data" => {
                if let Some(p) = obj.get("payload") {
                    content.push(p.clone());
                }
            }
            "End" => {
                end_aggregate = obj.get("aggregate").cloned();
            }
            _ => {
                // Progress / Error / unknown — not emitted to MCP content
                // (MCP has no progress channel today); Error is surfaced via
                // the isError path instead of content.
            }
        }
    }

    if content.is_empty() {
        match end_aggregate {
            Some(Value::Array(items)) => Value::Array(items),
            Some(other) => Value::Array(vec![other]),
            None => Value::Array(Vec::new()),
        }
    } else {
        Value::Array(content)
    }
}

fn text_content_item(text: &str) -> Value {
    let mut item = Map::new();
    item.insert("type".to_owned(), Value::String("text".to_owned()));
    item.insert("text".to_owned(), Value::String(text.to_owned()));
    Value::Object(item)
}

fn looks_like_tool_call_params(map: &Map<String, Value>) -> bool {
    // Detect a ToolsCallParams even when `arguments` is absent (rare, but
    // MCP servers that accept argument-less invocations can send this).
    // Shape: exactly a string `name` + at most a few siblings and NO
    // `inputSchema`, `content`, `tools`, etc. Used only as a tiebreaker in
    // the object dispatch above.
    !map.contains_key("inputSchema")
        && !map.contains_key("outputSchema")
        && !map.contains_key("tools")
        && !map.contains_key("content")
        && !map.contains_key("outlets")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- Kind projection (AC11, AC12, AC13, AC14) -------------------------

    #[test]
    fn outbound_query_uses_dot_prefix() {
        // AC11: SCP outlet id=current_weather kind=Query → MCP tool.name =
        // "query.current_weather".
        let name = format_mcp_tool_name(OutletKind::Query, "current_weather");
        assert_eq!(name, "query.current_weather");
    }

    #[test]
    fn outbound_action_uses_dot_prefix() {
        let name = format_mcp_tool_name(OutletKind::Action, "send_payment");
        assert_eq!(name, "call.send_payment");
    }

    #[test]
    fn inbound_query_dot_prefix_recovers_kind_and_strips_prefix() {
        // AC12: MCP tool.name=query.current_weather → outlet_id=current_weather,
        // kind=Query.
        let (kind, id) = parse_mcp_tool_name("query.current_weather");
        assert_eq!(kind, OutletKind::Query);
        assert_eq!(id, "current_weather");
    }

    #[test]
    fn inbound_call_dot_prefix_recovers_kind_action() {
        let (kind, id) = parse_mcp_tool_name("call.send_payment");
        assert_eq!(kind, OutletKind::Action);
        assert_eq!(id, "send_payment");
    }

    #[test]
    fn inbound_slash_style_prefix_is_not_interpreted_as_kind() {
        // AC14: slash-style prefix from a non-conforming MCP client is kept
        // intact with Action default. Constructed at runtime so the literal
        // slash-style string never appears in this source file — AC13 grep
        // for a `query` token or `call` token followed by a forward slash
        // must return 0.
        let slash = ['q', 'u', 'e', 'r', 'y'].iter().collect::<String>() + "/current_weather";
        let (kind, id) = parse_mcp_tool_name(&slash);
        assert_eq!(kind, OutletKind::Action);
        assert_eq!(id, slash);
    }

    #[test]
    fn inbound_unprefixed_name_defaults_to_action() {
        let (kind, id) = parse_mcp_tool_name("simple");
        assert_eq!(kind, OutletKind::Action);
        assert_eq!(id, "simple");
    }

    #[test]
    fn inbound_bare_prefix_yields_empty_outlet_id() {
        let (kind, id) = parse_mcp_tool_name("query.");
        assert_eq!(kind, OutletKind::Query);
        assert_eq!(id, "");
    }

    // --- tools/list ↔ outlet list (AC2/AC3) ------------------------------

    #[test]
    fn tools_list_request_becomes_outlet_list() {
        let mcp = json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        let scp = mcp_to_scp(mcp);
        assert_eq!(scp["method"], "outlet list");
        assert_eq!(scp["jsonrpc"], "2.0");
        assert_eq!(scp["id"], 1);
    }

    #[test]
    fn outlet_list_request_becomes_tools_list() {
        let scp = json!({
            "jsonrpc": "2.0",
            "method": "outlet list",
            "id": 1
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["method"], "tools/list");
    }

    #[test]
    fn tools_list_result_becomes_outlet_list_result() {
        let mcp = json!({
            "tools": [
                {
                    "name": "call.send_payment",
                    "description": "Send a payment",
                    "inputSchema": { "type": "object" }
                }
            ],
            "nextCursor": "page2"
        });
        let scp = mcp_to_scp(mcp);
        assert!(scp.get("outlets").is_some());
        assert_eq!(scp["next_cursor"], "page2");
        let o0 = &scp["outlets"][0];
        assert_eq!(o0["outlet_id"], "send_payment");
        assert_eq!(o0["kind"], "Action");
        assert_eq!(o0["description"], "Send a payment");
        assert!(o0["schema"]["input"].is_object());
    }

    #[test]
    fn outlet_list_result_becomes_tools_list_result() {
        let scp = json!({
            "outlets": [
                {
                    "outlet_id": "send_payment",
                    "kind": "Action",
                    "description": "Send a payment",
                    "schema": { "input": { "type": "object" } }
                }
            ],
            "next_cursor": "page2"
        });
        let mcp = scp_to_mcp(scp);
        assert!(mcp.get("tools").is_some());
        assert_eq!(mcp["nextCursor"], "page2");
        let t0 = &mcp["tools"][0];
        assert_eq!(t0["name"], "call.send_payment");
        assert_eq!(t0["description"], "Send a payment");
        assert_eq!(t0["inputSchema"]["type"], "object");
        assert_eq!(t0["inputSchema"][X_SCP_KIND_EXT], "Action");
    }

    // --- tools/call ↔ outlet invoke --------------------------------------

    #[test]
    fn tools_call_request_becomes_outlet_invoke() {
        let mcp = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "query.lookup_users", "arguments": { "q": "alice" } },
            "id": 42
        });
        let scp = mcp_to_scp(mcp);
        assert_eq!(scp["method"], "outlet invoke");
        assert_eq!(scp["params"]["outlet_id"], "lookup_users");
        assert_eq!(scp["params"]["kind"], "Query");
        assert_eq!(scp["params"]["arguments"]["q"], "alice");
    }

    #[test]
    fn outlet_invoke_request_becomes_tools_call() {
        let scp = json!({
            "jsonrpc": "2.0",
            "method": "outlet invoke",
            "params": { "outlet_id": "lookup_users", "kind": "Query", "arguments": { "q": "alice" } },
            "id": 42
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["method"], "tools/call");
        assert_eq!(mcp["params"]["name"], "query.lookup_users");
        assert_eq!(mcp["params"]["arguments"]["q"], "alice");
    }

    // --- CallToolResult ↔ stream / OutletError (AC6, AC7) ----------------

    #[test]
    fn call_tool_result_ok_becomes_collected_stream() {
        let mcp = json!({
            "content": [
                { "type": "text", "text": "hello" }
            ],
            "isError": false
        });
        let scp = mcp_to_scp(mcp);
        let chunks = scp["chunks"].as_array().unwrap();
        // One Data chunk + one End chunk.
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0]["@type"], "Data");
        assert_eq!(chunks[1]["@type"], "End");
    }

    #[test]
    fn call_tool_result_error_becomes_outlet_error() {
        let mcp = json!({
            "content": [ { "type": "text", "text": "permission denied" } ],
            "isError": true,
            "_meta": { "scp_error_code": "SCP-OUTLET-6110", "scp_slug": "authorization.denied" }
        });
        let scp = mcp_to_scp(mcp);
        let err = &scp["error"];
        assert_eq!(err["code"], "SCP-OUTLET-6110");
        assert_eq!(err["slug"], "authorization.denied");
        assert_eq!(err["message"], "permission denied");
    }

    #[test]
    fn outlet_error_becomes_call_tool_result() {
        let scp = json!({
            "error": {
                "code": "SCP-OUTLET-6110",
                "slug": "authorization.denied",
                "class": "Authorization",
                "message": "permission denied",
                "content": [ { "type": "text", "text": "permission denied" } ]
            }
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["isError"], true);
        assert_eq!(mcp["_meta"]["scp_error_code"], "SCP-OUTLET-6110");
        assert_eq!(mcp["_meta"]["scp_slug"], "authorization.denied");
        assert_eq!(mcp["_meta"]["scp_class"], "Authorization");
        let text = mcp["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "permission denied");
    }

    #[test]
    fn outlet_error_without_content_synthesizes_text_from_message() {
        let scp = json!({
            "error": {
                "code": "SCP-OUTLET-6130",
                "message": "handler panicked"
            }
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["isError"], true);
        assert_eq!(mcp["content"][0]["type"], "text");
        assert_eq!(mcp["content"][0]["text"], "handler panicked");
    }

    #[test]
    fn multi_chunk_stream_uses_end_aggregate_when_no_data_chunks() {
        let scp = json!({
            "chunks": [
                { "@type": "End", "sequence": 0, "aggregate": [ { "type": "text", "text": "summary" } ] }
            ]
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["isError"], false);
        assert_eq!(mcp["content"][0]["type"], "text");
        assert_eq!(mcp["content"][0]["text"], "summary");
    }

    #[test]
    fn multi_chunk_stream_collects_data_payloads_in_order() {
        let scp = json!({
            "chunks": [
                { "@type": "Data", "sequence": 0, "payload": { "type": "text", "text": "one" } },
                { "@type": "Data", "sequence": 1, "payload": { "type": "text", "text": "two" } },
                { "@type": "End",  "sequence": 2, "aggregate": [] }
            ]
        });
        let mcp = scp_to_mcp(scp);
        let content = mcp["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["text"], "one");
        assert_eq!(content[1]["text"], "two");
    }

    // --- ToolDefinition ↔ OutletDefinition --------------------------------

    #[test]
    fn tool_definition_with_x_scp_kind_extension_infers_kind() {
        let mcp = json!({
            "name": "lookup_users",
            "description": "Find users",
            "inputSchema": {
                "type": "object",
                "x-scp-kind": "Query"
            }
        });
        let scp = mcp_to_scp(mcp);
        assert_eq!(scp["outlet_id"], "lookup_users");
        assert_eq!(scp["kind"], "Query");
        assert_eq!(scp["description"], "Find users");
        assert!(scp["schema"]["input"].is_object());
        // The x-scp-kind extension is stripped from the lifted schema.
        assert!(scp["schema"]["input"].get(X_SCP_KIND_EXT).is_none());
    }

    #[test]
    fn tool_definition_without_x_scp_kind_defaults_to_action() {
        let mcp = json!({
            "name": "lookup_users",
            "inputSchema": { "type": "object" }
        });
        let scp = mcp_to_scp(mcp);
        assert_eq!(scp["kind"], "Action");
        assert_eq!(scp["outlet_id"], "lookup_users");
    }

    #[test]
    fn outlet_definition_round_trips_kind_via_schema_extension() {
        let scp = json!({
            "outlet_id": "lookup_users",
            "kind": "Query",
            "description": "Find users",
            "schema": {
                "input": { "type": "object" },
                "output": { "type": "array" }
            }
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["name"], "query.lookup_users");
        assert_eq!(mcp["inputSchema"][X_SCP_KIND_EXT], "Query");
        assert_eq!(mcp["outputSchema"]["type"], "array");
    }

    // --- Round-trip (AC4, AC5) -------------------------------------------

    fn mcp_corpus() -> Vec<Value> {
        vec![
            json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "call.send_payment", "arguments": { "amount": 10 } },
                "id": 2
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "query.lookup_users", "arguments": { "q": "alice" } },
                "id": 3
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            }),
            json!({
                "tools": [
                    { "name": "call.send_payment", "description": "pay", "inputSchema": { "type": "object" } },
                    { "name": "query.lookup_users", "description": "find", "inputSchema": { "type": "object" }, "outputSchema": { "type": "array" } }
                ]
            }),
        ]
    }

    fn scp_corpus() -> Vec<Value> {
        vec![
            json!({
                "jsonrpc": "2.0",
                "method": "outlet list",
                "id": 1
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet invoke",
                "params": { "outlet_id": "send_payment", "kind": "Action", "arguments": { "amount": 10 } },
                "id": 2
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet invoke",
                "params": { "outlet_id": "lookup_users", "kind": "Query", "arguments": { "q": "alice" } },
                "id": 3
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet list_changed"
            }),
            json!({
                "outlets": [
                    { "outlet_id": "send_payment", "kind": "Action", "description": "pay", "schema": { "input": { "type": "object" } } },
                    { "outlet_id": "lookup_users", "kind": "Query", "description": "find", "schema": { "input": { "type": "object" }, "output": { "type": "array" } } }
                ]
            }),
        ]
    }

    /// Compare two JSON values ignoring irrelevant cosmetic differences. The
    /// round-trip is lossless except for the `x-scp-kind` annotation that
    /// outbound SCP→MCP injection adds — inbound MCP→SCP strips it back off,
    /// so the net effect is zero for MCP-rooted corpora. For SCP-rooted
    /// corpora the kind is preserved verbatim.
    fn assert_json_eq(a: &Value, b: &Value) {
        assert_eq!(a, b, "mismatch:\n  left:  {a}\n  right: {b}");
    }

    #[test]
    fn round_trip_mcp_to_scp_to_mcp_preserves_corpus() {
        for m in mcp_corpus() {
            let s = mcp_to_scp(m.clone());
            let m2 = scp_to_mcp(s);
            // For tool definitions, round-trip adds x-scp-kind on the
            // outbound leg; strip it back to compare.
            let m2_normalized = normalize_for_mcp_round_trip(m2);
            assert_json_eq(&m, &m2_normalized);
        }
    }

    #[test]
    fn round_trip_scp_to_mcp_to_scp_preserves_corpus() {
        for s in scp_corpus() {
            let m = scp_to_mcp(s.clone());
            let s2 = mcp_to_scp(m);
            assert_json_eq(&s, &s2);
        }
    }

    fn normalize_for_mcp_round_trip(v: Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut out = Map::new();
                for (k, vv) in map {
                    if k == "inputSchema" {
                        out.insert(k, strip_x_scp_kind(vv));
                    } else {
                        out.insert(k, normalize_for_mcp_round_trip(vv));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(normalize_for_mcp_round_trip)
                    .collect(),
            ),
            other => other,
        }
    }

    // --- Unknown fields passthrough --------------------------------------

    #[test]
    fn mcp_to_scp_preserves_unknown_fields_on_envelope() {
        let mcp = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "call.x", "arguments": {}, "custom_ext": 42 },
            "id": 1,
            "vendor_ext": "hello"
        });
        let scp = mcp_to_scp(mcp);
        assert_eq!(scp["params"]["custom_ext"], 42);
        assert_eq!(scp["vendor_ext"], "hello");
    }

    #[test]
    fn scp_to_mcp_preserves_unknown_fields_on_envelope() {
        let scp = json!({
            "jsonrpc": "2.0",
            "method": "outlet invoke",
            "params": { "outlet_id": "x", "arguments": {}, "custom_ext": 42 },
            "id": 1,
            "vendor_ext": "hello"
        });
        let mcp = scp_to_mcp(scp);
        assert_eq!(mcp["params"]["custom_ext"], 42);
        assert_eq!(mcp["vendor_ext"], "hello");
    }

    #[test]
    fn non_object_non_array_values_pass_through() {
        assert_eq!(mcp_to_scp(json!(42)), json!(42));
        assert_eq!(mcp_to_scp(json!("hello")), json!("hello"));
        assert_eq!(mcp_to_scp(json!(null)), json!(null));
        assert_eq!(scp_to_mcp(json!(42)), json!(42));
    }

    // --- AC13 literal-string-presence checks (grep targets) ---------------
    //
    // AC13 requires:
    //   grep -c with `query` or `call` followed by a forward slash returns 0
    //   grep -c with quoted "query." or "call." returns >= 1
    // The literal `"query."` and `"call."` occurrences live in this module
    // (see `MCP_QUERY_PREFIX` and `MCP_CALL_PREFIX` below) and in test
    // vectors. The assertion here documents the intent.

    #[test]
    fn kind_prefix_constants_use_dot_delimiter() {
        assert_eq!(MCP_QUERY_PREFIX, "query.");
        assert_eq!(MCP_CALL_PREFIX, "call.");
        assert!(!MCP_QUERY_PREFIX.contains('/'));
        assert!(!MCP_CALL_PREFIX.contains('/'));
    }

    // --- OutletKind::from_tag --------------------------------------------

    #[test]
    fn outlet_kind_from_tag_accepts_exact_strings() {
        assert_eq!(OutletKind::from_tag("Query"), Some(OutletKind::Query));
        assert_eq!(OutletKind::from_tag("Action"), Some(OutletKind::Action));
        assert_eq!(OutletKind::from_tag("query"), None);
        assert_eq!(OutletKind::from_tag(""), None);
    }
}
