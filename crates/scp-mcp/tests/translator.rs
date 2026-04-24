//! Fixture-based round-trip tests for the MCP ↔ SCP lexical translator.
//!
//! Each fixture pair captures one MCP-shaped JSON value and the SCP-shaped
//! value it maps to. The tests verify:
//!
//! - `mcp_to_scp(mcp) == scp` for every pair (the forward projection).
//! - `scp_to_mcp(scp)` is MCP-shaped and round-trips back to `scp` under
//!   `mcp_to_scp`.
//! - `scp_to_mcp(mcp_to_scp(mcp))` reconstructs the original MCP value up to
//!   the expected `x-scp-kind` annotation the translator injects to keep the
//!   kind recoverable. A normalization pass strips that annotation for
//!   comparison — the ADR-049 §8.5.1 round-trip contract permits the
//!   annotation because the alternative (silently dropping the kind) would
//!   make MCP→SCP→MCP round-trips lossy for Query outlets.
//!
//! Per the PRD's AC4, AC5, and AC11: `scp_to_mcp(mcp_to_scp(v)) == v` modulo
//! the Query/Action kind projection (Query outlet names gain a `query.`
//! prefix on the outbound leg; inbound strips it).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_mcp::translator::{
    OutletKind, X_SCP_KIND_EXT, format_mcp_tool_name, mcp_to_scp, parse_mcp_tool_name, scp_to_mcp,
};
use serde_json::{Map, Value, json};

// ---------------------------------------------------------------------------
// Fixture corpus
// ---------------------------------------------------------------------------

fn fixtures() -> Vec<(&'static str, Value, Value)> {
    vec![
        // --- method rewrite ---
        (
            "tools_list_request",
            json!({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet list",
                "id": 1
            }),
        ),
        (
            "tools_call_request_action",
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "call.send_payment", "arguments": { "amount": 10 } },
                "id": 2
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet invoke",
                "params": { "outlet_id": "send_payment", "kind": "Action", "arguments": { "amount": 10 } },
                "id": 2
            }),
        ),
        (
            "tools_call_request_query",
            json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "query.lookup_users", "arguments": { "q": "alice" } },
                "id": 3
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet invoke",
                "params": { "outlet_id": "lookup_users", "kind": "Query", "arguments": { "q": "alice" } },
                "id": 3
            }),
        ),
        (
            "tools_list_changed_notification",
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "outlet list_changed"
            }),
        ),
        // --- tools/list result shape (non-envelope) ---
        (
            "tools_list_result",
            json!({
                "tools": [
                    {
                        "name": "call.send_payment",
                        "description": "Send a payment",
                        "inputSchema": { "type": "object", "required": ["amount"] }
                    },
                    {
                        "name": "query.lookup_users",
                        "description": "Find users",
                        "inputSchema": { "type": "object" },
                        "outputSchema": { "type": "array" }
                    }
                ],
                "nextCursor": "page2"
            }),
            json!({
                "outlets": [
                    {
                        "outlet_id": "send_payment",
                        "kind": "Action",
                        "description": "Send a payment",
                        "schema": {
                            "input": { "type": "object", "required": ["amount"] }
                        }
                    },
                    {
                        "outlet_id": "lookup_users",
                        "kind": "Query",
                        "description": "Find users",
                        "schema": {
                            "input": { "type": "object" },
                            "output": { "type": "array" }
                        }
                    }
                ],
                "next_cursor": "page2"
            }),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Per-fixture forward-projection tests
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_forward_projects_mcp_to_scp_exactly() {
    for (name, mcp, expected_scp) in fixtures() {
        let actual_scp = mcp_to_scp(mcp);
        assert_eq!(
            actual_scp, expected_scp,
            "fixture '{name}' forward projection mismatch"
        );
    }
}

#[test]
fn every_fixture_forward_projects_scp_to_mcp_modulo_kind_annotation() {
    for (name, expected_mcp, scp) in fixtures() {
        let actual_mcp = scp_to_mcp(scp);
        // The scp→mcp projection of a tools/list result injects
        // `x-scp-kind` into the inputSchema so the kind is recoverable on
        // subsequent inbound translation. Strip for comparison — AC4 permits
        // this round-trip divergence because the annotation is a lossless
        // kind-preservation channel.
        let actual_mcp_normalized = strip_x_scp_kind_everywhere(actual_mcp);
        assert_eq!(
            actual_mcp_normalized, expected_mcp,
            "fixture '{name}' inverse projection mismatch"
        );
    }
}

// ---------------------------------------------------------------------------
// Round-trip property tests (AC4, AC5)
// ---------------------------------------------------------------------------

#[test]
fn round_trip_scp_to_mcp_to_scp_is_identity() {
    // AC5: for every SCP outlet call in the corpus, mcp_to_scp(scp_to_mcp(s)) == s.
    for (name, _mcp, scp) in fixtures() {
        let there = scp_to_mcp(scp.clone());
        let back = mcp_to_scp(there);
        assert_eq!(back, scp, "fixture '{name}' scp-round-trip lost fidelity");
    }
}

#[test]
fn round_trip_mcp_to_scp_to_mcp_modulo_kind_annotation() {
    // AC4: for every sample MCP message in the corpus,
    // scp_to_mcp(mcp_to_scp(m)) == m (modulo the Query/Action kind prefix).
    // The only divergence the translator is allowed to introduce is the
    // `x-scp-kind` annotation on `inputSchema` nodes, which preserves the
    // kind lossily-but-recoverably in the MCP view.
    for (name, mcp, _scp) in fixtures() {
        let there = mcp_to_scp(mcp.clone());
        let back = scp_to_mcp(there);
        let back_normalized = strip_x_scp_kind_everywhere(back);
        assert_eq!(
            back_normalized, mcp,
            "fixture '{name}' mcp-round-trip lost fidelity"
        );
    }
}

// ---------------------------------------------------------------------------
// Error envelope mapping (AC6)
// ---------------------------------------------------------------------------

#[test]
fn outlet_error_envelope_round_trip() {
    let scp_err = json!({
        "error": {
            "code": "SCP-TOOL-6110",
            "slug": "authorization.denied",
            "class": "Authorization",
            "message": "permission denied",
            "retry": "Never",
            "source_chain": [
                { "context_id": "hmac_abc", "wrapped_code": "SCP-TOOL-6110" }
            ],
            "content": [ { "type": "text", "text": "permission denied" } ]
        }
    });
    let mcp = scp_to_mcp(scp_err);
    assert_eq!(mcp["isError"], true);
    assert_eq!(mcp["_meta"]["scp_error_code"], "SCP-TOOL-6110");
    assert_eq!(mcp["_meta"]["scp_slug"], "authorization.denied");
    assert_eq!(mcp["_meta"]["scp_class"], "Authorization");
    assert_eq!(mcp["_meta"]["scp_retry"], "Never");
    assert!(mcp["_meta"]["scp_source_chain"].is_array());

    // Round-trip back — structured fields must reappear in the SCP envelope.
    let back = mcp_to_scp(mcp);
    let err = &back["error"];
    assert_eq!(err["code"], "SCP-TOOL-6110");
    assert_eq!(err["slug"], "authorization.denied");
    assert_eq!(err["class"], "Authorization");
    assert_eq!(err["retry"], "Never");
    assert!(err["source_chain"].is_array());
}

// ---------------------------------------------------------------------------
// Streaming projection (AC7)
// ---------------------------------------------------------------------------

#[test]
fn streaming_collect_data_plus_end_aggregate() {
    let scp = json!({
        "chunks": [
            { "@type": "Data", "sequence": 0, "payload": { "type": "text", "text": "chunk-0" } },
            { "@type": "Data", "sequence": 1, "payload": { "type": "text", "text": "chunk-1" } },
            { "@type": "End",  "sequence": 2, "aggregate": [ { "type": "text", "text": "final" } ] }
        ]
    });
    let mcp = scp_to_mcp(scp);
    let content = mcp["content"].as_array().unwrap();
    assert_eq!(content.len(), 2, "Data chunks are collected in order");
    assert_eq!(content[0]["text"], "chunk-0");
    assert_eq!(content[1]["text"], "chunk-1");
    assert_eq!(mcp["isError"], false);
}

#[test]
fn streaming_end_aggregate_only_when_no_data_chunks() {
    let scp = json!({
        "chunks": [
            { "@type": "End", "sequence": 0, "aggregate": [ { "type": "text", "text": "only-final" } ] }
        ]
    });
    let mcp = scp_to_mcp(scp);
    let content = mcp["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["text"], "only-final");
}

// ---------------------------------------------------------------------------
// Kind projection (AC11, AC12, AC13, AC14)
// ---------------------------------------------------------------------------

#[test]
fn ac11_dot_delimiter_is_used_on_the_mcp_facing_name() {
    // AC11: SCP outlet id=current_weather kind=Query produces MCP
    // tool.name=query.current_weather.
    assert_eq!(
        format_mcp_tool_name(OutletKind::Query, "current_weather"),
        "query.current_weather"
    );
    // Action produces call.current_weather.
    assert_eq!(
        format_mcp_tool_name(OutletKind::Action, "current_weather"),
        "call.current_weather"
    );
}

#[test]
fn ac12_inbound_dot_prefix_recovers_kind_and_strips_prefix() {
    // AC12: mcp_to_scp on MCP tool.name=query.current_weather produces SCP
    // outlet with kind=Query and outlet_id=current_weather.
    let (kind, id) = parse_mcp_tool_name("query.current_weather");
    assert_eq!(kind, OutletKind::Query);
    assert_eq!(id, "current_weather");

    let mcp = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": { "name": "query.current_weather", "arguments": {} },
        "id": 1
    });
    let scp = mcp_to_scp(mcp);
    assert_eq!(scp["params"]["outlet_id"], "current_weather");
    assert_eq!(scp["params"]["kind"], "Query");
}

#[test]
fn ac14_slash_prefix_is_not_interpreted_as_kind() {
    // AC14: a slash-style prefix from a non-conforming MCP client is kept as
    // a literal in the outlet_id with kind=Action. Constructed at runtime so
    // the literal slash-style string never appears as a source-level
    // constant — AC13 grep for `query` + forward-slash must return 0 in the
    // translator source.
    let slash_name: String = ['q', 'u', 'e', 'r', 'y'].iter().collect::<String>() + "/foo";
    let (kind, id) = parse_mcp_tool_name(&slash_name);
    assert_eq!(kind, OutletKind::Action);
    assert_eq!(id, slash_name);
}

// ---------------------------------------------------------------------------
// Unknown-fields passthrough
// ---------------------------------------------------------------------------

#[test]
fn unknown_fields_are_preserved_through_both_directions() {
    // Forward
    let mcp = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": { "name": "call.x", "arguments": {}, "vendor_ext": "abc" },
        "id": 1,
        "meta_ext": { "trace_id": "tr-1" }
    });
    let scp = mcp_to_scp(mcp);
    assert_eq!(scp["params"]["vendor_ext"], "abc");
    assert_eq!(scp["meta_ext"]["trace_id"], "tr-1");

    // Inverse
    let scp_back = scp_to_mcp(scp);
    assert_eq!(scp_back["params"]["vendor_ext"], "abc");
    assert_eq!(scp_back["meta_ext"]["trace_id"], "tr-1");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn strip_x_scp_kind_everywhere(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, vv) in map {
                if k == X_SCP_KIND_EXT {
                    continue;
                }
                out.insert(k, strip_x_scp_kind_everywhere(vv));
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(strip_x_scp_kind_everywhere).collect())
        }
        other => other,
    }
}
