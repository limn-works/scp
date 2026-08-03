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
//!   comparison — the §8.5 / ADR-015 round-trip contract permits the
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
                "params": { "outlet_id": "send_payment", "kind": "action", "arguments": { "amount": 10 } },
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
                "params": { "outlet_id": "lookup_users", "kind": "query", "arguments": { "q": "alice" } },
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
                        "kind": "action",
                        "description": "Send a payment",
                        "schema": {
                            "input": { "type": "object", "required": ["amount"] }
                        }
                    },
                    {
                        "outlet_id": "lookup_users",
                        "kind": "query",
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
            "code": scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED,
            "slug": "authorization.denied",
            "class": "Authorization",
            "message": "permission denied",
            "retry": "Never",
            "source_chain": [
                { "context_id": "hmac_abc", "wrapped_code": scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED }
            ],
            "content": [ { "type": "text", "text": "permission denied" } ]
        }
    });
    let mcp = scp_to_mcp(scp_err);
    assert_eq!(mcp["isError"], true);
    assert_eq!(
        mcp["_meta"]["scp_error_code"],
        scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED
    );
    assert_eq!(mcp["_meta"]["scp_slug"], "authorization.denied");
    assert_eq!(mcp["_meta"]["scp_class"], "Authorization");
    assert_eq!(mcp["_meta"]["scp_retry"], "Never");
    assert!(mcp["_meta"]["scp_source_chain"].is_array());

    // Round-trip back — structured fields must reappear in the SCP envelope.
    let back = mcp_to_scp(mcp);
    let err = &back["error"];
    assert_eq!(
        err["code"],
        scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED
    );
    assert_eq!(err["slug"], "authorization.denied");
    assert_eq!(err["class"], "Authorization");
    assert_eq!(err["retry"], "Never");
    assert!(err["source_chain"].is_array());
}

#[test]
fn error_message_richer_than_content_survives_round_trip() {
    // D3 / A2: the SCP error `message` is richer than the MCP text content. The
    // reverse path must recover the ORIGINAL message from `_meta.scp_message`
    // (the A2 read-back), not recompute it from the shorter content text. Fails
    // against the pre-fix write-only channel.
    let rich = "detailed authorization failure: token nb caveat exceeded at edge 3";
    let scp_err = json!({
        "error": {
            "code": scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED,
            "message": rich,
            "content": [ { "type": "text", "text": "denied" } ]
        }
    });
    let mcp = scp_to_mcp(scp_err);
    // The human message is preserved under _meta; content stays the short text.
    assert_eq!(mcp["_meta"]["scp_message"], rich);
    assert_eq!(mcp["content"][0]["text"], "denied");

    let back = mcp_to_scp(mcp);
    assert_eq!(
        back["error"]["message"], rich,
        "the richer scp_message must survive, not be replaced by the content text"
    );
}

#[test]
fn non_object_error_value_is_not_treated_as_error_envelope() {
    // D1 / A3: a message whose `error` field is a non-object (here a string) is
    // NOT an OutletError envelope. It must fall through to verbatim recursion —
    // the value is preserved, not dropped, and no `isError` marker is invented.
    let scp = json!({ "error": "some string" });
    let mcp = scp_to_mcp(scp);
    assert_eq!(mcp["error"], "some string", "non-object error must survive");
    assert!(
        mcp.get("isError").is_none(),
        "a non-object error is not an error envelope; no isError marker"
    );
}

#[test]
fn error_envelope_with_sibling_keys_still_marks_iserror() {
    // A3: an OutletError body carrying an extra sibling key must STILL be
    // recognized as an error (object-typed `error` detection is not gated on
    // len==1) — a sibling must not suppress the MCP isError marker.
    let scp = json!({
        "error": { "code": scp_core::context::outlets::error_codes::CODE_EXECUTION_FAULT, "message": "boom" },
        "trace_id": "tr-9"
    });
    let mcp = scp_to_mcp(scp);
    assert_eq!(
        mcp["isError"], true,
        "sibling key must not suppress isError"
    );
    assert_eq!(
        mcp["_meta"]["scp_error_code"],
        scp_core::context::outlets::error_codes::CODE_EXECUTION_FAULT
    );
    // The sibling is preserved (translated) on the MCP side.
    assert_eq!(mcp["trace_id"], "tr-9");
}

#[test]
fn error_envelope_colliding_sibling_cannot_clobber_iserror() {
    // A3 (round-3): a crafted sibling that collides with a structural field the
    // error translation owns (`isError` / `content` / `_meta`) must NOT
    // overwrite it — otherwise `{"error":{...}, "isError":false}` would flip a
    // real error back to success (fail-open). The colliding siblings are dropped
    // for these owned keys, not applied.
    let scp = json!({
        "error": { "code": scp_core::context::outlets::error_codes::CODE_EXECUTION_FAULT, "message": "boom" },
        "isError": false,
        "content": [ { "type": "text", "text": "not the real content" } ],
        "_meta": { "scp_error_code": "SPOOFED" }
    });
    let mcp = scp_to_mcp(scp);
    assert_eq!(
        mcp["isError"], true,
        "a colliding isError:false sibling must not re-open the fail-open hole"
    );
    // The error translation's own content/_meta win over the crafted siblings.
    assert_eq!(mcp["content"][0]["text"], "boom");
    assert_eq!(
        mcp["_meta"]["scp_error_code"],
        scp_core::context::outlets::error_codes::CODE_EXECUTION_FAULT
    );
}

#[test]
fn iserror_non_bool_true_is_treated_as_error() {
    // A4: a malicious/lenient server sending a non-`false` isError (here the
    // string "true") must be treated as an error, not silently as success.
    let mcp = json!({
        "content": [ { "type": "text", "text": "boom" } ],
        "isError": "true"
    });
    let scp = mcp_to_scp(mcp);
    assert!(
        scp.get("error").is_some(),
        "non-bool isError must map to an SCP error envelope"
    );
    // A literal `false` remains success.
    let ok = mcp_to_scp(json!({
        "content": [ { "type": "text", "text": "ok" } ],
        "isError": false
    }));
    assert!(ok.get("error").is_none(), "isError:false is success");
}

#[test]
fn name_prefix_wins_over_disagreeing_x_scp_kind() {
    // D2: when the tool name prefix and the `x-scp-kind` extension disagree, the
    // NAME PREFIX wins (translate_tool_definition_to_outlet). Here `query.` name
    // vs `x-scp-kind: action` → kind resolves to query.
    let mcp = json!({
        "name": "query.forecast",
        "inputSchema": { "type": "object", "x-scp-kind": "action" }
    });
    let scp = mcp_to_scp(mcp);
    assert_eq!(scp["outlet_id"], "forecast");
    assert_eq!(
        scp["kind"], "query",
        "the dot-prefix on the name takes precedence over x-scp-kind"
    );
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
    assert_eq!(scp["params"]["kind"], "query");
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
// Opaque payload verbatim (regression for the HIGH finding)
// ---------------------------------------------------------------------------
//
// `arguments` and `_meta` are opaque caller payloads. The translator must move
// them VERBATIM and only rewrite envelope identifiers/field names. The old code
// recursed into these payloads and re-ran envelope shape-detection, so a
// payload key like `name` was rewritten to `outlet_id`, `content` was collapsed
// into stream `chunks`, etc. — destroying and inventing keys. These tests use
// payloads whose keys deliberately collide with envelope keys and assert
// byte-exact survival through both round-trip directions; they FAIL against the
// old recursing code and PASS with the pass-through fix.

#[test]
fn arguments_with_envelope_colliding_keys_survive_verbatim_both_directions() {
    // Keys here collide with every envelope key the translator branches on:
    // `name`, `content`, `tools`, `outlets`, `error`, `chunks`, `outlet_id`,
    // `inputSchema`, `isError`. Built fresh per use so no clones are needed.
    let payload = || {
        json!({
            "name": "Alice",
            "outlet_id": "not-an-outlet",
            "content": [ { "type": "text", "text": "hi" } ],
            "tools": [ { "name": "x", "inputSchema": {} } ],
            "outlets": [ "a", "b" ],
            "error": { "code": "not-an-scp-error" },
            "chunks": [ 1, 2, 3 ],
            "isError": true,
            "nested": { "name": "Bob", "tools": [] }
        })
    };

    // --- MCP tools/call → SCP → MCP ---
    let mcp = || {
        json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "call.echo", "arguments": payload() },
            "id": 7
        })
    };
    let scp = mcp_to_scp(mcp());
    assert_eq!(
        scp["params"]["arguments"],
        payload(),
        "arguments corrupted on mcp_to_scp (envelope shape-detection leaked into the payload)"
    );
    let back = scp_to_mcp(scp);
    assert_eq!(back, mcp(), "tools/call did not round-trip byte-for-byte");

    // --- SCP outlet invoke → MCP → SCP ---
    let scp_msg = || {
        json!({
            "jsonrpc": "2.0",
            "method": "outlet invoke",
            "params": { "outlet_id": "echo", "kind": "action", "arguments": payload() },
            "id": 7
        })
    };
    let mcp_out = scp_to_mcp(scp_msg());
    assert_eq!(
        mcp_out["params"]["arguments"],
        payload(),
        "arguments corrupted on scp_to_mcp"
    );
    let scp_back = mcp_to_scp(mcp_out);
    assert_eq!(
        scp_back,
        scp_msg(),
        "outlet invoke did not round-trip byte-for-byte"
    );
}

#[test]
fn result_meta_with_arbitrary_keys_survives_verbatim() {
    // `_meta` is opaque and must pass through byte-for-byte in both directions
    // (no recursion, no scp_* reinterpretation of arbitrary keys).
    let meta = || {
        json!({
            "name": "meta-name",
            "tools": [ "t1" ],
            "outlet_id": "meta-outlet",
            "vendor": { "trace": "abc", "content": [ 1, 2 ] }
        })
    };

    // CallToolResult (non-error) → SCP.
    let mcp = json!({
        "content": [ { "type": "text", "text": "ok" } ],
        "_meta": meta()
    });
    let scp = mcp_to_scp(mcp);
    assert_eq!(scp["_meta"], meta(), "_meta corrupted on mcp_to_scp");

    // Collected-stream result → MCP.
    let scp_stream = json!({
        "chunks": [ { "@type": "End", "sequence": 0, "aggregate": [] } ],
        "_meta": meta()
    });
    let mcp_out = scp_to_mcp(scp_stream);
    assert_eq!(mcp_out["_meta"], meta(), "_meta corrupted on scp_to_mcp");
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
