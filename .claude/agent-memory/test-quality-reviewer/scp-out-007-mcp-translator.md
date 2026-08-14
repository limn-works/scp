---
name: scp-out-007-mcp-translator
description: SCP-OUT-007 MCP<->SCP lexical translator tests (crates/scp-mcp translator.rs + client.rs) @2399b844e — SHIP with follow-ups
metadata:
  type: project
---

# SCP-OUT-007 MCP↔SCP translator tests @2399b844e (branch fix/outlet-recover-007-mcp)

Two commits: f23ed4923 (initial re-port, HAD the recursion bug) + 2399b844e (payload-verbatim fix + client naming + doc/AC).
Verdict: SHIP. Tests are genuine, not vacuous.

**Payload-verbatim regression tests are LOAD-BEARING (verified against old code by source).**
Old f23ed4923 lines 313/404 did `translate_*_value(args/meta)` (RECURSED). Fix moves `arguments`/`_meta` verbatim (translator.rs mcp_to_scp:317, scp_to_mcp:581/743/411). Regression payload contains a `tools` array → under old recursion `translate_tools_list_result_to_outlet_list` fires and renames tools→outlets → assert_eq to payload() FAILS. So `arguments_with_envelope_colliding_keys_survive_verbatim_both_directions` + `result_meta_with_arbitrary_keys_survives_verbatim` genuinely catch recursion regressions in BOTH directions (each asserts per-direction value + full byte-exact round-trip). nested-collision covered by whole-value assert_eq.
- Minor: many colliding keys are redundant signal (whole-value opaque move means one colliding key like `tools` suffices); extra keys = documentation/defense, not independent signal.

**Client naming tests assert the RIGHT thing.** `invoke_outlet_sends_external_tool_name_verbatim` inspects `transport.sent_requests()[1].params["name"]=="get_weather"` (real wire, load-bearing vs re-prefix). `list_outlets_preserves_verbatim_tool_name_with_advisory_kind` pins verbatim name retains `query.` prefix + advisory kind.

**Round-trip corpus:** duplicated in TWO places — tests/translator.rs `fixtures()` (6) and inline `mcp_corpus()`/`scp_corpus()` (5 each). Both do mcp→scp→mcp and scp→mcp→scp. Covers: list req, call action, call query, notification, list-result. NOT in round-trip corpus: error envelope (separate field-wise test, lossy), Data-chunk streaming (one-directional only).

**GAPS (follow-up, non-blocking):**
1. Non-object `error` value (`{"error":"str"}`) UNTESTED despite explicit comment at scp_to_mcp:507-517 about the peek preventing silent drop. Highest-ROI missing test.
2. x-scp-kind vs name-prefix CONFLICT precedence (has_mcp_kind_prefix wins) untested; only no-prefix+ext path tested (`tool_definition_with_x_scp_kind_extension_infers_kind`).
3. Error-envelope round-trip is field-wise, not byte-exact (genuinely lossy: `scp_message` written outbound at 694 but never read back inbound — dead field; message reconstructed from content text). Not caught by any test.
4. Empty name "", already-`call.`-prefixed inbound, unicode outlet_id — untested (bare `query.` prefix is the closest).

**No flakiness.** Pure JSON fns; serde_json="1" no preserve_order → Value eq order-independent regardless. "stale-binary mtime" was a build-cache artifact, not test nondeterminism. Inline round_trip test couples to internal `strip_x_scp_kind` helper name — acceptable (same-module).
