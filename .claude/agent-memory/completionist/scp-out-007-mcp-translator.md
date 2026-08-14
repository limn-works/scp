---
name: scp-out-007-mcp-translator
description: SCP-OUT-007 scp-mcp lexical outlet↔tool translator re-port audit — all 14 ACs MET but 7 phantom ADR-049 citations
metadata:
  type: project
---

# SCP-OUT-007 lexical MCP↔SCP translator re-port audit @2399b844e (branch fix/outlet-recover-007-mcp, #2219)

Story was DROPPED by squash-merge #2098; re-ported f23ed4923 + review-fixes 2399b844e.

**Verdict: functionally COMPLETE, all 14 ACs MET, but INCOMPLETE on artifact-divergence — 7 phantom ADR-049 citations.**

Why: **Why:** ADR-049 is "Actor-per-Context Concurrency Model" — its §2="Supervisor is a plain struct", §5="OwnedIdentityDid unforgeable ctor", and it has NO §8.5. Code comments cite "ADR-049 §2" for outlet Query/Action classification (correct source=spec §5.4.2 + SCP-OUT-017/ADR-061), "ADR-049 §5" for JCS canonical @type sort (invented detail; ADR-049 §5 unrelated), and "ADR-049 §8.5" for MCP translation (§8.5 is a SPEC section in 08-products; MCP ADR is ADR-015). Sites: lib.rs:14,75; translator.rs:58,126,136,879; tests/translator.rs:12. The pyo3 helper mcp.rs:656 itself cites §5.4.2 (correct) — internal inconsistency proves the ADR-049 refs wrong. **How to apply:** fix per one-way flow: repoint to §8.5/ADR-015 (MCP) and §5.4.2/SCP-OUT-017 (kind); drop/replace the ADR-049 §5 JCS ref.

**Everything else genuine:**
- §8.5.1→§8.5 repoint CORRECT (§8.5 exists spec 08:132 "MCP Compatibility", §8.5.1 does not). Story sources+description repointed too.
- AC3/AC4 rewording HONEST: original cited nonexistent `tests/fixtures/` dir → in-code `fixtures()` corpus (real, 5 fixtures, both round-trip tests iterate + assert). "proptest intentionally omitted (actionItem not AC)" defensible — actionItems separate proptest from fixture tests. NOTE: proptest actionItem genuinely skipped (only place an actionItem not done; not a blocking AC gap).
- AC7 rewording HONEST not scope-shrink: original mis-targeted allowlist.rs as an outlet-name allowlist; allowlist.rs is genuinely a stdio subprocess-COMMAND allowlist (StdioAllowlist, validate_command, node/npx/docker). Property relocated to server.rs (validates on outlet_id :371, emits via format_mcp_tool_name :379) + translator.rs. Intent preserved.
- Payload-recursion bug (the original known bug) FIXED: arguments/_meta move VERBATIM at all 4 sites; 2 regression tests with envelope-colliding keys prove byte-exact survival.
- FFI rename real+atomic: ContextProvider::invoke_tool→invoke_outlet across all 3 bridges (pyo3 mcp.rs:853, napi:380, uniffi:5092) + trait server.rs:168; grep invoke_tool/ContextToolInfo = 0 everywhere. resolvers.rs/runtime.rs/outlets.rs/scp-ffi CLAUDE.md changes doc-comment-ONLY (verified diff).
- Bridge kind NOT hardcoded: outlet_kind_to_mcp(t.kind) pure projection from registry (comment "never hardcode Action here").
- Tests RAN: 248 lib+tests + 13 translator + 5 doctests, 0 fail 0 ignored. AC greps pass (register_tool/invoke_tool=0; query/|call/=0; "query."|"call."=12). No stubs. No stale SCP-TOOL- codes.

LESSON: a coder can correctly repoint a stale spec § (8.5.1→8.5) while simultaneously introducing NEW phantom provenance to the wrong ADR — grep every ADR-NNN citation and read the actual ADR section; a nearby helper citing the RIGHT source (§5.4.2) is the tell.

## RESOLUTION rounds 2-4 (confirming passes @41b81f8bc → 28668cd27 → 338a7667a) — now COMPLETE

Round-2 (41b81f8bc) killed the ADR-049 phantom (grep ADR-049 crates/scp-mcp clean) + adopted canonical `pub use scp_core::context::outlets::OutletKind` (deleted local sentinel enum). BUT the repoint over-corrected: it substituted the ADR-049 phantom with **SCP-OUT-017 cited 6× as owner of the canonical enum / classification gate / authorization gate / scp-mcp handler wiring** — roles SCP-OUT-017 does NOT own. Correct owners (verified vs outlet.json story titles+`files`):
- **canonical OutletKind enum** = SCP-OUT-011 (title "Add OutletKind enum and kind field...scp-protocol"; NOT 017).
- **runtime read-only authorization gate** (resolves kind from registry, blocks Action-as-Query) = SCP-OUT-013 (ReadOnlyInvocation guard) + SCP-OUT-014 (split UCAN stems).
- **SCP-OUT-017** = SDK-surface exposure ONLY; its `files` array is 4 FFI bridges + 4 SDK files, NEVER scp-mcp — so "until SCP-OUT-017 wires the MCP handler" describes work no story scopes.
Two were stale sentinel-era "Until SCP-OUT-017 provides the canonical enum / wires..." leftovers (server.rs:116 untouched by round-2; server.rs:440 round-2-rewrote-but-preserved) contradicting the shipped canonical enum. One was in a SECURITY comment (translator.rs:334) — worst place to mis-cite.

Round-3 (28668cd27, code) repointed all 6 → SCP-OUT-011/013/014, dropped all "Until" phrasing, grep SCP-OUT-017 crates/scp-mcp clean; also bundled a real A3 hardening (error-envelope sibling loop now skips isError/content/_meta so `{"error":{...},"isError":false}` can't re-open fail-open; +1 regression test, 268 pass).
Round-4 (338a7667a, PRD-only 3 lines) swept the SAME phantom out of outlet.json: SCP-OUT-002 desc "kind field added in 017"→011; SCP-OUT-007 desc sentinel/"until 017" premise→present-tense 011 enum + 013 gate + 014 stems + advisory-kind; SCP-OUT-007 auditNote round-3 changelog entry appended (round-2 entry KEPT as honest changelog). After round-4: grep SCP-OUT-017 outlet.json = only structural (gate `stories` array + 017's own id) + changelog auditNote; ZERO story description/AC misattributes. validate-prd pass (442 stories). Code byte-identical to round-3.

**FINAL VERDICT: COMPLETE, zero findings.** All 14 ACs met, 268 tests, no stubs, code+artifact agree.

LESSON 2: killing a phantom cite by *substituting* another story is itself a phantom risk — verify the replacement story ACTUALLY owns the role via its title + `files` array, don't trust the orchestrator's suggested target (here the coordinator itself suggested "§5.4.2 + SCP-OUT-017"; 017 was wrong for the gate/enum roles). LESSON 3: sweep the phantom in BOTH code AND the PRD artifact (description + auditNote) — a code-only fix leaves the story premise + auditNote diverged; keep the superseded round entry as a changelog and append a correcting entry rather than rewriting history.
