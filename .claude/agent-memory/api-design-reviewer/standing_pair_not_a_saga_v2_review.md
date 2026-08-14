---
name: standing-pair-not-a-saga-v2-review
description: API review of spec/standing-pair-not-a-saga-v2 — reclassify standing-pair create from 3rd saga to single-context async; saga surface drops 3→2
metadata:
  type: project
---

Branch `spec/standing-pair-not-a-saga-v2` (docs-only) reclassifies standing-pair creation from a cross-context saga to a single-context async op.

**Decision content (durable):** A standing pair is ONE 2-member MLS group (both parties derive identical `derived_context_id`), so creation is ordinary `create + add_member + Welcome`, NOT a saga. Consequence for API surface: standing-pair creation has NO `start_*_saga` FFI export — it stays the existing `standing_context(peer)` get-or-create call. ADR-049 §3a now enumerates exactly TWO saga FFI exports: cross-context tool invocation (§6.2.4) and broadcast hosting handshake (§5.14.13). Both block-until-terminal, supervisor-minted SagaId (UUIDv4 string, never caller-supplied).

**Verified-correct claim:** ADR §3a now says SCP-SAGA- IS registered at 13000-13999. Confirmed against sdk-common.md prefix table + sub-block partition AND scripts/check-error-codes.sh. Prior ADR text claiming it needed registration was wrong; correction is accurate.

## Review at HEAD 5a5f7f275 (2026-06-24)
Prior-round BLOCKING finding (sdk-common.md not updated) is now RESOLVED — this HEAD added 3 contract paragraphs to sdk-common §"Standing contexts" (lines 363-397): (a) `Ok` ≠ peer-joined (offline/slow/blocking/declining all yield identical Ok, no sync confirmation — forecloses existence oracle); (b) Welcome-joiner decrypt-but-not-send-until-Phase-2E caveat; (c) no-`created`/`peer_joined`-discriminant MUST, identical across 4 bindings. All correct and well-motivated.

**Verdict this round: NEEDS REVISION** — no design flaw; 3 artifact-sync gaps remain:
1. **MEDIUM — `.docs/sketch.md` un-synced.** sketch.md is the canonical "API surface sketches — pseudocode for all operations" artifact (CLAUDE.md project map). Its §"Standing Context" (~lines 257-268) still shows `standingContext(...) → Context {...}` "Idempotent: returns existing if one exists" with NONE of the new contract. LLM authors read sketch.md for the return SHAPE. **RECURRING LESSON: an API-surface spec change must also sync sketch.md — grep sketch.md for the op name every time.**
2. **MEDIUM — send-gating caveat is prose-only, not on the copyable example.** sdk-common code block (367-382) models exactly the failure pattern (`standing_context` then immediate `channel.send`) with caveat 3 paragraphs below. Spec §5.15.8 agent-lifecycle example (05-contexts ~200-211) DOES annotate the joiner `channel.send` inline — sdk-common should mirror that. Warnings belong inline in the copyable example, not surrounding prose.
3. **LOW — four-binding-identical MUST but example shows only 3** (Rust/Python/Swift; TS+Kotlin absent). TS is where a `created: bool` enrichment is most tempting (NAPI full runtime access).

Good patterns confirmed: no-discriminant MUST serves BOTH security (sync existence oracle) and LLM authorability (one uniform return). `register_standing_context` kept OFF FFI surface (mirrors §3a). No stale "standing-pair saga" refs survive outside historical framing. `standing_context` still not implemented in any of 4 bindings (grep bindings/ + scp-ffi empty) — sdk-common/spec are ahead of code, expected for this docs-only lane.

**Recurring API-review pattern for SCP:** when a spec reclassifies a developer-facing op, check BOTH `.docs/standards/sdk-common.md` AND `.docs/sketch.md` are updated — spec §X.Y.Z is source of truth, but sdk-common.md and sketch.md are what binding authors/LLMs read. Constant-time-wrt-existence obligations must hold AT THE BRIDGE (renders typed-vs-generic error), not only in core.
