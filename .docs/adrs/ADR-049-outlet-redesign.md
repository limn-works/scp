# ADR-049: Outlet Redesign — Rename, Classification, Caveats, Structured Errors, Streaming

**Status:** Proposed
**Date:** 2026-04-19
**Phase:** Phase 7 (outlet redesign)
**Supersedes (partial):** ADR-010 (Tool Registration & Execution), ADR-015 (MCP Boundary), ADR-020 (Tool Invocation Error Model), ADR-041 (Participation Consequences for Tool Misbehavior — outlet-facing portions only)
**Related:** ADR-043 (Protocol Constants Reclassification — `max_chain_depth` u8), ADR-044 (Attestation Two-Class Model), ADR-045 (Fuzzing Infrastructure)
**Deferred research:** [GitHub discussion #1698](https://github.com/limn-works/scp/discussions/1698)

## Context

Four largely-independent forces converged on the outlet surface at the same time:

1. **Terminology.** The protocol called these functions "tools" everywhere — UCAN stems `tool:invoke:*`, Rust types `ToolRegistration` / `ToolCost`, event variants `ToolInvoked`, canonical hash domain separator `SCP-TOOL-REGISTRATION-V1:`, spec prose, SDK surfaces. "Tool" is agent-centric vocabulary inherited from the MCP / function-calling-LLM world, where the tool is an instrument an agent wields. SCP's security boundary is the *context*, not the agent (§5.1). The right word for a stateless function the context exposes, which the context governs, is **outlet** — a socket on the context, not a hammer in an agent's hand. Pre-1.0 is the right time to fix terminology; post-1.0 is too late.

2. **Classification.** Every outlet invocation was treated identically for economic, rate-limiting, caching, and cross-context amplification purposes. In practice, read-only queries (look up a record, answer a derived question, serve cached state) and side-effecting actions (send a message, mint a token, post a payment) have opposite security and economic profiles. Reads are idempotent, free, cacheable, and fan out widely; actions are non-idempotent, billable, non-cacheable, and must be chain-amplification-bounded. Collapsing them into one kind forced every policy knob to be a compromise between the two.

3. **Caveats on UCAN delegations.** The UCAN `nb` field was used only for protocol-defined fields; applications had no structured way to delegate a capability *with* per-call constraints (a spending cap, a time window, an adapter allowlist, an input-schema narrowing). The absence was filled by ad-hoc conventions in each SDK that did not round-trip through delegation attenuation. An application that wanted to mint a daily $50 cap on a payment-outlet capability had no protocol-level way to do it.

4. **Error envelope + streaming.** Invocation errors were returned as `Result<Value, String>` with an ad-hoc mapping from half a dozen internal error variants to the string. Seven distinct internal variants collapsed to a single `PermissionDenied` at the FFI boundary (a real bug, tracked in the original audit). Invocations were always one-shot — a large LLM response waited until it was fully complete before crossing any layer, breaking on any timeout shorter than the full generation.

Seven parallel reviewers (alignment, architecture, api-design, cryptographer, security, simplifier, black-hat) reviewed the initial redesign PRD and spec additions. They identified approximately 20 BLOCKERs and 40 MAJORs. User chose to **strip scope** rather than push back on the review findings. Deferrals went into [discussion #1698](https://github.com/limn-works/scp/discussions/1698); the remaining work folds the BLOCKERs into the PRD + spec.

## Decision

### 1. Rename `tool` → `outlet` everywhere (hard break, no aliases)

The rename is total:

- Rust types: `ToolRegistration` → `OutletRegistration`, `ToolCost` → `OutletCost`, `ToolInvoked` → `OutletInvoked`, etc.
- UCAN stems: `tool:invoke:*` → split into `outlet_query:*` and `outlet_call:*` (see §2 below); wire form uses underscore, SDK-facing display form uses colon per §5.4.2.1 parser.
- Capability URIs in ceilings: `tool:invoke:*` → `outlet:query:*` / `outlet:call:*`.
- Canonical hash separator: `SCP-TOOL-REGISTRATION-V1:` → `SCP-OUTLET-REGISTRATION-V2:` (new suffix reflects new preimage, not just a namespace change — see §5 below).
- Event variants: `ToolInvoked` etc. → `OutletInvoked` etc.; event log discriminants renumbered into a new band so any stale pre-rename event logs fail verification rather than silently replaying under the wrong vocabulary.
- Context templates: `scp:template/tool-interface` → `scp:template/outlet-interface` (template ID is part of context metadata; a renamed template ID means pre-rename templates hash differently and are not silently honored — deliberate hard break, same rationale as the rest of the rename).
- Error code prefix: **retained** as `SCP-TOOL-` within the 6100-6199 sub-block. Rationale: `scripts/check-error-codes.sh` indexes prefixes in a closed set; adding a new top-level prefix requires coordinated changes across every language SDK's error surface and every CI gate. Sub-block allocation within the existing prefix is the forward-compatible path. The slug (`slug` field on `OutletError`) carries the `outlet.` semantic prefix; the code carries the legacy `SCP-TOOL-` prefix.
- MCP boundary: `scp-mcp` translates lexically at the boundary (§8.5.1). Inside SCP everything is an outlet; externally, MCP clients see `tools/list` and `tools/call` preserved on the wire.

No deprecation aliases. No transitional period. Pre-rename callers are broken; pre-rename event logs fail verification; pre-rename UCAN tokens are rejected.

### 2. Introduce `OutletKind { Query, Action }` with structural classification

Every outlet registers with a kind. The kind is structural, not advisory:

- **Query** — read-only, idempotent, semantically cacheable. `cost == None || cost.amount == 0` enforced at registration (`QueryCostViolation` on violation); `cost.cost_formula` must be absent. Invoked through a `ReadOnlyInvocation` handle that denies writes to context state (messages, roles, registry, event log, governance, economy); any write attempt returns `QueryViolation` and emits an operator-attributable integrity-failure signal.
- **Action** — may mutate. No structural floor. Invoked through a `MutableInvocation` handle. The existing cost, rate, and amplification rules apply.
- Default is `Action` (fail-safe — an undeclared kind cannot accidentally be treated as read-only).

UCAN stems split: `outlet_query:{id}` authorizes Query invocations only; `outlet_call:{id}` authorizes Action invocations only; attenuation cannot cross classes. The `outlet_invoke:*` stem used in intermediate rename stories is deleted (hard break).

Chain amplification (§6.2.0.3): a Query-originated call cannot transitively invoke an Action outlet. `origin_kind` is bound to the UCAN `nb` field of the signed delegation chain — it is not a runtime claim; forging it requires forging the signed delegation. The check is evaluated at every hop target.

Chain depth (§6.2.0.4): partitioned by kind — Query uses the full `max_chain_depth` budget, Action uses `max(1, max_chain_depth / 2)`.

Rate tiers (§6.2.0.2): Query per-interface 600/min, per-caller 100/min (an order of magnitude higher than Action, reflecting the idempotent read contract); Action 60/min and 10/min (original defaults).

Session amplification (§6.2.1): sessions inherit the `origin_kind` of the first call that opened them; no session upgrade path.

### 3. Scoped UCAN invocation caveats — structured typed fields only

Caveats live in the UCAN `nb` field as an `InvocationCaveats` struct (§7.3.8) with 12 typed, optional fields: `amount_max_per_call`, `amount_max_cumulative`, `valid_from`, `valid_until`, `hours_of_day`, `days_of_week`, `max_calls`, `rate_window`, `input_schema`, `allowed_adapters`, `allowed_target_dids`, `origin_kind`. Mint-time limits enforce ≤ 8 populated fields (excluding `origin_kind`, which is a structural attenuation invariant and does not count against the user-facing ≤ 8 cap), ≤ 4 KiB serialized `input_schema`, ≤ 8 nesting depth, ≤ 16 list entries.

`narrow()` attenuation is per-field:

- Numeric bounds tighten (`<=` or `>=` depending on direction).
- Bitmasks subset (`child & parent == child`).
- Lists subset.
- `input_schema` uses conservative JSON Schema narrowing with a whitelist of keywords (`enum`, `const`, `minimum`, `maximum`, `minLength`, `maxLength`, `pattern`, `required`, `additionalProperties: false`) and per-keyword rules; the `pattern` keyword requires **lexical equality** because regex containment is undecidable (PSPACE-complete in general, undecidable for extended dialects).
- `hours_of_day` enforces a 24-bit mask-width assertion at mint and narrow (bits 24..31 must be zero) to prevent ambient-data smuggling and validator-implementation differentials.

Runtime enforcement wires caveats into three points of the 11-step UCAN validation pipeline (§7.2.1): step 7b (attenuation) calls `narrow()` on every delegation edge; step 11b (time-box) checks `valid_from` / `valid_until` / `hours_of_day` / `days_of_week`; a post-input check validates `input_schema`, `amount_max_per_call` against the estimated invocation cost, `allowed_adapters` against the negotiated adapter, `allowed_target_dids` for cross-context, and consults the `CaveatCounterStore` for `max_calls` / `amount_max_cumulative` / `rate_window`. Failures surface as Authorization-class errors with class-specific slugs.

Caveats compose with `SpendingCapability` (§19.5), `MemberBudgetTracker` (§19.3), `InboundPolicy`, and `OutboundPolicy` (§6.2) under logical AND — additive deny-surfaces, never widening.

Revocation is whole-token (§7.2.1 step 10). No per-caveat revocation; if an operator needs to narrow, they revoke and re-issue.

### 4. Structured `OutletError` envelope replacing lossy boolean/string path

`OutletError` carries (wire tags shown):

- `code: String` (tag 1) — `SCP-TOOL-{6100..6199}`; sub-block allocation within 8 classes.
- `slug: String` (tag 2) — kebab-case, class-scoped finer distinction. Multiple slugs may share one code (e.g., `SCP-TOOL-6110` with slugs `authorization.expired`, `authorization.revoked`, `authorization.missing`).
- `class: OutletErrorClass` (tag 3) — eight root classes: Protocol, Authorization, Input, Execution, Output, Economic, Transport, Governance.
- `message: String` (tag 4) — human-readable prose, max 1 KiB, **PII-constrained** (MUST NOT include emails, DIDs of non-self members, raw input values, SQL, stack traces, file paths; SDKs SHOULD apply a redaction lint).
- `retry: RetryPolicy` (tag 5) — `Never | Immediate | After(Duration) | WithBackoff { min, max }`.
- `detail: Option<Value>` (tag 6) — **typed per-class schema**, not free-form. Each class has a specified detail shape; a non-matching detail is a wire-layer rejection at the receiving SDK. Prevents covert-channel use.
- `source_chain: Vec<ContextHop>` (tag 8) — ordered cross-context hop trail; each `context_id` is pseudonymized via `HMAC(hop_salt, context_id)` where `hop_salt` is a per-context-pair salt established at interface acceptance. Hop index 0 (caller's own context) is NOT pseudonymized.

Tags 7, 9, 10 are **reserved for forward-compatible evolution**. They were drafted (`related_code`, `i18n_key`, `trace_id`) and dropped before merge: cross-reference is served by `source_chain.wrapped_code`; localization is SDK-layer; telemetry `trace_id` is transport-layer with its own conventions. Future tags MUST use 11+ and round-trip through `_unknown_fields`.

**Query oracle collapse.** Authorization errors that would reveal whether a specific `outlet_id` exists are collapsed to `SCP-TOOL-6110` with slug `authorization.denied` when the caller holds neither `outlet_query:{id}` nor `outlet_call:{id}`. Without the collapse, a caller who holds no capability could enumerate the outlet registry by probing error codes — a practical oracle against private outlets.

**Cross-context wrapping preserves the original code.** Source-chain hops append with `wrapped_code` of the previous hop; the outermost caller sees the innermost reason and the trail of boundaries traversed. Opposite of HTTP gateway remapping.

**SDK sealed hierarchies.** Each SDK renders `OutletErrorClass` as a sealed type — Python subclass tree, TypeScript tagged-union with runtime `instanceof` preserved across napi-rs FFI, Swift `enum` with associated values, Kotlin sealed class with data-class children. Conformance fixtures round-trip through all four bridges.

### 5. Streaming-native invocation (every call is a stream)

Every invocation is a stream per §5.4.5. `OutletResponse` is deleted. The wire types are `OutletStreamOpen`, `OutletStreamChunk` (with `sig: Ed25519Signature`), `OutletStreamCredit`, and a tagged `ChunkPayload` union (Data / Progress / End / Error). The variant discriminator field is named `@type` (leading `@`) so that under RFC 8785 JCS sort order it precedes every body-field key in every variant — a canonical-hashed chunk is classified before any body field is read. (The draft used `"type"`, but under JCS `type` sorts AFTER all lowercase-letter body keys; `@type` is the minimal change that actually delivers the "classify first" property.)

- **Per-chunk operator signature** over `SHA-256("SCP-OUTLET-CHUNK-SIG-V1:" || len_be32(context_id) || context_id || len_be32(outlet_id) || outlet_id || request_id || sequence_be || caveats_binding || SHA-256(canonical_jcs(payload)))` closes the equivocation gap where an operator could stream different sequences to different members and commit a manifest of only one. Binding `context_id`, `outlet_id`, and `caveats_binding` into the preimage closes the cross-outlet, cross-context, and cross-caveat-set replay surface. Matches §5.4.5 byte-for-byte.
- **`caveats_binding`** over `SHA-256("SCP-OUTLET-CAVEAT-BIND-V1:" || len_be32(ucan_cid) || ucan_cid || request_id || len_be32(invoker_did) || invoker_did || estimated_chunk_count_be || canonical_jcs(effective_caveats))` commits the open to the exact caveat set validated at check time AND pins the binding to (a) the specific token, (b) this stream instance, (c) the invoker identity, (d) the invoker-declared billable-chunk ceiling, and (e) the narrowed caveats (including `origin_kind`). A later `OutletStreamOpen` with the same `request_id` but a different `caveats_binding` is rejected as `AttenuationViolation`. Matches §5.4.5 byte-for-byte.
- **Credit grant signature** over `SHA-256("SCP-OUTLET-CREDIT-V1:" || len_be32(context_id) || context_id || len_be32(outlet_id) || outlet_id || request_id || grant_be || monotonic_seq_be || caveats_binding)` — stream-identity binding on credit grants closes the cross-stream grant-replay surface (a grant signed for stream A in context X cannot be replayed as a valid grant for stream B in context Y).
- **`offer_id`** over `SHA-256("SCP-OUTLET-OFFER-ID-V1:" || len_be32(context_a_id) || context_a_id || len_be32(outlet_id) || outlet_id || len_be32(context_b_id) || context_b_id || timestamp_be)` — length-prefixed and domain-separated (§6.2.0.1).
- **V1 preimage naming.** None of the four new preimages shipped under an earlier V-number; the ADR tracks them as V1 from first commit. Drafts that briefly wrote `SCP-OUTLET-CAVEAT-BIND-V2` / `SCP-OUTLET-CHUNK-SIG-V2` are erased — "V1" is the historically accurate first-ship label.
- **`chain_depth` is `u8`** to match §24.4 + ADR-043 `[0, 255]`.
- **Credit-based backpressure** with default window 32 and 30-second stall timeout; End/Error are terminal and never consume credit.
- **Chunk manifest** uses RFC 6962 tag bytes (`0x00` for leaves, `0x01` for interior) under `SCP-OUTLET-CHUNK-V1:` separator; leaf covers the full chunk including `sig`. The root `stream_manifest_hash` is the commitment. Per-chunk inclusion-proof **API** is deferred (see §6 below); the commitment itself is protocol-level.
- **Billing semantics** escrow-at-open + per-chunk accrual + receipt-at-close + refund-on-terminate + cancel-ack-sequence-bounded billing + credit-stall escrow release. Event log records `chunks_billed: u32` separately from `stream_chunk_count`.
- **One `OutletInvokedEvent` per stream**, emitted at terminal chunk, carrying `stream_chunk_count`, `chunks_billed`, `stream_manifest_hash`, `stream_terminal_status`.
- **Cross-context streaming** (§6.2.0.5): shared-member bridge re-encrypts chunks per-recipient; `chain_depth` is set at open and inherited; credit flows end-to-end.
- **Non-streaming invocation** is the degenerate two-chunk case (`Data(output)` + `End(output)`). SDKs MAY expose a `.invoke()` helper that awaits the collected `End.aggregate`, but the wire contract is always the streaming form.

SDK idioms: Python `AsyncIterator`, TypeScript `AsyncIterable`, Swift `AsyncThrowingStream`, Kotlin `Flow`. Progress chunks are surfaced (not filtered out). Each SDK also exposes `grantCredit` and `cancel`.

### 6. Deferred scope (tracked in [discussion #1698](https://github.com/limn-works/scp/discussions/1698))

The following pieces were specced but pulled before merge. They are intentionally deferred, not forgotten.

- **Query result cache (§5.4.3).** Relay-hosted operator-signed shared cache. Unresolved design questions: relay-side authz boundary for cache reads (relays are not membership-aware, the cache must be membership-gated); interaction with per-member pseudonym routing (§9.10.4), which prevents grouping hits on a single routing ID without leaking subscribership; billing semantics for a paid Query operator serving unbounded cached audience. The spec deferral stub in §5.4.3 prohibits silent cache-like optimization by implementations.
- **Per-chunk inclusion-proof API.** `outlets.inclusion_proof(invocation_id, chunk_index)` returning a Merkle path. The manifest root commitment is kept at the protocol level; the API is a convenience over that primitive and can be added without a wire break.
- **Error envelope fields `i18n_key`, `trace_id`, `related_code`.** Tags 9, 10, 7 reserved on the wire; `_unknown_fields` forward-compat ensures future re-introduction does not require a wire break.

Each deferred item carries a rationale in the discussion thread so the context isn't lost. Re-adding any of them is a future ADR, not a silent patch.

### 7. Updates to stale "done" PRDs

Several PRDs in `main.json` were marked `done` against tool-era acceptance criteria that reference `ToolRegistration`, `ToolRequest`, `ToolResponse`, `ToolInterface`, or `tool_invoke:*`. These stories (SCP-010, SCP-013, SCP-018, SCP-040, SCP-041) remain historically accurate — they describe what was built at the time — but their acceptance criteria no longer pass a codebase where those types have been renamed. The outlet PRD adds a migration-superseded story that explicitly annotates each affected story's `details` with a `superseded_by` field pointing to the gate-rename stories. The text of the original acceptance criteria stays intact (history), but the machine-verifiable status is now "superseded by SCP-OUT-NNN, kept for provenance."

## Rejected alternatives

- **Keep the word "tool".** Rejected per the terminology rationale above. Pre-1.0 is the right window; post-1.0 would require a second hard break we would regret.
- **Alternative names: "service", "operation", "endpoint", "handler".** `service` is too heavy (implies deployment, scale, long-running process); SCP outlets are stateless. `operation` is RPC vocabulary that loses the context-as-socket metaphor. `endpoint` is HTTP-centric. `handler` is a language-level implementation detail, not a protocol concept. `outlet` consistently read as the right noun in prose, API, docs, and error codes during the terminology review. See discussion #1698 for the full trade-off table.
- **`outlet+invoke_only` without classification.** Single invocation verb with runtime hints for rate/cache/amplification. Rejected because every rate, cache, and amplification decision would become a per-outlet policy knob the operator declares and the runtime hopes-is-honest — classification pushes the distinction into the type system where the runtime can enforce it structurally. Classification also gives the UCAN stem split, which is the hook that makes chain-amplification enforceable on the authorization boundary.
- **A caveat DSL.** A small expression language in `nb` for general-purpose predicates over input / context / time. Rejected. A DSL is a parser-differential attack surface, a complexity multiplier for every SDK, and a future-compatibility hazard. Fixed-field caveats with a ≤ 8-field cap keep the verifier small enough to fuzz to saturation and keep delegation semantics auditable by eye.
- **Shared relay-hosted Query result cache (first draft).** Deferred per §6 above, rejected for the initial merge because of unresolved authz / pseudonym / billing interactions. Kept as a primitive the kind semantic is compatible with.
- **Per-chunk inclusion-proof API on the SDK surface.** Deferred per §6. The manifest root is the protocol-level commitment; the proof API is a later optional convenience.
- **Error envelope with 35+ codes.** The initial draft enumerated every distinguishable runtime condition as a distinct code, running to ≥ 35 entries across the 6100-6199 sub-block. Compressed to ~15 codes (1-2 per class, ~15 total), with fine-grained distinctions carried in `slug`. Full enumeration was unmemorable; the compact taxonomy keeps the wire form legible and leaves room inside the sub-block (6180-6199 reserved).
- **`i18n_key`, `trace_id`, `related_code` on the wire.** Deferred per §6. Locale catalogs belong in SDKs; trace IDs belong in the transport layer with their own propagation conventions; cross-references are carried implicitly via `source_chain.wrapped_code`.

## Consequences

- **Pre-migration tokens, event logs, and signatures are invalid.** Any agent, relay, or stored artifact from before the rename fails verification after the migration commit. This is intentional — pre-1.0, there is no compatibility obligation.
- **The protocol wire surface breaks.** MessagePack field tags, canonical hash separators, UCAN stems, event-log discriminants, and error-envelope shape all change. Deployments must migrate atomically.
- **The SDK public surface breaks.** Every language SDK renames `Tool*` to `Outlet*`, splits invocation into `.query()` / `.call()` (or `.invoke()` with kind-inferred stem), exposes caveat helpers, and renders `OutletError` as a sealed hierarchy. Application code that used the pre-rename SDK compiles only after a rename pass.
- **The MCP boundary is preserved.** External MCP clients continue to see `tools/list` and `tools/call`; the boundary is lexical and handled by `scp-mcp`.
- **The enforcement surface expands.** New scripts (`check-handle-affinity.sh`, `check-no-bridge-globals.sh`, `check-no-fallback-registry.sh`, `check-no-default-in-tests.sh`) interact with the outlet rename because they all indexed tool-era identifiers. `bridge_ratchet_baseline.json`, `ratchet/once-lock-count.json`, and the capability matrix all update.
- **Every OutletExecutor is wrapped in `catch_unwind`.** A panic inside an executor maps to `SCP-TOOL-6130` (handler-panic) with an operator-attributable integrity-failure signal. The SDK's own bugs are not conflated with operator-originated failures.
- **Stream billing is escrow-based.** An operator who begins serving chunks against a caller whose escrow is insufficient never gets started; an operator whose stream is terminated mid-way bills only for cancel-ack-bounded billable chunks. The economic layer stays consistent across partial streams.
- **Cross-instance handle reuse across separate SCP instances is independent of this ADR.** ADR-048 handled that concern; outlets inherit the handle-affinity discipline established there.
- **Ratchet invariant (monotonicity).** Every coverage ratchet touched by this ADR — `bridge_ratchet_baseline.json`, `ratchet/once-lock-count.json`, `ffi_conformance.rs` assertion counts, `pipeline_wiring.rs` assertion counts, SDK capability matrix cell counts — is NON-INCREASING in the weakening direction. Additive expansion (new operations, new assertions) is always permitted; removal, weakening, or exemption of an existing counter requires explicit human approval per the CLAUDE.md worktree invariant. The outlet redesign is a rename + expansion: every existing mechanical enforcement count stays at or above its pre-rename value, and new entries (streaming, caveats, error envelope, classification) are layered on top. Cleaning up the one-time bookkeeping cost of the rename itself (e.g., deleting a `ToolRegistration` type and replacing it with `OutletRegistration`) counts as an identifier change, not a ratchet regression; no check count drops as a result.

## Notes

### Supersedes table

| Prior ADR | Aspect superseded | New location |
|-----------|-------------------|--------------|
| ADR-010 | Tool registration wire format (V1 preimage, unprefixed concatenation) | §5.4.1 V2 preimage with length prefixes |
| ADR-010 | Single `ToolResponse` return type | §5.4.5 streaming-native + degenerate two-chunk form |
| ADR-015 | Tool vocabulary on the MCP boundary interior to SCP | §8.5.1 lexical translator keeps MCP external; SCP internal is outlet |
| ADR-020 | Ad-hoc `Result<Value, String>` error path with 7-to-1 collapse at FFI | §5.4.4 structured envelope with per-class typed detail |
| ADR-041 | Participation-consequence hooks keyed to tool-era event variant names | §5.4.2 QueryMisdeclaration + renamed variant set |

### Gate-level priority reconsideration

Gates 2-5 (classification, caveats, errors, streaming) carried `P1` in the initial draft. The tightened scope (caveats and errors both substantially smaller; streaming has the deferrals carved out) makes each gate a narrower, more focused deliverable. Per the "no DOA decisions" tenet, each gate should ship as part of a coherent first cut rather than be partially deferred; the P0/P1 split has been reconsidered, with Gates 2-4 moving to P0 (the behavioral invariants they encode — classification, caveat attenuation, typed errors — are load-bearing for the rename to mean anything at runtime) and Gate 5 remaining P1 (streaming is load-bearing for SDK ergonomics, not for protocol correctness; the degenerate one-shot case is always available).

### Cross-reference from removed §5.4.3 stub

The deferred §5.4.3 explicitly names this ADR and discussion #1698 so future readers discover the deferral chain. Downstream sections (§5.4.2 cacheability prose, §5.4.5 streaming, §5.14.10 event log) were audited and revised to not depend on the cache being present.
