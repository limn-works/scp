---
name: project-eventlog-unification-phase2
description: API review of the ContextEventLogProvider trait + payload encoding API in the native-WASM event-log unification (Phase 2 substrate)
metadata:
  type: project
---

Reviewed `feat/eventlog-unification-phase2-substrate` (HEAD 964f186, branch off main, 46 files). Verdict APPROVED.

Scope: `ContextEventLogProvider` trait (`crates/scp-runtime/src/context/builder.rs:125-405`) + payload API (`crates/scp-event-log/src/payload.rs`).

**Why:** Part of the ADR-011 amendment (`.docs/adrs/phase-2.md`) unifying the scp-runtime event log onto the scp_event_log RFC-6962 substrate so native and WASM Merkle roots converge. Producers stopped baking params into event *names* (`format!("ContextTombstoned:{dest}:{pid}")` / JSON-blob-as-type-tag) and now emit typed `EventType` + structured `EventPayload`.

**How to apply (key API facts for future reviews of this trait):**
- The migration `append_event(&str)` -> `(EventType, &str, EventPayload)` is a real misuse-resistance win: closed `EventType` taxonomy, convergent leaf preimage `SHA-256(0x00 || rmp_serde(Event))`.
- ONE residual misuse surface: producer passes `EventType::X` and `XPayload` as TWO unlinked args. No compile-time binding — `EventType::AccessRevoked` + `SpendApprovedPayload` compiles. Deliberately accepted because (a) consumer decode (`payload_target_did`/`rmp_array_first_string` in consequence.rs:884-924) reads element-0 positionally and is variant-AGNOSTIC by design — a typed binding wouldn't be consumed; (b) mismatch is hash-detectable. If the typed emit-site set grows in later phases, recommend a lightweight `sealed trait VariantPayload { const EVENT_TYPE: EventType }` (NOT typestate — that would violate the worktree's new agent-first tenet).
- Default proof impls (`prove_event_inclusion`/`prove_event_consistency`/`rebuild_event_log_for_proof`) replay entries through the substrate; `MerkleEventLogProvider` overrides to prove against its live tree via `with_log` (no replay, "single proof seam"). Both prove against the same committed preimage so they can't diverge. Good default.
- Read-side defaults return `Err("not supported")` not `Ok(None)`; half-impl providers fail at call time not compile time. Acceptable for an INTERNAL trait (one prod impl + test mocks), would be a defect on public SDK surface.
- Three append entry points (`append_event` -> ContextCreationError for creation; `append_context_event`/`_with_payload` -> ContextError for ops). Convenience methods default-delegate to `append_event`; implementors only write one. Justified by the error-type boundary.
- Two new payload structs (AccessRevokedPayload, GovernanceActionExecutedPayload) fully consistent with the prior 8: positional MessagePack, target_did-first (decode relies on element-0), doc-links, spec cites, round-trip tests incl empty-target.
- Pre-existing (NOT this diff): producer emits `EventType::GovernanceActionExecuted` (gov_helpers:3604) but consequence engine WarningCount trigger matches legacy `EventType::GovernanceAction` (consequence.rs:852). Element-0 decode still works; flag for a later phase to align the variant set.

NEW worktree CLAUDE.md tenet observed: "Agent-first API design" — SDK's primary author is an LLM; flat named-field config over builders/typestate; typestate a model can't track is a DEFECT not a safety feature; enforced via `.docs/standards/construction.md` + ADR-052 structural check. This reframes prior "stringly-typed param" findings: prefer required fields/enums, avoid typestate.
