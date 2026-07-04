# ADR-058: Typed SDK Trust-Input Surface

**Status:** Accepted (2026-07-03).

**Relates to:** ADR-059 (structured trust *outputs*) — this ADR is its input-side analog. ADR-026/028 (SDK delegation layers), ADR-048 §1/§7 (per-SDK idiom over the JSON FFI), ADR-017 (Trust Engine), spec §7.3.2.1 / §7.3.4.4.

## Context

The trust-engine bridge operations exchange structured records across the FFI as JSON strings: `verify_participation_requirements` takes a `RequireParticipation[]` and a `ParticipationProfile[]`; `check_capability_requirements` takes a `CapabilityRequirement[]` and a `ChallengeVerification[]`. The Rust core owns the canonical serde wire shapes (`crates/scp-protocol/src/trust/{participation,admission,challenge}.rs`). The FFI bridges (PyO3, NAPI, UniFFI) take and return those shapes as JSON strings — a deliberate, uniform boundary (ADR-048 §1: the FFI Rust layer stays flat-function/JSON; §7: each language SDK adds its own idiom on top).

Two failure modes appear when the SDK *also* stays JSON at its public surface:

1. **The caller hand-authors serde JSON.** They must know that `threshold` is externally-tagged (`{ "AtLeast": 100 }`), that `fact` is a bare PascalCase variant string, that byte arrays serialize as JSON number arrays, and that `verification_level` is `"SelfAttested"`/`"ChallengeVerified"`. A single wrong key or camelCased field silently produces a bridge deserialization error at runtime, not a compile error. This is exactly the agent-first-API failure mode the builder tenets forbid: the type signature (`requirementsJson: string`) tells an LLM author nothing, so it cannot write correct code from the signature plus one example.

2. **Divergence across SDKs.** Each SDK, left to hand-roll JSON, reverse-engineers the serde shape independently. That is the same structural defect ADR-059 identified on the *output* side (both SDKs reverse-engineering prose into structure) — here on the input side.

The Python SDK already resolved this for the participation path: `verify_participation_requirements` takes typed `RequireParticipation`/`ParticipationProfile` dataclasses whose `_to_bridge_dict()` methods serialize to the exact serde JSON internally (see `bindings/python/scp_sdk/trust.py`). The typed `ConsequenceRule`/`ConsequenceConfig` (context params) and `CachedAttestation` (participation record) inputs prove the same convention across all four SDKs — typed objects in, serde JSON emitted internally, over the unchanged JSON bridge. What remains is inconsistent: `check_capability_requirements` still takes raw dicts in Python, and TypeScript/Swift/Kotlin still take raw JSON strings for *both* trust-input operations.

## Decision

**SDK trust-input surfaces take typed objects and serialize internally to the JSON FFI. The FFI bridges stay JSON.**

Concretely, each language SDK exposes typed value types — `RequireParticipation`, `ParticipationProfile`, `CapabilityRequirement`, `ChallengeVerification` (and the supporting `VerificationLevel` / challenge verification-method / participation-fact / participation-threshold enums) — modeled in that language's idiom (dataclasses in Python, interfaces + `encode*` functions in TypeScript, `Codable` structs in Swift, data classes with JSON builders in Kotlin). Each SDK owns the camelCase→snake_case (and typed-enum→externally-tagged) projection to the canonical serde wire shape, mirroring the existing `encode*` / `_to_bridge_dict` precedent. The `this.#native.*` / `uniffi.scp.*` / bridge call still receives JSON strings — no `crates/scp-ffi/*` change, no Rust change.

The canonical serde shapes in `scp-protocol` remain the single source of truth. Each SDK's serializer is pinned to those shapes by round-trip tests that reuse the bridge test fixtures (e.g. the NAPI `check_capability_requirements_*` fixtures), so a drift between an SDK projection and the serde shape trips a test, not a production deserialization error.

This is the input-side analog of ADR-059's output-side rule (bridge returns structured records, SDK consumes structure — never parses prose). Symmetry: structured in, structured out; the JSON crossing the FFI is an implementation detail of the boundary, never the public API.

## Rationale

- **Agent-first authorability (builder tenet, ADR-052).** A typed signature (`requirements: CapabilityRequirement[]`, `verifications: ChallengeVerification[]`) plus one example lets an LLM author correct code with no compile-retry loop. A `string` parameter named `...Json` cannot — it hides the entire serde contract behind prose the model must already know.
- **Identical shape across bindings.** The typed surface is the same conceptual shape in every SDK, so knowledge transfers. Python already proves the pattern for participation; this ADR makes the convention uniform (all four SDKs, both trust-input operations).
- **The boundary is already proven.** `ConsequenceRule`, `ConsequenceConfig`, and `CachedAttestation` are typed SDK inputs serialized internally over the *unchanged* JSON bridge in all four SDKs. This ADR does not introduce a new mechanism — it extends an established, tested one to the two remaining trust-input operations.
- **Misuse resistance.** Byte-array length checks, non-negative `u64`/`u32` range checks, and enum exhaustiveness move the failure from a runtime bridge error to a construction-time (or compile-time) error at the SDK boundary.
- **No FFI churn, no DOA risk.** The FFI contract is untouched, so this is additive and reversible per SDK; it commits to nothing structural beyond the already-shipped Python precedent.

## Rejected alternative

**Keep the SDK surface as raw JSON strings (status quo for TS/Swift/Kotlin, and for Python's `check_capability_requirements`).** Rejected: it pushes the serde wire contract onto every caller, defeats agent-first authorability, and invites per-SDK divergence in how the JSON is hand-assembled — the precise structural defect ADR-059 corrected on the output side. "The bridge takes JSON, so the SDK takes JSON" conflates the FFI boundary with the public API; the two are deliberately different layers (ADR-048 §1 vs §7).

## Consequences

- **Positive:** One canonical, typed, misuse-resistant trust-input surface per SDK; identical shape across bindings; drift caught by tests, not production; no FFI/Rust change.
- **Costs:** Each SDK carries a typed model + serializer for the four input types, kept in sync with the `scp-protocol` serde shapes by fixture-pinned round-trip tests. This is the same maintenance the participation/consequence/attestation typed inputs already carry.
- **Scope note:** The convention now covers the full trust-input surface: `verify_participation_requirements` (Op A) and `check_capability_requirements` (Op B) in the initial application, then `aggregate_trust_input` (Op C — typed `EventLogEntry`, 32-byte Merkle root, `ConsequenceRule`, per-`AttestationType` `ThresholdRequirement` / `AttestorInfo` maps, `CachedAttestation`, `ChallengeVerification`) and the challenge pair `trust_verify_attestation` / `trust_verify_response` (Op D — the attestation envelope plus typed `ChallengeRequest` / `ChallengeResponse`) across all four SDKs. No trust-input operation takes raw JSON at an SDK surface; the raw `...Json` mirrors that remain (the UniFFI-generated free functions and the Swift `SCP` 1:1 forwarders of the generated `inner` API) are the ADR's unchanged JSON *bridge boundary*, with the typed surface layered on top. Any future trust-input operation is brought onto this convention as it is added.
