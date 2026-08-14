---
name: standing-pair-v2-autoaccept-allowlist-only
description: API review of spec/standing-pair-not-a-saga-v2 @ 01db91cf1 — auto-accept collapsed to allowlist-only across all surfaces incl §5.13.7 child-context; APPROVED
metadata:
  type: project
---

Branch `spec/standing-pair-not-a-saga-v2` @ HEAD `01db91cf1` (docs-only). This commit (vs prior-round 5a5f7f275) does TWO things API-relevant:

1. **Auto-accept collapsed to allowlist-only** (`from: known_did(list)` / `TrustRequirement::KnownDid` / `Explicit`) across §5.12.2 (05-contexts), sketch.md AutoAcceptPolicy, sdk-common.md Rust+Python examples, technical-overview.md. Dropped arms: `shared_context`/`SharedContext` (co-membership), `discovery_context` (open-registry). Added a normative **no-default ⇒ default-deny ⇒ prompt** rule on every surface. `Any` + `SharedContext` removal is deferred to a downstream code-correctness PR at BOTH sites (scp-protocol `context::policy` + WASM `check_trust` reimpl, ADR-034) — spec-leads-code, no code touched here.

2. **§5.13.7 child-context auto-accept rewritten** from the misuse-prone "parent lineage provides a stronger trust signal" (the "I'm in the parent → auto-accept the child" failure mode) to: child eligibility is a cryptographically-enforced **floor on who can reach you** (relay-enforced §5.13.2), NOT a trust signal, does NOT trigger auto-accept; auto-accepting a child follows the same §5.12.2 `known_did` allowlist-or-prompt rule. This is exactly the LLM-misuse-resistant framing required.

**Verified all 3 prior-round (5a5f7f275) findings RESOLVED at this HEAD:** (1) sketch.md §Standing Context now carries full contract; (2) send-gating caveat now INLINE on every copyable `channel.send` example in sdk-common; (3) all 4 bindings (Rust/Python/Swift/TS/Kotlin) shown, TS carries the no-`created`/`peer_joined`-discriminant NOTE.

**Cross-surface consistency — checked, no false positives:** grep of `shared_context|sharedcontext|discovery_context|discoverycontext` across the 5 docs returns ONLY: the §5.12.2 provenance paragraph (intentional, describes the code divergence) + unrelated subsystems that are NOT auto-accept triggers and correctly untouched — DataProvenance `discovery_method`/`discoveryMethod` field (how data was discovered), DiscoveryResult `source: .discoveryContext` origin label, `sharedContexts(with:)` connection-graph filter, tech-overview `DiscoveryContextVerified` handle-resolution trust level. None offer co-membership/lineage/discovery as an auto-accept option.

**standing_context get-or-create contract:** still uniform — no-discriminant MUST, identical shape across bindings, Ok≠joined, auto-revive. Already APPROVED in [[standing-pair-not-saga-okreturn-softening]]; not re-litigated.

**Verdict: APPROVED.** One canonical allowlist pattern, default-deny, no surface offering an unsound auto-accept trigger. Related: [[standing-pair-not-a-saga-v2-review]] (prior round), [[standing-pair-not-saga-okreturn-softening]].
