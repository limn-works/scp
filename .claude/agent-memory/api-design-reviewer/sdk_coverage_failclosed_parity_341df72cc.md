---
name: sdk-coverage-failclosed-parity-341df72cc
description: APPROVED review of fix/sdk-coverage-fail-closed-and-parity @341df72cc — discovery TypedDicts public, BridgeTrustLevel int Literal, discover_contexts async, PERM-3030 re-raise, provider.rs comment-only
metadata:
  type: project
---

Reviewed branch `fix/sdk-coverage-fail-closed-and-parity` @341df72cc. Verdict APPROVED.

**Why:** Python SDK promoted discovery TypedDicts to public surface + exposed BridgeTrustLevel + added async discover_contexts; needed cross-binding (TS) parity check.

**How to apply:** Reference points for future discovery/trust API reviews in this repo:

- `discovery.py` TypedDicts (`ResolutionPathDict`/`TrustLevelDict`/`DiscoveryResult`) mirror TS `types.ts:909/924/939` + `discovery.ts:53` field-for-field. TrustLevel kind = 6 Literals; ResolutionLayer = 5 Literals; both match Rust spec §22.7/§22.11.3 exactly. snake_case (py) vs camelCase (ts) is correct per-language idiom.
- **Open ergonomics nit (non-blocking):** all three py TypedDicts use `total=False` but TS makes fields required. `DiscoveryResult`/`ResolutionPathDict` are always-fully-populated records → should be `total=True` to match TS contract. `TrustLevelDict` legitimately needs partiality (`sources` only on MultiLayerCorroborated) — TS models with discriminated union, py can't, so flat partial dict is defensible.
- **PERM-3030 re-raise:** behaviorally equivalent across bindings via different idioms. Python (`trust.py:763-771`) catches only `bridge.UcanError` then re-raises `[SCP-PERM-3030]`; non-UCAN faults propagate uncaught. TS (`trust.ts:456-461`) catches all, re-raises non-`[SCP-PERM-\d+]`, then re-raises 3030. Same consumer experience (3030 surfaces, not collapsed to false all-False CapabilityValidation). Cross-ref comment pins TS line. Sound.
- **BridgeTrustLevel** `Literal[0,1,2,3]` (`bridge.py:26`) == TS `0|1|2|3` == Rust discriminants `provenance.rs:48-67` (ShadowBridged=0..NativeNative=3). Verified exact. Bare int Literal not IntEnum is a minor discoverability tradeoff but matches TS for parity.
- **discover_contexts SCP-instance asymmetry** (py omits `scp` param TS requires) is INTENTIONAL + documented (`discovery.py:186-189`): py `context_discover` is module-level #[pyfunction], TS uses getBridge(scp). Do NOT flag as parity defect.
- **provider.rs in diff is COMMENT-ONLY** (scp-runtime/crypto/mls): removed stale trait-era "default impl / MUST override" docs now that methods are inherent; renamed ContextManager→actor refs (ADR-049). No surface change. The focus item "ADR-053 PreRotationCustodyProvider" does NOT exist in this diff — PreRotationCustody is in scp-platform/scp-identity (untouched); ADR-053 here = ADR-051→053 doc renumber.

Builds on [[sdk_coverage_failclosed_parity_57840faab]] — same branch, BridgeTrustLevel + discovery Literal parity confirmed again; discover_contexts TS/py signature split is documented intentional divergence.

**Re-review addendum (later pass, ADR-053 reviewed as a design proposal):** ADR-053 `PreRotationCustodyProvider` DOES exist as `.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md` (status: **proposed**). Reviewed its proposed API shape (not yet code): 4 flat methods `generate() -> PreRotationKeyHandle`, `public_key(handle) -> [u8;32]`, `import_seed_bytes(seed) -> PreRotationKeyHandle`, `consume(handle) -> [u8;32]`; NAPI flat record `{generate,publicKey,importSeedBytes,consume}`. FOLLOWS agent-first tenet: no typestate/builder; generate-before-consume is data-driven (hold a handle), not phantom typestate. Separate-provider-from-KeyCustodyProvider is driven by §9.7.4.1 §3 substrate-isolation (security boundary), a justified reason to add a 2nd small interface. 3 open questions gate acceptance (WASM scope, mandatory backend floor, whether §9.7.4.1 needs an explicit sub-clause — spec change lands before code per artifact-flow). API shape APPROVABLE.
