---
name: ffi-slice-coverage-pattern
description: Where gaps hide when auditing a new FFI-op slice (bridge×SDK×enforcement) — the recurring cross-bridge coverage/enforcement asymmetries
metadata:
  type: project
---

Auditing an FFI slice that exposes a new op across pyo3/napi/uniffi + Python/TS/Swift/Kotlin: the FUNCTIONAL chain (Supervisor method → 3 bridges → 4 SDK wrappers) is usually fully wired and easy to verify (grep the `.method(` call in each bridge body; grep the SDK delegation). The gaps hide in two consistent places:

1. **pipeline_wiring.rs per-bridge assertions.** Convention asserts each wired op reaches its Supervisor seam for EVERY applicable bridge (`fn_body_contains(SRC, "op", ".supervisor_method(")` — non-vacuous, comment-stripped). Check that uniffi assertions exist too — the 2J FFI slice (HEAD cef1c681d) added pyo3+napi assertions for reserve_key_package/context_join_from_welcome/invite_member but **omitted all uniffi assertions**, despite uniffi being asserted for other ops (participation_record, ucan_evaluate, saga). Empty enforcement cells even though code is wired.

2. **Bridge-layer test comments misattributing why a happy-path isn't asserted.** UniFFI (Swift/Kotlin) genuinely CANNOT reach the full sealed/round-trip happy path in single-process because `identity_create` does not publish the minted DID doc to a resolver-visible store (the "no-publish" limitation) — so a locally-created peer is unresolvable. This is REAL and correctly documented in the Swift/Kotlin SDK tests. But the napi + uniffi *Rust bridge* unit-test comments instead claimed the happy-path was blocked because "the §5.13.3 0xFF02 KeyPackage-capabilities path is not green on THIS branch" — which is false (commit 9fe3b4c9b making it green is an ancestor; Python real-bridge + TS real-napi tests both assert the full sealed outcome on the same branch). Phantom provenance in test comments.

Verification cheat-sheet that worked: `check-sdk-coverage.py` PASS proves every matrix cell resolves to a real symbol (name-existence only, not semantics); read the actual SDK method body for real delegation; happy-path is covered at runtime (`invite_member_round_trip*` in spawn_from_welcome_tests.rs) + PyO3/Python (`test_invite_member_seals_for_single_admin_context`) + TS real-napi Layer 2. Follow-ups #2027 (governed-context invite+GenesisAttestation), #2028 (stale-genesis-params-at-join), #2029 (AddMember(None) never real-adds in prod), #2032 (KPs carry no wrapping key → §9.16.1 sender-key distribution unwired) are all genuinely pre-existing/model-wide, not corners cut on the slice.
