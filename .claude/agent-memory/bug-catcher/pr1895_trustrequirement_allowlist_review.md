---
name: pr1895-trustrequirement-allowlist-review
description: CLEAN review of PR #1895 (fix/trustrequirement-allowlist-only) — TrustRequirement collapsed to single KnownDid variant; verified UniFFI Swift checksum is REAL not stale
metadata:
  type: project
---

PR #1895 collapse TrustRequirement → allowlist-only KnownDid. Reviewed for logic defects (compiler already passed). CLEAN — no defects found.

**Why clean (verification performed):**
- All 4 Rust bridges (PyO3/UniFFI/NAPI/WASM) internally consistent: oracle struct made unit (no `trusted_dids` field), match arm reduced to single `KnownDid(dids) => dids.contains(inviter)`.
- WASM `check_trust` correctly reads externally-tagged serde shape `{"KnownDid":[...]}` (enum has NO `#[serde(rename_all)]`/tag attr → default external tagging). Matches Python test JSON + native serde.
- SDK wrappers (Python/TS native+wasm+bridge/Swift Context+Scp+ScpBindings/Kotlin Scp.kt) all drop the param consistently; arg order at FFI boundary preserved (5 positionals: params,inviter,identity,policy,spending).
- **UniFFI Swift checksum VERIFIED REAL:** ScpBindings.swift hand-updated 59132→11385. Regenerated Kotlin UniFFI binding via `scripts/generate-uniffi-kotlin.sh` → produced `11385.toShort()` for `evaluate_invitation`. Matches. NOT the recurring stale-checksum CRITICAL (see [[uniffi-checksum-staleness]]). Kotlin internal binding is gitignored/build-generated (regenerates fresh, no staleness risk).
- Tests are real, not tautologies: invitation.rs `auto_accept_trust_explicit_list` uses KnownDidTrust oracle → Bob(not in list)=PromptAgent, Alice(in list)=AutoAccept. Python `test_known_did_allowlist_travels_in_policy` asserts `len(call)==5` AND allowlist rides in policy_json[3] as `{"from":{"KnownDid":[...]}}`.
- No dangling refs to removed `Any`/`SharedContext`/`Explicit` TrustRequirement variants anywhere (the many Explicit/SharedContext hits belong to unrelated enums: RelayUrlSource, DiscoveryMethod, IdentitySource, ContextCreation).
- `check-python-falsy-optionals.py` example reference updated from gone `evaluate_invitation` to live `trust.py` canonical pattern (verified trust.py still has `is not None` form).

**LESSON reinforced:** For UniFFI Swift checksum hand-edits, regenerate the Kotlin binding (shares the same Rust-side metadata hash) and grep the `.toShort()` value — fast way to confirm a Swift checksum without building uniffi-bindgen + Swift toolchain.
