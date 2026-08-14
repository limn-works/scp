---
name: 2240-partA-followup-recovery-message-overclaim
description: #2240 Part A follow-up (HEAD 2e68d0a9c) — UniFFI recovery ownership-rejection message introduces a NEW sibling-bridge overclaim; Kotlin/Swift fixes are clean
metadata:
  type: project
---

Commit 2e68d0a9c (branch fix/2240-postmerge-kotlin-uniffi) — 2-file post-merge fix for #2240 Part A.

**VERIFIED TRUE**: UniFFI custody registry (`identity_custody_registry`) is populated ONLY by
create-family: `register_identity_custody` called from identity_create / _with_custody /
_with_agent_key / _link_attestation, plus migrate re-registration of an already-present entry.
`identity_load` builds a `CustodyMethod::External` handle and does NOT insert. So "recovery is
restricted to identities created on this SCP instance" + "identity_load does not populate the
custody registry" is accurate.

**NEW OVERCLAIM (the finding)**: the new message's tail — "PyO3/NAPI additionally admit loaded
identities — reconciled in #2240 Part B" — is FALSE under every reading.
- PyO3 recovery gate keys on `identity_registry` (populated ONLY by create/migrate at
  identity.rs 1171/1288/1443/2178). PyO3 `identity_load` READS the registry and fails 1010 if
  absent — it never adds a DID.
- NAPI recovery gate keys on `identity_registry` (create/migrate only). NAPI `identity_load`
  DHT-fallback (scp.rs ~841) builds an "external" handle with scp_identity:None and does NOT
  register → recovery returns 1020, exactly like UniFFI.
- Net: on ALL three bridges the recovery-admitted set == created-in-process DIDs; identity_load
  populates NO recovery gate. The real distinction is only structural (custody_registry vs
  identity_registry, both create-only). Impact: error-string on a fail-closed path, zero
  security/functional impact — but it's a fresh inaccuracy in the very message the PR exists to
  correct. Scar-tissue pattern (misnomer perpetuated + deferral of a false claim to Part B).
  Fix = drop the "loaded" language / restate accurately. Verdict: SHIP WITH CONDITIONS.

**CLEAN**: Kotlin test fixture retired to neutral `{"status":"delegated"}`; propagation test
upgraded to assert real SCP-IDENT-1022 (meaningful — verifies ffiCall preserves code, not
tautological). Swift Scp.swift:770 is a literal `try inner.identityExecuteRecovery(...)`
zero-logic passthrough; no higher-level Swift wrapper exists; behavior tested at UniFFI Rust
layer (bridge.rs 19167 fails-closed-1022, 19198 unowned-1020, 19227 invalid-tier) — "no Swift
test" is legit ADR-026, not scar tissue. Nullifier `key_rotation_completed` shape fully retired
from live assertions (remaining hits are explanatory doc-comments only).

**Deferrals to Part B**: registry-keying reconciliation = legit (unsettled upstream design,
human sign-off). IDENT_1020 overload (ownership vs invalid-tier share 1020) = weakest deferral,
not structurally gated on the WIRE, but acknowledged + tested-around (Python pins via message,
test_real_ffi.py:288). Catalog doc staleness = marginal/LOW.
