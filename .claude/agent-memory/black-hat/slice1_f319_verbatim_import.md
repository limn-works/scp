---
name: slice1-f319-verbatim-import
description: Black-hat audit of f319ca863 (WASM verbatim ContextRoleState import, BLACK-CEIL-01 fix) — crypto core sound, one LOW doc-accuracy finding
metadata:
  type: project
---

# f319ca863 — WASM export/import verbatim ContextRoleState restore (BLACK-CEIL-01 fix)

Audited the commit that converges WASM context import with native: carry typed
`ContextRoleState` verbatim in the signed snapshot + `member_sequence_numbers`
sidecar, restore as-is on import (no `system_assign_role` recompute, no member_caps
rebuild, no ceiling intersection). Signed: `deserialize_and_verify_envelope` enforces
`exporter_did == role_state.creator_did` + Ed25519 `verify_strict` over JCS bytes.

## VERDICT: crypto/security core SOUND. 14 binding-level probes, all defenses hold.

Probes that PASSED (defenses confirmed), in `crates/scp-ffi/wasm/src/manager.rs`:
- P1 re-wrap under attacker exporter_did → CTX-2093 (exporter==creator binding).
- P2 import with creator key NOT in thread-local registry → CTX-2093. `#active`/`#agent`
  resolution is REGISTRY-ONLY; a `Resolved` (from_did) record REJECTS #active/#agent;
  DID embeds only #0. So a non-creator CANNOT supply a verifying key → fail-closed.
- P3 empty signature → CTX-2093 (fail-closed on unsigned).
- P4 version downgrade (v<N) → CTX-2094 (no unsigned-legacy accept).
- P5 inject extra member into signed snapshot → CTX-2093 (JCS re-canon breaks sig).
- P6 multi-colon `{"Custom":"a:b:c"}` ceiling entry → CTX-2032 at deserialize
  (`CapabilityCeilingRaw::try_from` runs `validate_entries` BEFORE sig check).
- P7 creator-signed over-ceiling member_cap survives verbatim = native parity (in-band).
- P8/P8b sidecar desync (member w/o seq; ghost seq w/o member) → no panic; seq=None /
  ghost survives but not in members. BENIGN: sidecar is INSIDE signed envelope (P5),
  AND import sets `crypto: None` so a reset seq=0 pairs with a FRESH (absent) AEAD key —
  no nonce reuse across export. seq IS fed to encrypt_message(epoch,seq) but only post-
  re-init. Creator-only (in-band).
- P9 un-suspension closed across export/import in BOTH orders (suspend-then-widen,
  widen-then-suspend), 2 members, via PRODUCTION dispatch_governance_action
  (SuspendAccess + ModifyCeiling). Stays suspended.
- P10 double round-trip: member_capabilities no upward drift; stays suspended.
- P12 wrong-signer (attacker #active signs victim snapshot, creator_did kept) → CTX-2093.
- P11 JCS idempotent.

GOTCHA that bit my first draft: `test_insert_ceiling` calls the TEST-ONLY
`set_ceiling_and_refresh` which RE-RUNS `system_assign_role` (re-grants suspended
member). That is NOT the production path. Production `dispatch_modify_ceiling` does
`set_ceiling` ONLY (no refresh) — matching native `apply_pending_ceiling_modification`.
Use dispatch_governance_action(ModifyCeiling) for un-suspension probes, not the helper.

## FINDING (LOW, doc-accuracy only — NOT exploitable):
`canonicalize_snapshot_sets` doc (manager.rs ~L7519-7526) claims "the whole
`role_state` subtree serializes byte-identically regardless of incidental iteration
order." FALSE: `assignments: HashMap<_, RoleAssignment>` has JCS-sorted KEYS, but each
value carries `tokens: Vec<UcanToken>` where `UcanToken.att: Vec<UcanAttestation>` is an
UNSORTED Vec (HashSet-iteration order from system_assign_role) and `nnc` is a RANDOM
nonce (`generate_nonce`). Probe 11b/11c empirically: same logical state, two member
insertion orders → members/member_capabilities/ceiling/role_definitions/suspended all
byte-identical (serde_sorted_set works), but `assignments` JSON DIFFERS.
BENIGN because WASM export is single-signer verbatim (signer signs what it produced;
verifier re-canon the SAME received bytes; tokens carried verbatim). WASM digest is
explicitly NOT byte-parity with native (manager.rs L470). So no convergence claim breaks.
Recommend: soften the doc sentence to exclude `assignments[*].tokens` (att Vec order +
random nnc) from the byte-identical claim, OR sort `att` + note nnc non-determinism.

No native-parity (in-band creator authority) behavior raised as a WASM finding.
