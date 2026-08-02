---
name: nonce-dedup-saga-removal
description: NonceDedup configurable-TTL API removed in lockstep with cross-context saga deletion — no replay regression
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (vs origin/main) reverts
`NonceDedup` (`crates/scp-protocol/src/crypto/sender_keys/key_protocol_verify.rs`)
from per-instance configurable TTL back to a fixed `NONCE_EXPIRY_SECS` (300s).

Removed: `with_ttl`, `ttl_secs()`, `from_entries`, `from_entries_with_ttl`,
`entries()`, the `ttl_secs` field; `NONCE_EXPIRY_SECS` / `NONCE_DEDUP_CAPACITY`
de-`pub`'d (now private consts). `#[derive(Default)]` instead of manual impl.

**Why this is NOT a replay regression (SOUND):** the configurable-TTL API
existed solely for the §6.2.4 cross-context saga, which set its dedup window
strictly longer than its clock-skew tolerance to close the coterminous-window
gap (BLACK-XCTX-01). That saga is **fully deleted in the same diff**:
`context/tools/cross_context_saga.rs` gone, `handlers/saga.rs` gutted, zero
remaining refs to `cross_context_saga`/`CrossContextSaga`/`BLACK-XCTX` in crates/.
Only surviving `NonceDedup` consumers: `scp-runtime .../wrapping_extension.rs`
(×2), both `NonceDedup::new()` (sender-key request path, default 300s where
freshness == dedup window by design — no skew gap). Core `is_replayed`/`record`
logic unchanged and sound (TTL prune + capacity oldest-eviction).

**trust.ts (focus file):** unchanged-sound vs prior review
[[trust-ucan-classification]]. Confirmed exact parity with
`bindings/python/scp_sdk/trust.py` (_PASSED_BEFORE map, prefix lists,
classify order SIGNATURE_CHAIN→CEILING→TOKEN_PARSE→NONCE→REVOKED→EXPIRY).
Boundary `validate_ucan_token`/`validate_capability_uri` throw [SCP-VALID-*]
(not [SCP-PERM-*]) → re-thrown by evaluateTrust regex, matching Python (catches
UcanError only). Fail-closed; ucan_validate_on delegates to full validate_ucan
with rt.ceiling_strings. **ADR-051 design-only, no code** [[adr-051-prerotation-substrate]].

**RE-VERIFIED 2026-06-20 @HEAD ad51633f3 — VERDICT CLEAN.** Confirmed against
live source (not just memory): (1) zero `with_ttl`/`from_entries`/`ttl_secs`/
`cross_context_saga`/`CrossContextSaga` consumers remain anywhere in crates/+bindings/.
(2) HPKE seal/open + verify_sender_key_request/verify_block_notification/
verify_epoch_advance fn signatures untouched — the 3 key_protocol_verify hunks are
ONLY `pub const`→`const` + doc-comment + removal of saga-only NonceDedup methods.
(3) mls/provider.rs diff is 100% doc-comment terminology (ContextManager→actor/
supervisor, ADR-049) — no functional crypto change. (4) trust.ts `__PASSED_BEFORE`
+ all 6 prefix sets are byte-faithful to Python `_PASSED_BEFORE` and consistent with
the live 11-step `validate.rs` order (parse1→sig2→chain3-5→keyscope5ab→cap6→catA6b→
atten7→ceiling8→nonce9→revoke10→expiry11). (5) Every TS prefix maps to a REAL Rust
Display chain: UcanError #[error] strings in ucan/mod.rs, MalformedToken(format!) in
validate.rs (`verification method`, `unrecognized signing key ID`, `unparseable
capability URI in attestation`), and `From<ResolutionError> for CoreUcanError` in
scp-ffi/common/resolvers.rs (`DID not found`/`invalid DID document`/`network
unavailable`/`DID revoked\/downgraded`/`z-base-32 decode failed`/`DID public key must
be 32 bytes`/`hex decode failed`/`unsupported DID method`). startsWith semantics hold
for the longer real strings. (6) NAPI From<UcanError> advice suffix uses em-dash U+2014
(` — check token format...`), matching `__extractCoreError`'s ` — ` split. (7) Layer-2
zeros (totalDuration/governanceActionsAgainst/roleHistory) are honest no-data, not
fabricated — bridge exposes no such data at this layer; matches Python dataclass
defaults. KNOWN conservative approx (present in BOTH SDKs, not a regression): step-6
`ceiling` failure reports signaturesValid=true even though atten(7)/catA(6b) never ran.
