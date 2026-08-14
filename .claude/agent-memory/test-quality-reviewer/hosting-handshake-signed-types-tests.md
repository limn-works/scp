# §5.14.13 Broadcast Hosting Handshake signed-types tests (commit 54f937e0f, branch saga-2c)

File: `crates/scp-protocol/src/context/broadcast/hosting_handshake.rs` (NOT scp-runtime —
diff-stat path label is misleading). 26 `#[test]`s in inline `mod tests`. Module is `pub mod`
wired in `broadcast/mod.rs:18`. Spec source: `.docs/specs/05-contexts.md:1587` (§5.14.13).
Reviewed clean — SHIP.

## Types under test
BroadcastHostConfig (clamp/validate/with_defaults/to_jcs), BroadcastHostingRequest
(sign/verify/signing_preimage, OPTIONAL ucan), BroadcastHostingGrant (sign/verify/preimage),
AcceptedHostSnapshotEntry (JCS). Signed via §9.5.1 canonical_hash (domain-separated,
field-enumerated, length-prefixed) — NOT SHA-256(prefix‖JCS).

## Why the byte-exact preimage tests are NOT tautological (key finding)
`request_preimage_is_byte_exact_gated` (812) + `grant_preimage_is_byte_exact` (939)
reconstruct the SHA-256 preimage INDEPENDENTLY (raw `Sha256::new()` + manual field
concatenation), then assert `==` the impl's `signing_preimage()`. They do NOT call the impl's
own hasher to check itself. The hardcoded field order matches the NORMATIVE §5.14.13 order
verbatim (Fixed32 host, Fixed32 broadcast, VarBytes(did), Fixed32(wrapping_pubkey),
VarBytes(jcs(config)), [OptVarBytes(ucan) | U64(current_key_epoch)], RawBytes16(nonce),
U64(timestamp_ms)). Spec is source of truth → survives any canonical_hash refactor that
preserves the contract. HIGH ROI.

## Other strong patterns
- `*_tamper_each_covered_field_fails_verify` (766/901): per-field bit-flip sweep incl the
  gated↔ungated `ucan: Some→None` transition.
- `ucan_absent_differs_from_present_empty` (846): pins §9.5.1 optional-field invariant
  (absent SHA-256(0x00) sentinel ≠ present zero-length VarBytes 00000000). Real collision
  resistance, not a round-trip.
- wrong-signer, domain-separator-distinctness, request≠grant-preimage, serde+JCS round-trips.

## Honest scoping (NOT a gap)
Signed-TYPE coverage only. Runtime Prepare-B lifetime-ceiling clamp
(min(requested, granted_at_ms+max_grant_lifetime_ms)) and post-grant HPKE-pull
wrapping_pubkey binding are documented as later 2C runtime steps — doc comments on verify()
explicitly warn "verify checks signature ONLY; caller MUST separately validate/clamp". No
overclaim. Correct per-leaf-type scoping.

## Flakiness: LOW across all 26
Fixed seed keys (`SigningKey::from_bytes(&[seed;32])`), fixed nonces/timestamps, deterministic
JCS. No time/network/random/order deps.
