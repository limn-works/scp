# Red Hat Agent Memory

## PR #127 Reassessment (2026-03-01, post-fixes)
After commit 54b8096 ("close 6 remaining gaps"), reassessed all chains.

### Fixed (closed)
- RED-101 partially fixed: WASM now has Ed25519 sig verification (verify_token_signature). Still missing 5/11 checks (delegation chain, root issuer, audience, attenuation, nonce, ceiling).
- RED-018/custody_type: UniFFI fallback changed from Hardware to InMemory.
- Inner envelope: u32 length prefixes added for field-boundary collision prevention.

### Still Open
- **RED-101 (HIGH, downgraded from CRITICAL)**: WASM validation still missing 5/11 ADR-016 checks: delegation chain, root issuer, audience, attenuation enforcement, nonce replay, ceiling. Self-signed tokens now rejected (sig verified), but tokens can be used cross-context via missing audience check.
- **RED-102 (HIGH)**: NAPI/UniFFI still mint `[0u8; 64]` placeholder signatures (napi/ucan.rs:432). Tokens structurally valid but fail Ed25519 verification in any bridge with sig checking.
- **RED-103 (CRITICAL)**: Broadcast gated subscription still uses stub `roles::UcanToken` with NO signature/expiry. validate_messages_read_ucan still only checks aud+att string match.
- **RED-105 (HIGH)**: WASM wildcard bypass still present (wasm/ucan.rs:234). `starts_with(&context_prefix)` without trailing `/` delimiter. Token for `scp:ctx:a` matches `scp:ctx:abc`.
- **RED-106 (MEDIUM)**: SSE notification->request conversion still uses hardcoded `id: 0`.
- **RED-107 (HIGH)**: SSE endpoints still have no authentication.
- **RED-108 (MEDIUM)**: block_subscriber still doesn't remove from subscribers HashMap. can_read() still returns true for blocked subscribers.
- **RED-109 (MEDIUM)**: Handle context target squatting still possible -- any DID registers handles pointing to any context.
- **RED-110 (MEDIUM)**: Cover traffic fixed 1024-byte payloads still distinguishable from real messages.
- **RED-111 (HIGH, upgraded)**: NAPI proof resolver uses `compute_revocation_cid` to key proofs (bare hex CID), but scp-core validation pipeline expects `compute_cid` format (bafyrei-prefixed JWT hash CID) in `prf` field. Delegation chains through NAPI are silently broken. PyO3 and UniFFI use correct `compute_cid`.

## Key Attack Patterns for This Codebase
- **Bridge parity gap**: WASM bridge cannot depend on scp-core (tokio incompatibility), so it re-implements validation partially. ALWAYS check WASM bridge when core validation changes.
- **Two UcanToken types**: `roles::UcanToken` (stub, no sig/expiry) vs `crypto::ucan::UcanToken` (full, has sig/encoded). Broadcast uses the stub. Any code accepting the stub has no sig verification.
- **CID computation divergence**: `compute_cid` (JWT hash + bafyrei prefix) vs `compute_revocation_cid` (payload JSON hash, hex). PyO3/UniFFI use `compute_cid` for proofs (correct); NAPI uses `compute_revocation_cid` (wrong). Cross-bridge delegation chains break.
- **Zero-signature tokens**: NAPI and UniFFI bridges mint `[0u8; 64]` placeholder sigs. These pass structural parsing but fail Ed25519 verification.
- **SSE broadcast model**: All SSE clients receive all responses. No per-session isolation.
- **Wildcard prefix matching**: `starts_with` on context_id without delimiter allows cross-context access for IDs sharing a prefix.
- **"Caller is responsible" pattern**: Still present from PR #76. claim_shadow, upgrade_shadow_role defer sig verification.

## Critical Files
- `crates/scp-ffi/wasm/src/ucan.rs` -- Missing 5 validation steps (RED-101), wildcard bypass (RED-105)
- `crates/scp-core/src/context/broadcast.rs` -- Stub UcanToken no sig (RED-103), block doesn't remove (RED-108)
- `crates/scp-core/src/context/roles.rs` -- Stub UcanToken struct (no signature field)
- `crates/scp-ffi/napi/src/ucan.rs` -- Zero-sig mint (RED-102), wrong proof CID function (RED-111)
- `crates/scp-mcp/src/sse.rs` -- No auth (RED-107), notification confusion (RED-106)
- `crates/scp-core/src/discovery/handles.rs` -- Context target squatting (RED-109)
