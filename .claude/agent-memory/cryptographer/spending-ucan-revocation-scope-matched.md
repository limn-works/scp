# Scope-Matched Spending-UCAN Revocation (commit 904f6d3dc, spec 72817f104, §19.5)

Reviewed 2026-07-08. Verdict: SOUND, no blocking findings.

## CID identity (byte-identical at both sites) — VERIFIED
- `compute_revocation_cid(s)` = lowercase-hex(SHA-256(s.as_bytes())), 64 chars. Over the RAW encoded JWT string. (revoke.rs:648)
- Gate (spending.rs:1097): `compute_revocation_cid(&token.encoded)`. `parse_ucan` (validate.rs:434) stores `encoded` VERBATIM — no re-serialization.
- Revoke (supervisor revoke_spending_ucan): `compute_revocation_cid(encoded_token)` on the same raw arg the bridge forwards.
- Store write, ArcSwap cache, hydration all carry the same hex string raw. No canonicalization anywhere → no mismatch.

## Identity binding (store key == lookup key == token iss) — VERIFIED
- Spending UCANs are self-delegations iss==aud==payer. Gate Step A (spending.rs:1046-1057) HARD-enforces token.iss==token.aud==actor_did before revocation Step F.
- Global store keyed by `iss` (verify enforces iss==aud). Gate looks up `global_revoked_spending_cids.get(sender_did)` where sender_did==actor_did==iss.
- Cannot poison another DID's set (verify_signature requires sig under iss's kid VM). Cannot evade own revocation (must present token with iss==self, looked up under self).

## verify-before-revoke (spending::verify_spending_ucan_genuine) — SOUND
- Checks: header.validate + is_spending_ucan + iss==aud + validate_key_scope + verify_signature (kid-aware, resolve_public_key_by_kid under iss).
- Deliberately skips nonce-freshness + expiry + delegation-chain. Skipping opens NO hole: the only effect of entering a store is inserting a CID; expired/replayed/bad-chain tokens are independently rejected at gate Steps C/E/G. Set membership = {genuinely-signed spending self-delegations by iss}, keyed by iss → anti-bloat holds.

## Scope classification identical at route vs spend — VERIFIED
- `spending_scope_of` and gate `validate_spending_ucan` (Step H) BOTH select via `.find(|a| a.with.starts_with("scp:spending:") && a.can=="spend")` then `SpendingScope::parse`. First-match, identical predicate → a token cannot classify one way at revoke, another at spend. Global(`*`) vs Context(id) sound.

## Auth model (observation, not a finding)
- Spending-revoke authz lives at the BRIDGE: all 3 native bridges run `core_revoke_ucan` w/ BridgeRevocationAuthorizer (issuer-OR-creator) + `is_spending_ucan` gate BEFORE `revoke_spending_ucan`. `revoke_spending_ucan` itself has no independent revoker authz — relies on that prior gate. A context-creator can revoke another payer's global token (issuer-OR-creator), but enforcement is LOCAL per-instance self-governance, bounded by 24h expiry. Fine for the model.
- Saga §7 path (saga.rs:1167) keys global set by the OUTER tool-invoke token's iss; inert for spending (tool-UCAN CIDs never in spending store) — defense-in-depth, not load-bearing.

## Infra
- sanitize_key_component REJECTS (../, \, .., NUL) — validating gate, not lossy; DIDs+hex pass unchanged → storage key injective, no collision.
- Hydration wired into restore_on_startup (supervisor.rs:9019), after saga replay. Store keyed `identity/{did}/revoked_spending_ucans/{cid}`, record stores raw did+cid.
- Fails CLOSED: no KeyResolver → verify errors → revoke Err (no false revocation). Empty store → global map empty.
