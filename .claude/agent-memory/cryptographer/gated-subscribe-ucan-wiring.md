---
name: gated-subscribe-ucan-wiring
description: Gated broadcast-subscribe messages:read UCAN validation wiring (spec §5.14.4) — soundness review, base 9f85f5346
metadata:
  type: project
---

# Gated broadcast subscribe — messages:read UCAN validation

Handler: `crates/scp-runtime/src/context/actor/handlers/broadcast.rs::handle_subscribe_broadcast`
Enforcement: `crates/scp-protocol/src/context/broadcast/mod.rs` `validate_messages_read_ucan` (L2088) → `validate_ucan` 11-step (validate.rs L550). Called from `BroadcastContext::subscribe` L717 with **`self.context_id`** (trusted state, NOT payload id).

**SOUND.** Full pipeline runs on presented token: sig (Ed25519 verify_signature), delegation chain (verify_delegation_chain — fail-closed: unresolvable proof → DelegationChainBroken, circular detect, all-chains-converge-to-one-root), root-issuer == `cell.role_state.creator_did`, audience == `p.subscriber_did`, capability match bound to THIS context (CapabilityUri wildcard grant OK but still ceiling+root checked), ceiling = `role_state.ceiling().to_ucan_string_set()` over full att set, expiry (exp>now, exp<=now+24h MAX_EXPIRY_SECS enforced regardless of nonce noop). Adapters (KeyResolverDidResolver, ContextRevocationChecker, InMemoryProofResolver from `cell.xctx_ucan_proofs.proofs`) reuse the SAME runtime adapters as saga::validate_ucan_rebind.

**Nonce noop (NoopNonceTracker) is sound for this capability class.** exp capped at 24h → a re-presented long-lived read grant has nnc up to ~24h stale, far beyond ±5min freshness window; stateful tracker would wrongly reject (NonceTooOld). Replay neutralized structurally: audience binding (token aud must == presenting subscriber DID) + duplicate-subscriber reject in subscribe. `check_and_record` default = check_replay+record, both overridden Ok(()). Expiry/revocation steps still run.

## Non-blocking notes (pre-existing, NOT regressions)
- Revocation set `governance.revoked_spending_ucan_cids` is documented **always-empty in current build** (economy_logic.rs L115-128) — revocation STEP runs but backing set empty runtime-wide (all capabilities). "spending" name reused for messages:read; when revocation lands, revoker must insert messages:read CIDs into this same per-context set or this path won't see them.
- Subscribe has NO proof-of-possession of subscriber key: anyone holding a copy of a token issued to DID S can register S as subscriber (aud binding forces subscriber_did==S). Low impact (public-within-context read; key delivery separately gated by wrapping pubkey in handle_broadcast_key_request). Pre-existing — open subscribe is also unsigned.
- Root-issuer==creator only (not "admin"): correct — admins issue via delegation chain rooted at creator. An admin NOT in a creator-rooted chain cannot issue a valid grant = correct fail-closed.
