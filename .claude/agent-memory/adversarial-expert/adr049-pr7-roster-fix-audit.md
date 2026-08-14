---
name: adr049-pr7-roster-fix-audit
description: Final double-zero adversarial audit of ADR-049 PR-7 roster-fix set (branch feat/adr049-pr7-atomic-crypto-move, HEAD bf1a787dc). Verdict SHIP, zero defects.
metadata:
  type: project
---

# ADR-049 PR-7 roster-fix audit (2026-07-15, HEAD bf1a787dc)

Diff 2a916e9c2..bf1a787dc — roster fixes after the separately-reviewed crypto-move core.
Verdict: ZERO defensible defects. SHIP.

**Why:** deep line-by-line verification of the five flagged risk areas; tried to break each and could not.

**How to apply:** if re-reviewing this branch or a follow-up touches these seams, these are the load-bearing facts.

## Verified sound
1. **Identity binding (BLACK-P7-1)** — `decrypt_and_dispatch` (messaging_helpers.rs:3150) rejects `request.requester_did != sender_did` where `sender_did` is MLS-credential-authenticated (state.rs `open()` → `decrypt_with_sender_did`). requester_pk resolved from `sender_did` (not payload). So gated-DID = authenticated-DID = signing-key, all one. String compares are exact; both DIDs extracted identically from ScpCredential → no normalization gap. The command-path answer (`Supervisor::handle_sender_key_request`, `HandleSenderKeyRequest` variant, `handle_handle_sender_key_request`) is FULLY `#[cfg(feature="testing")]`-gated — not the production answer path.
2. **KP-validate collapse (P2)** — `ProductionMlsBackend::validate_key_package` extracts `credential_did` from the SAME validated leaf (`validated.leaf_node().credential()` → BasicCredential → ScpCredential → did), mirroring retired `scp_mls::group::key_package_in_did` exactly. Callers (execute_add_member, join_context) compare `credential_did == owner/member_did` before the add — equivalent to the retired provider `validate_key_package(owner_did, kp)` internal check. Only `ProductionMlsBackend` is non-test (FailingBackend delegates); no alternate-backend spoof path. `scp_mls::group::add_member` independently re-validates sig/lifetime/ciphersuite. NO regression, NO dropped binding.
3. **Wire format (BLACK-P7-2)** — actor answer now `SenderKeyDistributionMessage::KeyResponse(r).to_bytes()` (msgpack, internally `#[serde(tag="msg_type")]`), matching receiver `from_bytes` (`process_incoming_sender_key`). Single `pending_distributions` producer (messaging_helpers.rs:3193); drain_and_deliver passes bytes as the management payload → single wrap, no double-wrap. Bare `SenderKeyResponse` (no msg_type tag) would fail decode → was the silent-drop bug. Test-only PROVIDER copy still bare (fixture-internal, no wire authority) — correctly documented.
4. **Heartbeat (HIGH-1)** — `handle_send_heartbeat` reports `ok_mutated`/`err_mutated`. Encrypted path: seal in encrypt_and_send precedes the empty-routing no-op, so a peerless/failed heartbeat still advanced the MLS send-gen (Class-C) → must coalesce. Reduces the #2149 window. Broadcast path returns early w/o seal — over-marking mutated is harmless (one redundant coalesced snapshot; collapses within window).
5. **Interactions** — `requester_public_key: [u8;32]` coerces to `&[u8]` for verify; prod passes `VerifyingKey::as_bytes()`. FFI `compile_error!(all(testing, extension-module))` references real features; fires only on the release-wheel-with-testing mistake, not on `cargo test` (extension-module suppresses symbol linking). Single ValidatedKeyPackage constructor.

## Non-blocking observation (not a defect)
Broadcast-context heartbeat over-marks `mutated` → 1 redundant coalesced snapshot per heartbeat interval. Bounded, negligible, acknowledged in-code. Pull answer routes to context_routing_id (all members) but HPKE-sealed to requester's ephemeral key — pre-existing, shared with push path, confidentiality intact.
