---
name: pr7-crypto-move-verdict
description: ADR-049 PR-7 (atomic crypto move) black-hat re-review verdict — BLACK-P7-1/2/5 all closed, no new exploit
metadata:
  type: project
---

# ADR-049 PR-7 (feat/adr049-pr7-atomic-crypto-move) — black-hat convergence verdict

Branch feat/adr049-pr7-atomic-crypto-move, HEAD de5e9b1a5. Verified prior BLACK-P7-* fixes.

**Verdict: ZERO exploitable findings. All prior BLACK-P7-* genuinely closed.**

- **BLACK-P7-1 (identity binding) CLOSED.** `decrypt_and_dispatch` (messaging_helpers.rs ~3147)
  rejects `request.requester_did != sender_did`. `sender_did` is MLS-authenticated from the
  credential (state.rs open() → `decrypt_with_sender_did`), NOT payload. requester_pk resolved
  from sender_did (line 3160); signature verified with it; membership + block gates all operate
  on the bound identity. No path to get a key sealed to your ephemeral under another DID.
- **BLACK-P7-2 (wire format) CLOSED.** Pull answer now `SenderKeyDistributionMessage::KeyResponse(..).to_bytes()`
  (state.rs ~2051), matching push path (distribute_sender_key) and what receiver parses
  (from_bytes → KeyResponse in both actor state.rs:2757 and provider process_incoming_sender_key).
  rmp round-trips. The two remaining bare `to_vec_named(&response)` producers (key_protocol.rs:301,
  provider.rs:1764) are TEST-ONLY fixtures — provider.handle_sender_key_request callers are all tests;
  live receive path uses actor cs.handle_sender_key_request.
- **BLACK-P7-5 (seam leak) CLOSED for realistic configs.** Test handlers (LandSenderKeyResponse etc.)
  are `#[cfg(feature="testing")]` and NOT exported by ANY FFI bridge (grep confirms). signed_at_override
  rejection gated on each bridge's OWN `testing` feature via `#[cfg(not(feature="testing"))]`.
  KEY: `allow_in_memory_custody` enables `scp-core/testing` but NOT the bridge's own `testing` (Cargo
  features are one-directional) — so the rejection stays compiled in on desktop/CLI builds. PyO3 adds
  a compile_error!(testing+extension-module) defense-in-depth guard (possible because extension-module
  is a clean production marker; napi/uniffi lack one). Authority-escalation seams deliberately kept out
  of `testing` in dedicated `outlet-capability-test-grant`. Residual = explicit `--features testing` on
  a shipped napi/uniffi artifact = build-misconfiguration, not an exploit.
- **nonce_dedup ≤300s + send-gen residuals:** honestly documented + tracked (#2146 block wiring, #2149
  send-gen). REQUEST_FRESHNESS_SECS = NONCE_EXPIRY_SECS = 300. Crash-replay re-answers an idempotent
  HPKE re-seal to the SAME ephemeral the requester already holds — grants nothing, freshness-bounded.
  NOT an authorization break.

Non-blocking observation only: napi/uniffi lack the PyO3 compile_error defense-in-depth guard, but
this is not exploitable (requires deliberate `--features testing` in a shipped build).
