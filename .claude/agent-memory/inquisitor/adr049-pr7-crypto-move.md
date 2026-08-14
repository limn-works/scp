---
name: adr049-pr7-crypto-move
description: ADR-049 PR-7 (SCP-CRYPTOMOVE-001) crypto ownership-move review — Class-S/C classification reasoning, golden-oracle bounded window, and the pub-vs-pub(crate) cross-layer-gate root cause
metadata:
  type: project
---

ADR-049 PR-7 moves per-context MLS crypto ownership off `Arc<MlsCryptoProvider>` onto the
actor-owned `PerContextState` (`take_crypto_state` at spawn, one-way per context). Reviewed
branch `feat/adr049-pr7-atomic-crypto-move`. Durable structural facts worth reusing:

**Class-S vs Class-C is semantically discriminated, not blanket.** The repo classifies each
mutation by *replay consequence*, and PR-7 keeps that discipline honest:
- `xctx_nonce_dedup` (cross-context outlet invocation) is **Class-S / fail-closed** because
  replaying a valid invocation re-invokes a real side effect ("grants something") — state.rs
  ~line 815 documents exactly this.
- per-context sender-key answer `nonce_dedup` is **Class-C / coalesced** because re-answering
  a *still-fresh* replay re-seals the SAME key to the SAME requester ephemeral pubkey (fresh
  per-seal HPKE ephemeral, no AEAD nonce reuse) — only the legitimate ephemeral-secret holder
  can open it, and the membership gate authorizes live regardless of dedup. "Grants nothing"
  is a genuine analysis backed by `key_protocol.rs::handle_sender_key_request` (freshness gate
  + HPKE-seal-to-requester + live membership gate). Verified SOUND.
- The related LAND path's epoch-floor advance IS Class-S fail-closed. Correct split.
  Lesson: when reviewing a "coalesced is fine" claim here, check whether replay produces a
  side effect vs. re-emits ciphertext only the legit party can open. That is the axis.

**Golden-oracle bounded-window pattern.** PR-7 DELETED most provider steady-state crypto twins
and re-pinned the actor methods against golden *expectations* (deterministic decrypted value),
NOT against a live provider twin. Only ~6 `#[cfg(any(test, feature="testing"))]` twins are
RETAINED in provider.rs (chiefly `handle_sender_key_request`) as byte-identity oracles + the
provider-level two-party fixture (`two_party_test_support.rs`, which needs providers that still
own crypto so consumers can `take_crypto_state`). Not dead (exercised), feature-gated out of
production (prod is zero-grep clean), and the byte-identity test self-protects against the drift
two-definition usually risks. OPEN concern: the window's bound is the "§6 provider-struct
dissolution" — documented in ADR-049 §376 as an "eventual / separable follow-on" with NO tracked
story ID. If §6 never gets ticketed, "bounded" becomes permanent duplication + lockstep
maintenance tax. Hold firm that the bound needs a real forward-only story.

**pub-vs-pub(crate) drift → cross-layer gate friction (root cause).** `send_checkpoint` /
`send_heartbeat` (messaging_helpers.rs) are declared `pub` but their own comments
(pipeline_wiring.rs:142, handlers/messaging.rs:1027) call them `pub(crate)`, and their only
callers are in-crate (actor handlers). PR-7's async-conversion signature change re-tripped
`check-cross-layer.sh` (which flags new `pub fn` without an FFI export; it exempts pub(crate)).
Root cause = pre-existing over-broad visibility contradicting documented intent. Correct fix is
narrowing to `pub(crate)` (removes the friction permanently), NOT a cross-layer-exempt marker
(papers over the symptom). The async conversion itself is SOUND/forced: the seal now mutates
owned crypto state, so the receiver became `&mut PerContextState` (Send), which retires the
ADR-049 Decision-7 sync-fn-returning-future workaround (that existed only to keep a `!Sync`
`&PerContextState` off the await). Decision 7 still governs the functions that keep shared
`!Sync` borrows — principled divergence, not drift.
