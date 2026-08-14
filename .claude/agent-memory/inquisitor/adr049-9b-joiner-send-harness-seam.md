---
name: adr049-9b-joiner-send-harness-seam
description: Interrogation of ADR-049 §9(b) joiner-send branch (chore/adr049-2f-residual @8acbd3cbb) — H1 MLS-tree membership gate, cfg(testing) TestInstallAccessKey seam, §9.16/§9.17 harness tripwires. Premises hold; honesty intact; two coherence findings (ADR not updated; no expiry-tripwire on seam).
metadata:
  type: project
---

# ADR-049 §9(b) joiner-send — harness seam + H1 gate interrogation

Branch `chore/adr049-2f-residual` tip `8acbd3cbb` vs origin/main. READ-ONLY audit.

## What landed in PRODUCTION vs deferred
- LANDED (prod): spawn_actor_from_welcome gives joiner an Active, send-capable actor
  handle (f0a971ecf); §9.16 H1 gate FIXED (400f6108a); §9.16 pull crypto primitives
  exist (request/handle/store_member_sender_key).
- DEFERRED (real+open GH issues, accurate titles): #2049 §9.16 actor-loop pull unwired;
  #2050 §9.17 access-key distribution entirely unwired in prod (send+receive); #2051
  reconcile §9.17 spec(pull) vs ADR-049 line~420 (Welcome-carried).

## Verdicts
- **H1 gate (mls_group.members() vs member_wrapping_keys cache): SOUND.** Spec §9.16.6
  Mitigation 1 literally names "current member of the context." MLS tree is authoritative;
  the wrapping-key cache was a coincidental adder-side proxy (populated only in
  add_member_from_bytes), empty on a Welcome-joiner → joiner was permanently RECEIVE-ONLY.
  Fix uses the IDENTICAL members()+ScpCredential DID-match that remove_member uses
  (provider.rs:1050). Not wrong-for-wrong. Non-vacuously tested (revert gate → runtime
  test fails at handle_sender_key_request anchor). MLS-only (MlsCryptoProvider); Broadcast
  membership gate is a different path.
- **cfg(testing) TestInstallAccessKey seam: SOUND as a test seam.** Mirrors established
  test_insert_member / seed_peer_pseudonym cfg(testing) precedent; gated on command
  variant + handler + Supervisor entrypoint; NO FFI export (grep in bindings/ empty);
  routes through non-persisting class_c_view + require_active. Lands a key the harness got
  via the REAL §9.17 pull, not a blind mint. Honest stand-in for #2050, not a claim of done.
- **Tripwires: prove genuine crypto composition, NOT production wiring — honestly stated
  in the DURABLE test docstrings (not just commits).** §9.16 side is strong (real pull,
  non-vacuous H1). §9.17 side is NARROWER: handle_access_key_request (wire.rs:280) gates
  only signature/freshness/nonce — NO membership gate (authorization is part of the
  unbuilt #2050 driver), so the §9.17 tripwire proves HPKE seal/open composes, not
  authorization. Green = "crypto composes over simulated transport w/ harness-driven pull
  + seam ingest"; explicitly NOT "prod actor-loop drives pull / ingests on receive."

## Coherence findings (not UNSOUND — honest half-state, but two real gaps)
1. **PROVENANCE: ADR (system of record) NOT updated.** Branch touched no .docs/. ADR-049
   follow-up #1 scoped spawn-from-Welcome to land WITH key injection as one unit; branch
   SPLIT it (entrypoint landed, distribution re-deferred) and recorded the split ONLY in
   commits/code/GH — violates the ADR's own stated rule ("recorded here — not only in
   commit messages and code comments — so they remain in the system of record"). Fix:
   update ADR-049 follow-ups to cite #2049/#2050/#2051 and the entrypoint/distribution split.
2. **DRIFT RISK: the reverse-tripwire discipline was consumed, not reproduced.** ADR
   follow-up #1's praised pattern = a test that FAILS when the deferred thing lands, forcing
   a rewrite. Flipping the reverse-tripwires to positive bidirectional consumed that. The
   NEW deferral (#2050 prod distribution) has NO equivalent: nothing fails when #2050 lands,
   so TestInstallAccessKey seam + manual pull-driving can silently outlive their
   justification and the bidirectional test keeps passing on the seam even if prod
   distribution were broken. Consider tying the seam's existence to #2050.

Overall: SOUND. No false/expired premise; decisions are spec-aligned (implemented spec's
PULL model, flagged ADR for reconciliation via #2051 — correct artifact-flow direction).
