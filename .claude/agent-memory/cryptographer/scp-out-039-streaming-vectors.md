---
name: scp-out-039-streaming-vectors
description: SCP-OUT-039 outlet-streaming conformance vectors (§25.21) crypto review — seeds byte-exact, preimages sound, 2 broken-provenance + 1 defense-in-depth finding
metadata:
  type: project
---

# SCP-OUT-039 outlet-streaming conformance vectors (branch feat/outlet-streaming-ffi)

Reviewed §25.21 behavioural vectors + §5.4.5 crypto. Core preimage helpers in
`crates/scp-protocol/src/context/outlets/stream.rs`. VERDICT: crypto SOUND, no seed/preimage byte error.

**Why behavioural not KAT:** §25.21 vectors carry payload *descriptors*, sigs+caveats_binding
recomputed at replay (request_id/sequence/caveats_binding not fixed until open). Preimage-structure
anchoring lives in CORE unit KATs (all PASS): caveats_binding_preimage_matches_spec (stream.rs:1936),
chunk_sig_preimage_matches_spec (:1980), credit_sig_preimage_matches_spec, cancel_sig_preimage_matches_spec
— hand-rolled re-derivations. Vector tier relies on these for preimage correctness (wrapper==core is
FFI-marshalling check, NOT a preimage anchor — delegates to same core fn).

- **Seeds byte-exact** to §25.2 (0x9d61b19d…7f60, RFC8032 §7.1 TV1) in ALL 6 files: scp-client-wasm
  lib.rs:905, scp-testing outlet_stream_conformance.rs:64 + through_open_path.rs:72, scp-ffi
  tests/outlet_stream_vectors_real.rs:63, uniffi/tests/…:55, napi/src/outlet_stream/tests.rs:481.
- **caveats_binding empty-caveats:** InvocationCaveats::empty()=all None; every field skip_serializing_if
  → JCS `{}`. Option-omit honored. BUT vectors only use EMPTY caveats (degenerate, order-independent).
- **WASM loop** signs all 29 chunks (22 data/4 end-synth-provenance/3 error), verify-TRUE under operator,
  verify-FALSE under real wrong key [0x11;32]. Real tamper. total_chunks==29 pins full coverage. Test PASSES.
- **cancel next_seq runtime-derived:** CancelIdentity carries NO next_seq; apply_outlet_cancel_signed
  reads live cursor (dispatch.rs:760/1079). §5.4.5:545 mandates this. credit binds monotonic_seq+stream_epoch+caveats_binding.
- §5.4.5:483 "stream_epoch NOT in chunk preimage but IS in credit preimage" — impl matches exactly.

UPDATE @9c63e91b2 (C12 final gate, b3a1dd3dc..9c63e91b2): all 3 prior findings RESOLVED + §25.2 pubkey typo fixed.
- §25.2 PUBKEY FIX VERIFIED CORRECT: spec doc changed tail daa3f4a18446b0b8d183f8e3 → daa62325af021a68f707511a.
  Independent pure-Python RFC8032 derivation from seed 0x9d61…7f60 = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a.
  Matches repo REF_PUBKEY (test_vectors.rs:42, enforced by vector_0_ed25519_sanity_check) AND harness EXPECTED_OPERATOR_PK.
  OLD value was a DOC-ONLY tail corruption (code was always right); fix removes a fresh-SDK-implementer landmine. SOUND.
- caveats_binding pinned value REPRODUCED: non_streaming expected_caveats_binding=92888ab8… recomputes exactly with
  effective_caveats_jcs=`{}` (empty). assert_caveats_binding_kat (common:666) uses real InvocationCaveats::empty().to_canonical_json_bytes(),
  runs over all 7 (caveats_binding_kat_pins_all_seven:713). ucan_cid/invoker_did load-bearing.
- FOCUS-4 SDK gap-cancel NON-FORGEABLE: all 4 SDK drains (py outlets.py:_send_cancel, ts #sendCancel, swift sendCancel:646,
  kotlin sendCancel:595) route through bridge outletStreamCancel(handle_id, caller_did) ONLY. Bridge outlet_stream_cancel_impl
  (outlet_stream.rs:913) authorized_control enforces caller==pinned invoker, signer=invoker custody key, CancelIdentity from
  pinned-at-open values, apply_outlet_cancel_signed reads RUNTIME live cursor (no SDK next_seq). CRITICAL#1+#3 hold.
- RESOLVED MEDIUM: outlet_caveats_binding_conformance.rs now EXISTS as registered [[test]] target (Cargo.toml:109) + exercises
  non-empty omit-none (amount_max_per_call=Some(100)+11 absent, :31/:72). §5.4.5:439 citation now resolves.
- RESOLVED LOW: §25.21:890 NAPI path corrected to napi/src/outlet_stream/tests.rs.
- RESOLVED LOW: EXPECTED_OPERATOR_PK now ASSERTED == derived key (common:732, scp-ffi:231, uniffi:182/314).
- Delta touches ZERO core preimage code (no scp-protocol/context/outlets) → prior core-KAT verification holds.
VERDICT @9c63e91b2: CLEAN, no crypto findings, APPROVE.
