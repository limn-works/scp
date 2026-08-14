---
name: scp-out-048-browser-invoker-signing
description: SCP-OUT-048 browser-invoker in-tab credit/cancel signing predicates + BrowserInvokerStreamSession (feat/outlet-xctx-048-wasm-session, HEAD 4cdc78a89) crypto review
metadata:
  type: project
---

# SCP-OUT-048 browser-invoker streaming signing (crypto review)

ROUND-4 FINAL (to-be-merged HEAD 4d54f107c, rebased): CONFIRMED SOUND — no new crypto findings. Round-4 delta 755ee122c..4d54f107c is TS-ONLY + rebase noise: (1) client.ts assertGrantU32 raw-predicate guard [1,2^32) on outletStreamSignCredit + outletStreamComputeCreditPreimage — reject-only, never transforms bytes, boundary correct (2**32 exactly representable, max valid=u32::MAX), applied to BOTH sign+preimage so no divergence, throws InvalidGrant (re-exported from sibling ts pkg errors, pre-existing branded-Credit class); (2) outlet-stream-session.ts REMOVED the caller-seed .fill(0) in #markClosed (R4-2) — DEFENSIBLE: seed is caller-owned long-lived identity key, JS-side fill was explicitly non-load-bearing (tab threat model assumes heap-read, ADR-057 Slice-3), and filling it would CORRUPT a caller reusing the buffer across sessions; wasm-side transient zeroize UNCHANGED (signing_key_from_seed lib.rs:1062/1066/1067 zeroizes both Vec+[u8;32] incl err path); comprehensive protection = #1980; (3) asyncDispose now async + added sync Symbol.dispose (TS2851 fix), both defer to idempotent #markClosed. VERIFIED: credit preimage source scp-protocol stream.rs BYTE-IDENTICAL to prior-sound 4cdc78a89 (0-line diff); scp-client-wasm/src/lib.rs UNTOUCHED by round-4 (empty diff); bridge.rs/provider.rs/ttl.rs/state.rs churn = rebased main (#2148 CloseOrchestrator no-crypto-provider), unrelated to outlet credit. KAT RAN native: `cargo test -p scp-client-wasm --lib` 14/14 pass incl credit_preimage_matches_core_helper + sign_credit_roundtrips_and_binds_epoch + verify_chunk_signature. No code modified.

VERDICT: crypto core SOUND. 2 MEDIUM (both non-cryptographic: 1 spec-conformance gap-cancel + false comment, 1 test coverage), 2 LOW/INFO doc.

**What shipped**: crates/scp-client-wasm/src/lib.rs adds 4 #[wasm_bindgen] invoker predicates — outletStreamSignCredit/SignCancel (deterministic Ed25519 over §5.4.5 prehashed preimage from a caller 32B seed) + outletStreamComputeCredit/CancelPreimage (WebCrypto seam, #1980). BrowserInvokerStreamSession (bindings/typescript-wasm/src/outlet-stream-session.ts) signs open/credit/cancel in-tab, MLS-decrypts + on-device chunk-verify, §5.4.5 seq enforcement.

**Preimages SOUND** (scp-protocol/src/context/outlets/stream.rs):
- CREDIT-V1: domain || lp(ctx) || lp(outlet) || rid(16) || grant_be(4) || monotonic_seq_be(8) || stream_epoch_be(8) || binding(32). stream_epoch is NOT a wire field of OutletStreamCredit — only in the signed preimage; node re-derives pinned epoch (§6.2.1.1e) → verify takes epoch as separate param. Correct (not attacker-supplied on wire).
- CANCEL-V1: domain || lp(ctx) || lp(outlet) || rid(16) || next_seq_be(8) || binding(32).
- Distinct domains (all colon-terminated, prefix-free) + different field layouts → no credit/cancel/chunk cross-type collision. len-prefix on variable ctx/outlet; fixed-width BE for u64/u32; rid/binding fixed 16/32.

**I INDEPENDENTLY reproduced in Python (pynacl)**: operatorPk=d75a9801… (§25.2 TV1), invokerPk=3d4017c3… (TV2), caveatsBinding=76ce5a4f… byte-exact, chunk-0 operator sig byte-exact (proves JCS `{"@type":"data","value":0}` + len-prefix + endianness + domain all correct). Credit/cancel preimages reproduced against spec text.

**Seed handling SOUND**: signing_key_from_seed zeroizes Vec + [u8;32]; SigningKey is ZeroizeOnDrop (workspace ed25519-dalek v2 has `zeroize` feature — Cargo.toml:43). TS Uint8Array seed persists across grants by design (session-lifetime on-device key); wasm copy zeroized. Key-in-tab as-built honestly documented per ADR-057 Slice-3 caveat.

**Seq/gap NOT tautological**: gap key = authenticated chunk.sequence (operator-signed, transport-variable) vs local #expectedSequence cursor. Correct per lesson-gap-detector-key-must-exhibit-the-gap. 6131 fires on non-contiguous; 6110 on sig-fail (verify happens at ingest BEFORE gap check). next_seq=0 = nothing consumed.

**KAT guard REAL**: out048_ts_invoker_fixture_kat.rs re-derives every fixture byte from primitives + §25.2 key, assert_eq pins fixture; #[test] not ignored; RAN + passes. 15 lib tests pass.

## FINDINGS
- MEDIUM (conformance + scar-tissue): gap path (session next() ~line 353-366) sets #closed + throws 6131 but does NOT route a signed OutletCancel, despite §5.4.5:515 "cancels via the signed OutletCancel path AND surfaces StreamGap". Inline comment CLAIMS "best-effort cancel through the signed path" — FALSE. Node-side stream/escrow dangles until timeout.
- MEDIUM (coverage): no TS test exercises the 6131 gap path (untested §5.4.5 MUST).
- LOW (phantom ref): comments "mirrors the native `outlet_stream_sign_credit`" / "same wire form native bridges accept" — NO native sign_credit/sign_cancel FFI exists (grep empty across pyo3/uniffi/napi); native credit-signing is runtime-internal via KeyCustody; no runtime path deserializes the JSON credit/cancel wire yet (transport out of scope).
- INFO: credit/cancel have no committed cross-target GOLDEN (unlike chunks) — coverage = native roundtrip + TS WebCrypto self-verify + my Python repro. streamEpoch fixture field is an input scalar (unpinned by native guard, acceptable). monotonic_seq increments before await → failed delivery skips a seq value (benign, strictly-increasing OK). Browser cancel binds receiver-cursor #expectedSequence not node emission cursor — sound (node cross-checks own cursor §5.4.5:547; cancel_ack_seq node-derived; not app-forgeable).
