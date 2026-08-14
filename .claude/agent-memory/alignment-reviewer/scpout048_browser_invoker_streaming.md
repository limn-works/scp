---
name: scpout048-browser-invoker-streaming
description: SCP-OUT-048 (WASM browser-invoker streaming session) @ 4cdc78a89 — ALIGNED; 1 MEDIUM spec-conformance (gap handler skips the §5.4.5:515 signed-cancel, comment falsely claims it does it)
metadata:
  type: project
---

# SCP-OUT-048 browser-invoker streaming @ 4cdc78a89 (feat/outlet-xctx-048-wasm-session, on 81fa0aeeb on 8658f1afe, 2026-08-01) — ALIGNED; 1 MEDIUM

Browser-invoker side of a cross-context streaming saga, strictly inside the ADR-057 scope fence (browser PARTICIPATES/signs, node COORDINATES). Two-commit unit A (wasm free-fns + aliases) / unit B (TS wrappers + matrix rows + session + tests). All 8 ACs met.

## Verified aligned
- **Fence holds (AC1/AC5):** zero scp_runtime dep edge in crates/scp-client-wasm (Cargo.toml/lib.rs mentions are fence-explaining comments only); no saga/pump/escrow/receipt-sign/seal code — grep hits are the "why NOT here" doc block (lib.rs:808-819). Cargo.lock +1 = `zeroize` (wasm-safe workspace dep, inside fence, best-effort seed zeroization).
- **Preimage parity by construction:** wasm sign_credit/sign_cancel/compute_*_preimage DELEGATE to `scp_protocol::context::outlets::stream::{sign_credit_grant,sign_cancel,compute_credit_sig_preimage,compute_cancel_sig_preimage}` (lib.rs:958/1020/1070/1110) — NOT re-implemented. Domains SCP-OUTLET-CREDIT-V1 / -CANCEL-V1 / -CHUNK-SIG-V1 match spec §5.4.5 (05-contexts.md:491/536/469) exactly. Rust KAT out048_ts_invoker_fixture_kat.rs:80 is REAL (#[test], not ignored), pins TS fixture == reference impl.
- **Node-delegation coherent (ADR-057):** BrowserInvokerStreamSession routes open/credit/cancel + pollNext through injected NodeStreamCoordinator port (outlet-stream-session.ts:79-93); in-tab MLS decrypt via client.handleRelayFrame (:419, keys on-device); on-device chunk verify → SCP-OUTLET-6110 (:430/437). Round-trip test drives 10 Data + terminal End against mocked coordinator (AC6/AC7).
- **#1980 forward posture SERVED, not obstructed:** compute_credit_preimage/compute_cancel_preimage are the "#1980-forward WebCrypto seam" — compute 32-byte preimage without touching a private key so an off-wasm signer can sign later. Mirrors 037's compute_caveats_binding pattern. zeroize comment honestly says "Hygiene, not a load-bearing guarantee" citing ADR-057 §Consequences "As-built caveat (Slice 3)". A justified SUPERSET over the literal ACs (which name signing predicates only), aligned with the ADR's deferred migration.

## Artifact-flow: CLEAN (no invariant violation)
- outlet.json edits = path fix bindings/typescript→typescript-wasm (AC6/AC8) + description clarifying @limn-works/scp-ts-wasm two-package split (#2189). These make the story CONSISTENT WITH upstream ADR-057 fence (browser participant surface IS typescript-wasm) — downstream correction, not code reshaping upstream. **ACs NOT weakened** — only target-path renames; substance (signs open, grants credit, decrypts+verifies 10 chunks + terminal, mocked coordinator) byte-identical. This is NOT the 047-AC8 layered-reconciliation pattern (nothing relaxed); a plain path correction.
- sdk-capability-matrix.json: 4 new BrowserParticipant rows (sign_credit/sign_cancel/compute_credit_preimage/compute_cancel_preimage, typescript-wasm:true, others false+exempt) + 047-row note extension. All downstream reflections; check-sdk-coverage.py PASSES 0 errors; aliases resolve to real exported TS-wasm symbols (index.ts:50-55, client.ts:551/588/612/643).
- **No .docs/specs file modified** — §25.2 in the diff is only a KAT provenance note (RFC 8032 §7.1 reference key), not a spec edit. Safest outcome for the invariant.

## MEDIUM finding (code vs spec — fix code, not spec)
outlet-stream-session.ts:353-366 (gap handler): spec §5.4.5:515 (05-contexts.md:515) mandates the invoker-side drain, on a non-contiguous chunk, BOTH "cancels via the signed OutletCancel path AND surfaces StreamGap (SCP-OUTLET-6131)". Code surfaces 6131 (throws) but does NOT route a signed cancel — and the inline comment (:355-356) FALSELY claims "best-effort cancel through the signed path". Economic consequence: node-side executor keeps pumping/billing until credit-stall/timeout instead of being cancelled. Browser session IS the named drain locus (§5.4.5:515 "the invoke() InvocationHandle drain"), so the obligation applies directly. Fix: sign+route an OutletStreamCancel before throwing (or at minimum correct the comment + record the deviation). No spec change — spec is upstream.

## LOW / observations
- No explicit unit test for the 6131 gap path (logic present, untested; a test would have caught the missing cancel).
- cancel() signs next_seq = #expectedSequence (receiver cursor, :306); §5.4.5:547 says next_seq is the RUNTIME's next-to-emit cursor cross-checked node-side. At the pure-predicate layer this is the invoker's claim (AC3 = "over caller-supplied bytes"), authoritatively cross-checked by the node (047); but the browser cursor may LAG the node's, so a legitimate cancel could be node-rejected on mismatch. Worth a note in the session doc.
