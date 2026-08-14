---
name: adr057-t3-convergent-timestamp-aad
description: ADR-057 T3 (#1975) API review — deleting the loose committer-timestamp param by binding it into MLS AAD; APPROVED, textbook misuse-resistance win
metadata:
  type: project
---

ADR-057 T3 / issue #1975 (branch fix/1975-committer-timestamp-auth, HEAD bad06bd42) API-design review. Verdict APPROVED.

**What changed (public surface):** `scp-client::send_message` now returns `Result<Vec<u8>>` (SendOutput struct deleted); `AddMemberOutput.committer_timestamp_secs` field removed; `receive_message` loses its `committer_timestamp_secs` param; wasm `sendMessage`→`Uint8Array` (WasmSendOutput deleted), `receiveMessage(ctx, ciphertext)` two-arg; new `SCP-CRYPTO-4040` error.

**Why it's a strong design:** the old surface forced the embedder to carry a loose `u64` between a send call and every receive call across a network hop — a genuine footgun (wrong/stale/attacker-supplied value forks the §9.9.3 Merkle root). New surface makes misuse impossible *by construction*: the timestamp is bound into the MLS `FramedContent.authenticated_data`, covered by the committer's leaf signature + `PrivateMessage` AEAD tag, and recovered from openmls's *verified* `ProcessedMessage::aad()`. There is no param left to get wrong. Clean deletion — nothing stranded (the timestamp was pure protocol plumbing; embedder never needed it for its own logic). A compile-time fn-pointer signature-pinning test locks the two-arg/return shape.

**Patterns worth reusing:**
- To kill a "carry this loose value between two calls" footgun, bind the value into an authenticated channel (MLS AAD here) and *delete the param, don't validate it*. The best fix removes the seam rather than guarding it.
- Reject-never-clamp for convergent values: clamping an out-of-window timestamp to local clock would diverge each receiver's root; rejection gives all honest receivers an identical verdict. New module `scp-mls/src/convergent_timestamp.rs`, 13-byte AAD `b"SCPT" ‖ ver(1) ‖ u64 BE`, fail-closed decode (missing/malformed/version), plausibility window MAX_FUTURE_SKEW=300s / MAX_AGE=7d (distinct constants mirroring, not sharing, native §9.8.2(c)).
- Browser client (scp-client-wasm) has its own error-code namespace in `error.rs`, NOT the main FFI `scp-ffi/common/src/error_codes.rs`. Codes self-register via the band scheme in sdk-common.md (SCP-CRYPTO- = 4000-4999); `check-error-codes.sh` range-checks + uniqueness. New code just needs to sit in-band + be unique. 4040 arm MUST precede the catch-all `ClientError::Mls(_)`→4010 (tested).

**Minor findings (non-blocking):** (1) `convergent_timestamp.rs:16` module doc has a dangling empty `()` where an issue ref was stripped per no-issue-refs-in-code — renders "committer's ()." in rustdoc, wants cleanup. (2) SCP-CRYPTO-4040 collapses 3 sub-variants (missing/malformed/implausible) to one code; caller distinguishes only via message text — acceptable.

**Alignment observations for other lenses (not API-design blockers):** native `encrypt`/`add_member` left untouched (use signed-envelope created_at, no AAD). So a browser member receiving a NATIVE-authored frame would find no AAD → ConvergentTimestampMissing → reject: native↔browser share the same MLS group only if native also adopts AAD. ADR frames T3 as browser-path only ("shared MLS" = browser cohort for now); worth an inquisitor/alignment check that mixed cohorts aren't required. Also MAX_AGE=7d past bound has no spec §9.8.2 counterpart (spec only states ±5-min future) — ADR-scoped cold-presence tolerance.

**Spec/artifact flow:** ADR updated in the same commit range (good). No spec edit needed — the leaf VALUE (u64 in the Event) is transport-independent so §9.9.3 convergence holds unchanged; §9.16 sender-key AAD is a different layer and untouched.
