---
name: project-adr057-t3-convergent-timestamp-auth
description: ADR-057 T3 (#1975) — authenticate the browser-client convergent committer timestamp via MLS AAD; scp-mls seam facts + scp-client-wasm native-test gotcha
metadata:
  type: project
---

ADR-057 **T3 / #1975**: the browser participant (scp-client / scp-client-wasm) convergent committer timestamp (stamped on mirrored MessageSent/MemberJoined leaves for §9.9.3 log convergence) was a **loose relay-forgeable u64** transported beside the ciphertext; T3 binds it into the MLS `FramedContent` AAD (13-byte `b"SCPT"‖v1‖u64-BE`) so it is covered by the committer leaf-signature + PrivateMessage AEAD and recovered from the *verified* `ProcessedMessage::aad()`. Landed as 2 commits on branch `fix/1975-committer-timestamp-auth` off `2b23a3f31` (NOT pushed).

**Why:** removes the forgery seam that was the named blocker on wiring a real untrusted relay (Slice 3).

**How to apply / non-obvious facts for future work here:**
- `decrypt_with_membership_changes` is the ONLY scp-mls decrypt path that checks the AAD; its sole non-test consumers are scp-client. The **native runtime uses `decrypt_with_sender_did`** (no AAD) — leave `encrypt`/`add_member`/`decrypt_with_sender_did`/MlsBackend untouched when touching this. New paired ops: `encrypt_with_convergent_timestamp` / `add_member_with_convergent_timestamp`.
- Window is **reject-not-clamp** (300s future / 7d age vs injected Clock); clamping would write each receiver's local clock into its leaf and diverge roots. For a Commit the AAD check runs **pre-merge** (after Remove-refusal, before Lifetime bracket) so a rejection leaves the epoch unchanged.
- Distinct error code **SCP-CRYPTO-4040** for the ConvergentTimestamp{Missing,Malformed,Implausible} family (4010/4011/4012 already taken by scp-ffi/common; the wasm crate has its own 40x0 scheme 4010/4020/4030). scp-client-wasm gained a **direct `scp-mls` dep** only to name `MlsError` in the mapping — a plain `use`, NOT `pub use` (the latter trips [[feedback-no-git-checkout-paths]]-style no-shim gate `check-no-shim-reexports.sh`).
- **scp-client-wasm native-host tests ABORT (SIGABRT) on any `Err(JsValue)`** — `JsValue::from_str` can't run off-wasm. Error paths (tampered-wire rejection etc.) are NOT testable natively; cover them at the driver layer (scp-client) + the pure `error_code` unit tests. The strongest surface proof is a **compile-time fn-pointer signature assertion** ("forgery seam gone by construction"). No `wasm-bindgen-test-runner` is wired locally, and `wasm32-unknown-unknown` has no system-time source, so a full-crypto `#[wasm_bindgen_test]` is infeasible.
- **`cargo check -p scp-mls` does NOT run tests or clippy** — the prior agent's "check green" left a latent broken snapshot test (`restored_group_still_encrypts_and_decrypts` used plain `encrypt` + `decrypt_with_membership_changes`) and two `clippy::panic` test-lints. Always run `cargo test` + the all-features `-D warnings` clippy before declaring a scp-mls change done.
