---
name: adr057-prereq4-release-anchor
description: ADR-057 Prereq-4 reframe (#1444) from panic=unwind to --release-build fail-closed anchor — honest reframe, 2 residual coherence findings
metadata:
  type: project
---

#1444 rewrote ADR-057 Prereq-4: OLD premise "browser builds panic=unwind so catch_unwind converts openmls decrypt panic→Err" was false BOTH ways (panic=unwind infeasible on stable wasm toolchain — needs nightly + `-Z build-std=std,panic_unwind` + `+exception-handling` + wasm-pack wrapper, VERIFIED .mise.toml rust=stable; AND unnecessary). NEW premise: the sole attacker-reachable panic on openmls 0.8.1 decrypt path is a `debug_assert!(false,"Ciphertext decryption failed")` at private_message_in.rs:136 (VERIFIED — the arm returns `MessageDecryptionError::AeadError`, debug_assert compiled out of release → typed Err → MlsError::DecryptionFailed → [SCP-CRYPTO-4010], mapping VERIFIED scp-client-wasm/src/error.rs:51). catch_unwind demoted to native/debug defense-in-depth.

**Why:** genuine DOA-correction, human-approved 2026-07-16, flows ADR-first (governing tier) then annotates downstream PS-09 D6. Reframe is SOUND + honest; --dev footgun repeatedly disclosed; no over-claim.

**How to apply / residuals to watch:**
- Profile pin `[profile.release] debug-assertions=false` (root + fuzz Cargo.toml) is a documented NO-OP (release default) — comment is honest it changes no behavior, guards only an explicit `=true` override + greppability. NOT false confidence. The REAL footgun (--dev build re-arms the assert) is NOT prevented by the pin, only DOCUMENTED; enforcement DEFERRED to the (nonexistent-yet) scp-ts-wasm packaging slice.
- FINDING (provenance): Prereq-4 forward-refs "a mechanical build-flag check lands with the packaging slice — §Amendment 2026-07-15" but that Amendment section and PS-09's Mechanical-guards section BOTH omit it → deferred --release-only guard is homeless/untracked.
- FINDING (coherence): PS-09 line 73 Sequencing still prescribes "(2) D6 panic=unwind + effective catch_unwind" unannotated (wrong mechanism + a goal the reframe abandons); line 11 header still tags #1444 "panic=unwind LIVE". Supersession note (line 59) only patched the D6 bullet, not the whole file.
- QUESTION: "only panic is the debug_assert" is empirical (fuzz-evidenced via fuzz_mls_decrypt run `-O`, nightly) + version-pinned to openmls 0.8.1, not proven; an openmls bump could add a release panic with no pre-merge gate (nightly fuzz catches post-merge).
