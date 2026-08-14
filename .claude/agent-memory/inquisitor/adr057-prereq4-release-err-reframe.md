---
name: adr057-prereq4-release-err-reframe
description: ADR-057 Prereq-4 pass-2 — panic=unwind → --release typed-Err reframe; ADR body honest, categorical over-claim survives in 2 sibling artifacts
metadata:
  type: project
---

ADR-057 Prereq-4 pass-2 verify (#1444, branch fix/adr057-prereq4-release-err-decrypt @d8b281217).

**Why:** pass-1 flagged (a) categorical "the only attacker-reachable panic … is a debug_assert!" over-claim and (b) relay-threat scoping missing. Reframe replaces the wrong panic=unwind premise (infeasible on stable wasm toolchain + unnecessary) with: shipped wasm is `--release`, openmls 0.8.1 decrypt `debug_assert!` (private_message_in.rs:136 "Ciphertext decryption failed") compiled OUT → typed Err → MlsError::DecryptionFailed → [SCP-CRYPTO-4010].

**Verdict:** ADR BODY (governing artifact, lines 49/51/53) RESOLVED + honest on all 4. Item1 evidenced-not-proven correct (compile-out=construction for the debug_assert specifically; "found/evidenced by fuzz_mls_decrypt, pinned to 0.8.1, version-bump-caught-by-nightly" for the no-OTHER-panic claim — does not swing too far, keeps the compile-gate guarantee). Item2 relay-vs-insider scope accurate + genuine distinct threat model (StagedCommit/tree-KEM HPKE reachable only post-AEAD by authenticated member = Prereq-1 insider, out of scope; fuzz doesn't exercise it — honestly disclosed). Item3 --release guard pointer resolves bidirectionally (ADR 53(iii) ↔ PS-09 "Mechanical guards" new entry). Item4 no fuzz-proves-total-panic-freedom implication in ADR.

**RESIDUAL (MED, still-open):** the exact un-hedged categorical pass-1 flagged survives VERBATIM in the two artifacts the ADR points to — root Cargo.toml [profile.release] LOAD-BEARING comment (lines ~124-137, "the only attacker-reachable panic on the openmls 0.8.1 MLS decrypt path is a debug_assert!" + "standing evidence that the release path is panic-free") and PS-09 D6 supersession note ("The only attacker-reachable panic … is a debug_assert!"). ADR 53(i) explicitly calls Cargo.toml "the load-bearing anchor" → a reader following the pointer lands on the un-hedged claim the ADR body took care to hedge. Fix = align both to ADR's "no other release-mode panic has been *found* / evidenced" phrasing.

**How to apply:** the mechanical --release-only build-flag check being a SCHEDULED Slice-3 deliverable is NOT deferral-dressed-as-decision — package @limn-works/scp-ts-wasm doesn't exist yet, placeholder check forbidden, guarantee already holds by construction (debug-assertions=false default+explicit) + pinned by fuzz. Legit sequencing. Same pattern as [[ps09-adr057-ts-packaging]] scheduled guards but well-justified here. fuzz commit 4806eaa39 (guarantee-genuine-tamper guard so AEAD path stays reachable across inputs) = honest engineering.
