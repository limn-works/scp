---
name: plan1733-testing-import-elimination
description: Adversarial review of issue #1733 plan (eliminate scp_platform::testing from prod paths + CI enforcement R1-R5). Enforcement is NOT sound.
metadata:
  type: project
---

# Plan #1733 review (vs origin/main c102f8222) — enforcement unsound

**Context:** plan moves scp-platform `testing/` → `in_memory/`, splits security types behind new `in_memory_custody` feature, severs custody flags from testing chain (fixes did:key ride-in), keeps BridgeDidResolver gate, adds CI script R1-R5.

**SOUND:** shipped artifacts not weakened (did:key rejected in every default `server` build — scp-did/testing OFF; no `*-testing` in any server chain). Commit-2 severing genuinely fixes reported did:key vector + closes scp-runtime forge-leak (runtime Cargo.toml:26-28). #88 restored at platform layer. BridgeDidResolver own-testing keying correct+strictly-stronger for UCAN path. R4 sound for its one pinned line.

**NOT SOUND — attacker w/ ordinary commit access, no enforcement-file edits, trips NO R-rule:**
- F1 MAJOR: R4 pins only `allow_in_memory_custody = [...]` LHS line; does NOT check what pulls it. `server = [..., "allow_in_memory_custody"]` → shipped mobile selects plaintext custody. R5 sees token in allow_in_memory_custody region = pass.
- F2 MAJOR/BLOCKER: R1/R2 ban ONLY token `scp-platform/testing`. The whole `scp-*/testing` family unguarded (scp-core/testing scp-did/testing scp-protocol/testing scp-event-log/testing scp-mls/testing scp-runtime/testing). `server=[...,"scp-core/testing"]` → shipped wheel accepts did:key (3 non-UCAN paths) + arms scpid_sign forge. No rule fires.
- F3 MAJOR: R5 = type-name-token denylist over source text; cannot enforce "no prod SELECTS in-memory" (dataflow prop). Defeated by alias/re-export/wrapper in allowlisted scp-platform/src/in_memory/**, or laundered public ctor (start_node_in_memory pattern). AC2 "R5 is THE security property" false by construction (see ast-gate-checks-definition-not-name-resolution lesson).
- F4 MAJOR: R5 file-granular allowlist gives server.rs + bridge_runtime.rs (BOTH in every shipped artifact's default server/custody set) permanent wholesale pass. Future in-memory selection added there invisible.
- F5 MAJOR: BridgeDidResolver gate (resolvers.rs:83-88) + commit-4 rejection test cover UCAN path ONLY. tree.rs:320 (verify_event_signature), claiming.rs:210/223, attestation.rs:635 (IdentityDidPublicKeyResolver) call scp_did::extract_public_key_from_did DIRECT, no local backstop, no dedicated test. Asymmetric did:key failure if scp-did/testing ever lit.
- F6 MINOR: scp-node dep edge in_memory_custody is crate-wide not "binary-only" (dep feature can't scope to [[bin]]). Matches today, framing wrong.
- F7 MINOR: R5 reuses fragile check-handler-no-panic.sh bash cfg-region tracker as security authority.
- F8 MINOR: scp-identity prod dep `[]` compile-risk; fix MUST be software_platform never in_memory_custody/testing else #88 regresses invisibly.

**Fix:** replace R2 single-token ban with POSITIVE whitelist via `cargo tree -e features` per shipped config asserting scp-did/testing + allow_in_memory_custody OFF (bounded, closes F1+F2). Extend did:key test to event-log/claim/attest paths (F5). Reframe R5 as tripwire not the property. Add scp-identity coder guard.
