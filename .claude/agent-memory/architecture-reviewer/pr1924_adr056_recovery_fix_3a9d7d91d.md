---
name: pr1924-adr056-recovery-fix-3a9d7d91d
description: ADR-056 canonical-context-id PR-A rev6 @3a9d7d91d — recovery-direct double-hash fix; APPROVED (2 doc nits). Completeness verified — sole prod raw-primitive site = resolver fallback state.rs:2088.
metadata:
  type: project
---

# ADR-056 PR-A rev6 @ 3a9d7d91d — recovery-direct chokepoint fix — APPROVED (2 LOW doc nits)

ADR-056 NOW EXISTS (the phantom-provenance BLOCKER from rev1 — cited ADR-055 34× while ADR-055 didn't exist — is fully resolved; ADR-056-canonical-context-identity.md is a complete, coherent Accepted ADR dated 2026-06-28). Supersedes [[pr1924-canonical-context-id-prA]].

**Core design (unchanged, re-verified sound):** context identity = 32-byte digest; id string = hex(digest); resolution = decode-not-rehash via single chokepoint `state::context_id_to_bytes` (64-lowercase-hex⇒hex::decode, else SHA-256 fallback). `pub` cross-crate, reached by FFI as `scp_core::context::state::context_id_to_bytes` (facade re-export chain VERIFIED: scp_runtime::context::state pub mod → scp-core/src/lib.rs:91 re-export). builder.rs has a LOCAL wrapper fn `context_id_bytes`@705 that delegates to the chokepoint (NOT the raw primitive — shadows the name, documented).

**HEAD commit = recovery-direct fix.** rev1 BLOCKER #2 (key_destruction.rs straggler) RESOLVED @key_destruction.rs:91 (now chokepoint). This commit closes the LAST straggler of the class: `recovery_send_notification_direct`@supervisor.rs:3559 flipped from raw primitive → chokepoint. The rev1-introduced rationale ("only synthetic identity-private-state reaches here") was FALSE — `RecoverySendNotification` dispatch@3469 has NO registration gate, so seq-1 `revoke_ucans` + seq-2 `rotate_key_packages` compromise-recovery notifications hit it with REAL 64-hex member ids → raw primitive double-hashed → sealed to a slot the registered-actor handler never listens on → silent loss = security fail-open. Now byte-identical to the registered-actor twin `trust_recovery_helpers::recovery_send_notification`@322 (both chokepoint). seq-0 `mls_update` proven safe: `RecoveryAdvanceEpoch` on direct path returns ContextNotRegistered@3448 before any seal.

**COMPLETENESS VERIFIED (the focus question):** enumerated every `scp_protocol::context::context_id_bytes(` call across scp-runtime+scp-ffi+scp-testing. SOLE production raw-primitive call = resolver's own fallback `state.rs:2088`. ALL others are #[cfg(test)] (export_import, provider.rs cfg(test)@2575, agent_binding_pipeline_tests cfg(test)@mod.rs:445, builder.rs:989 in tokio::test, state.rs:2276-2339 in canonical_context_id_tests). No inline Sha256-of-id and no routing_id-misused-as-keying-arg in prod. The recovery-direct path is now architecturally symmetric with the registered-actor handler.

**Enforcement decision SOUND + consistent w/ #1826:** source-text gate implemented-then-removed (regex can't soundly tokenize Rust #[cfg(test)] scope = perpetual fail-open) → replaced by chokepoint + mutation-resistant tests + forthcoming `ContextDigest` newtype (#1931, makes raw keying a COMPILE error). Mirrors OwnedIdentityDid gate dropped for compiler enforcement (#1826). Gate cleanly removed — NO orphan refs in scripts/.github/CLAUDE.md.

**Tests VERIFIED PASS @3a9d7d91d:** new `recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive` (seeds MLS group under DIGEST, drives direct path, asserts TransportFailed not CryptoFailed — right seam, pins keying PROPERTY not trivia) + 6 canonical_context_id_tests + builder digest-keying test. clippy clean on scp-runtime (testing feature). ADR FFI count (4 event-log + 6 test-harness) MATCHES reality.

**2 LOW doc nits (NON-BLOCKING):**
1. supervisor.rs:3453-3466 — `RecoverySendNotification` DISPATCH-SITE block comment NOT touched by this commit; still frames the synthetic pseudo-context as the WHOLE story ("identity-scoped recovery steps... target a synthetic identity-private-state pseudo-context"). The commit corrected the twin comment 40 lines below (on the fn) but left this one stale — same class it just fixed.
2. trust_recovery_helpers.rs:350 — registered-actor handler comment "the raw context_id_bytes used for MLS crypto keying" calls the LOCAL var (chokepoint-resolved digest@322) "raw" — exact stale-comment class the commit fixed in supervisor.rs:3591-3594, left unfixed in the twin.
