---
name: adr049-pr7-rebase-verdict
description: ADR-049 PR-7 atomic crypto-state move — pass-2 rebase re-review verdict + reusable rebase-interdiff verification technique
metadata:
  type: project
---

# ADR-049 PR-7 (SCP-CRYPTOMOVE-001) — pass-2 rebase re-review

Verdict 2026-07-16: SHIP, one non-blocking MEDIUM doc finding. Branch feat/adr049-pr7-atomic-crypto-move @ efdaa6546.

**Why:** Rebase onto 14 main commits. Confirmed sound.
**How to apply:** If asked to re-verify PR-7 rebase soundness, this is done — don't re-run unless the branch moved.

## Reusable technique — prove a rebased patch body is byte-identical
The naive `git diff <old-tag>...<new-head>` sweeps in ALL the rebased-over main commits (looks like 161 files). To isolate the PR's own patch:
- patch_pre = `git diff <merge-base(tag,main)> <tag>`
- patch_post = `git diff <origin/main> <head>`
- Compare file SETS: `comm` on `--name-only` sorted lists.
- Compare BODIES order-normalized: `git diff -U0 ... | grep -vE '^(index|@@|diff --git|--- |\+\+\+ )' | sort` for each, then `diff`. Empty diff = byte-identical patch body (conflict resolution landed on disjoint lines).
PR-7 result: 34 common files, patch body identical (9656 content lines, zero diff); sole net-new file = invoke.rs test flip.

## Verified sound
- Atomic move IS production-wired: `spawn_actor_from_welcome` (supervisor.rs:12686) + lifecycle_helpers.rs:1779 do `take_crypto_state` → `seed_encrypted_crypto_from_owned`, with fail-closed rollback (taken_context_ids marker left in place to block group resurrection; destroy_mls_group defensive no-op).
- Provider seal/open fully DELETED; zero surviving production callers; no `#[ignore]` added anywhere in PR.
- invoke.rs test flip (ac10_seal_for_a_preserves_operator_sig) is genuine/stronger equivalent: 3 security assertions preserved verbatim; routed onto PerContextState::seal/open wrappers that delegate to the PRODUCTION ContextCryptoState::seal (state.rs:1666) — same seam messaging_helpers.rs:252 uses — with faithful aad_sequence reserve/commit + u64::MAX fail-closed guard.
- Two-commit structure clean/revertable: commit1 (3ae4f4a4e) = core, no invoke.rs; commit2 (efdaa6546) = only invoke.rs.

## Finding (MEDIUM, non-blocking, doc) — stale scope comment
provider.rs:300-334 (`OwnedMlsCryptoState` doc, a pub FFI-boundary type) still says "no production site calls take_crypto_state yet" + "legacy seal/open path continues to operate on contexts[ctx_id]". Both FALSE in shipped tree. Comment was accurate on origin/main (authored by #1757); PR-7 deletes provider seal/open + wires the production caller but leaves the comment untouched. Secondary: provider.rs:4084 test-doc references non-existent `provider.open()`. Documentation-provenance defect, not correctness/security. Cheap fix; recommend before or immediately after merge.
