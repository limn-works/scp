---
name: pr2234-broadcast-kea-fail-closed
description: PR #2234 (broadcast KeyEpochAdvance fail-closed + Merkle sort) — ADR-011 convergence doctrine applied outside its domain; native runtime cannot produce a 2nd broadcast author; spec back-filled after code.
metadata:
  type: project
---

Interrogation of PR #2234 @ `432691d70` (`fix/rotate-content-keys-review-followup`).

**Root facts established (re-verify before reuse):**

- **ADR-011 lives in `.docs/adrs/phase-2.md:679`, Status: Decided.** Its amendment DOES state
  the doctrine "a derived record is automatic *and* convergent iff its trigger input is
  convergent" — the PR's citation is literally accurate. BUT the amendment defines the
  convergent stream as **"the MLS-commit-ordered stream."** Spec §05:5 says Broadcast mode has
  **no MLS**. So applying "convergent governance trigger" to a *broadcast* context governance
  action is outside ADR-011's stated domain — an upstream open question resolved downstream.
- **The native runtime has NO author-grant wiring.** Only production `add_author` caller is
  `manager_methods.rs:203` (creator at creation). `execute_add_member` / `execute_change_role`
  in `governance_helpers.rs` never touch `broadcast_context`. The **WASM** bridge DOES wire it
  (`scp-ffi/wasm/src/manager.rs:3902, 3975`). ⇒ native broadcast contexts have exactly one
  author forever; multi-author KEA fan-out, the `.sort_unstable_by(author_did)` determinism
  fix, and the new multi-author tests all cover a state native prod cannot reach.
- **KEA best-effort was never a human decision.** Introduced by agent PRs #2175 (11f62b892)
  and #2218 (19681f4b1) as "same pattern as MemberBlocked." Status quo by imitation ⇒ reversing
  it is legitimate, not an unauthorized reversal.
- **Provenance was constructed backwards.** #2218 cited "Spec §2008 / §2015" — those are *line
  numbers*, not section numbers. This PR repoints them to §5.14.8/§5.14.10 and then ADDS the
  §5.14.8 paragraph that makes the citation true. Spec-documents-code, same file/class as the
  earlier SCP-OUT-031 finding (`05-contexts.md`). This file is a repeat offender.
- **`actor_did` misuse:** governance KEA leaves pass `rotation.author_did` as `actor_did`.
  Correct only on the *unilateral block* path. `AccessRevoked` in the same function shows the
  right shape (governance actor in `actor_did`, subject in payload). ADR-011 "Subject-bearing
  leaf payloads" requires the latter.
- **`authors: HashMap<String, AuthorState>`** (`scp-protocol/src/context/broadcast/mod.rs:592`)
  is the wrong primitive for a Merkle-feeding collection; BTreeMap = determinism by
  construction. Project already has the by-construction pattern (JCS canonical-JSON at
  `export_import.rs:338`) — it chose "remember to sort" here instead.
- **`checkpoint_events_since` is a hand-maintained mirror:** ~73 `append_context_event*` sites
  vs ~53 `checkpoint_events_since_mut()` bumps in `scp-runtime/src`. The whole "two `+= 1`, not
  `+= 2`" reasoning only exists because append and count are decoupled.
- **`bounded_reply_await`:** 60 uses in `supervisor.rs` @ this commit; the 6 raw `rx.await`
  are all in the test module. Invariant holds in prod code but has NO mechanical gate. The
  right fix is a newtype `ReplyRx<T>` (type system), not a grep denylist.
