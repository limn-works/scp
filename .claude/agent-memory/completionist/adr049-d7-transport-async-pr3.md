---
name: adr049-d7-transport-async-pr3
description: ADR-049 Decision-7 PR-3 review — transport/relay traits→async; complete in workspace, only non-CI scaffold missed
metadata:
  type: project
---

# ADR-049 Decision-7 PR-3 (ContextTransportProvider + RelayPersistence → async)

Reviewed branch `chore/adr049-d7-transport` tip `140786f56` vs origin/main `b9ea04f72`
(worktree `/Users/alec/Developer/limn/scp-wt-d7-transport`). Verdict INCOMPLETE(narrow).

**Why:** PR is the LAST block-in-place-deletion PR of Decision 7. Prescribed verbatim by
ADR-049-actor-per-context.md §161-165 (traits→`#[async_trait]`, is_connected stays sync,
Send-discipline sync-prelude + `impl Future + Send + use<…>`). Pure mechanical execution,
no ADR update owed.

**How to apply / findings for future passes:**
- Workspace conversion 100%: verified by full `cargo check --workspace --all-targets` with
  all FFI features = exit 0 (definitive frontier proof — every caller awaited, is_connected
  callers unchanged). Ratchet scp-transport 16→0 (provider 4→0, relay_persistence 12→0),
  gate PASSED, no other file silently changed.
- SOLE code gap = `scaffolds/rust-client/src/main.rs:159` sync `impl ContextTransportProvider
  for MockTransport` NOT converted (+ :179 MockEventLog already broken by PR-2's
  ContextEventLogProvider async). scaffolds/rust-client is STANDALONE (own `[workspace]`,
  path-dep scp-core) → NOT built by CI (no scaffolds step in .github/workflows) → silent
  divergence. Recurring scaffolds/templates-miss class (same as ADR-057 T1c
  scaffolds/rust-client + templates/personal-relay, and ContextInner→ArcSwap
  templates/cross-context-bridge). LESSON reconfirmed: on any trait-SIGNATURE change grep
  `scaffolds/ templates/` for out-of-workspace impls — cargo --workspace never catches them.
- Minor: relay_persistence.rs:118 struct doc still says StorageRelayPersistence "using the
  sync-to-async bridge pattern" — stale (module header line 8 updated, struct doc wasn't).
- 7 "pub-crate-visibility" helpers (apply_broadcast_publish, try_broadcast_commit_or_enqueue,
  drain_and_deliver_sender_keys, encrypt_and_send, send_checkpoint, send_heartbeat,
  recovery_send_notification): all PRE-EXISTING `pub` (diff shows only sync→async/lifetime,
  visibility unchanged) → no new SDK/FFI obligation. Not misclassified.
- No scope creep: async conversion + Arc<Mutex>→Arc + ADR-mandated sync-prelude hoisting +
  1 justified needless_pass_by_ref_mut allow + ratchet.
