---
name: adr049-d7-transport-async
description: ADR-049 Decision-7 PR-3 transport-async review (branch chore/adr049-d7-transport @140786f56) — 1 CRITICAL compile break + 1 durability regression
metadata:
  type: project
---

# ADR-049 D7 PR-3: ContextTransportProvider + RelayPersistence → async

Branch `chore/adr049-d7-transport` @140786f56 vs origin/main b9ea04f72.

**#1 sound:** `Arc<Mutex<A>>→Arc<A>` in RelayTransportProvider is safe — `TransportAdapter: Send+Sync`, all methods `&self`; Mutex was redundant serialization, `Sync` bound is the compiler guarantee for concurrent `&self`. Not a data race.

**CRITICAL — missed async impl → workspace test compile break:** `crates/scp-testing/tests/integration/network_simulation.rs:1004` `impl ContextTransportProvider for DemoTransport` still has SYNC `fn publish_context/delete_published/send_message`, no `#[async_trait]` (sibling `DemoEventLog` WAS converted). Trait is now `#[async_trait]` (builder.rs:47). File NOT in diff. It's a registered `[[test]]` (Cargo.toml:195-197, no required-features) → `cargo test -p scp-testing` / `cargo clippy --workspace --all-targets` (the CI cmd) fails E0407/sig-mismatch. Regression: on main trait was sync so it compiled.

**MEDIUM (HIGH consequence) — fail-closed→coalesced durability downgrade:** In `execute_remove_member` + `execute_rotate_content_keys` (governance_helpers.rs), the commit-broadcast enqueue (`try_broadcast_commit_or_enqueue` → sets `pending_commits` retry + `commit_fault` marker on transport-send failure) was HOISTED out of the `commit_class_s_keep` fail-closed persist to AFTER it (transport now async, can't await in sync closure). Now rides Class-C. Actor persist model (actor/mod.rs): commit_class_s_keep = synchronous fail-closed persist; Class-C only flushed on 50ms COALESCE_INTERVAL tick or shutdown drain. So enqueue durable only within ≤50ms. `commit_fault` is a SAFETY GATE (check_commit_fault blocks send path messaging_helpers.rs:913 + lifecycle:242 + governance:5182). Crash after transport-fail + before coalesce tick → both retry AND commit_fault lost → context resumes sends as healthy while existing members stuck on stale MLS epoch (permanent desync, no fault indication). state.rs:198 doc: PendingCommit must "survive process restart." `execute_add_member` was already Class-C best-effort (no change); `execute_reset_member` takes ClassCMut (already best-effort, no change).

**Clean:** relay_persistence.rs (mechanical block_in_place removal, no locks), native/server.rs (cleanup_connection_subscriptions drops write lock before .await:938), send_checkpoint/send_heartbeat (`+Send+use<>` excludes `state`, compiler-enforced, callers await immediately), no dropped must-use futures.
