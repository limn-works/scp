---
name: adr049-d7-pr3-transport-final
description: ADR-049 Decision-7 PR-3 (ContextTransportProvider + RelayPersistence async — the LAST block_in_place-deletion PR) @140786f56 — APPROVED, Decision-7 architecturally complete
metadata:
  type: project
---

# ADR-049 Decision-7 PR-3 (transport traits async) @ 140786f56 — APPROVED

Branch `chore/adr049-d7-transport` (tip 140786f56) vs origin/main b9ea04f72. Final of the 4-PR Decision-7 family (PR-0 RecoveryBackend, PR-1 ContextPersistence, PR-2 EventLog, PR-3 transport). See [[adr049-d7-async-trait-send-template]] / [[adr049-d7-async-provider-send-discipline]] / [[adr049-d7-pr2-classs-discharge-guard]].

**Converts** `ContextTransportProvider` + `RelayPersistence` to `#[async_trait]` (plain, Send — both are `Arc<dyn>` in ActorDeps moved into `tokio::spawn`, per ADR §165). Deletes the RelayTransportProvider sync→async bridge (provider.rs: 2 block_in_place + 2 block_on + the `require_multi_thread_runtime` probe) and the 6 StorageRelayPersistence bridges (relay_persistence.rs: 6 bip + 6 block_on). Ratchet scp-transport 16→0. **scp-transport now has ZERO block_in_place/block_on live sites** (verified: remaining string matches are comments + quic/test_support). This is the LAST block-in-place-deletion PR of Decision 7.

**Q1 `Arc<Mutex<A>>`→`Arc<A>` = RIGHT.** Every `TransportAdapter` method takes `&self`; `A: Send+Sync+'static` bound already on the struct + trait, all adapters satisfy. The Mutex existed ONLY to bridge the old sync surface and was forcing `!Send` guards (the exact anti-pattern Decision 7 removes) — also drops the `unwrap_or_else(PoisonError::into_inner)` cruft. Side note: it DID accidentally serialize sends; `Arc<A>` now allows concurrent sends, which is the CORRECT model (`&self` send is designed concurrent) — improvement not regression.

**Q2 interleaved-async hoisting = consistent w/ PR-2 MemberLeft precedent + STRENGTHENS discipline.** Transport broadcasts (`try_broadcast_commit_or_enqueue`) that were INSIDE sync `commit_class_s_keep` closures are hoisted AFTER the fail-closed persist (transport is async, can't `.await` in sync closure). Persist-before-observable-side-effect is the correct direction: Class-S (membership removal, nonce burns) fail-closed-persisted BEFORE the broadcast. execute_remove_member captures `Some(commit_bytes)` on success / `None` on fail-close paths (skips broadcast+drain, matches pre-hoist early returns). send_message: fail-closed nonce persist (`commit_send_nonce_token_on_abort`) still runs BEFORE Class-C reversals on transport failure — ordering byte-identical. NARROW note: `pending_commits` retry-entry moves atomic-with-ClassS → Class-C coalesced tick; but pending_commits IS Class-C (best-effort retry backstop, immediate send already attempted) — matches blessed precedent, not a regression.

**Q3 is_connected stays sync = CORRECT** per ADR §161/§163 carve-out (reads AtomicBool, no I/O). Trait is "partial-async" like ContextEventLogProvider (PR-2).

**Q4 ratchet + goal.** Bookkeeping (_updated/_context/_breakdown) accurate. Gate passes. Decision-7 goal (current_thread-viable) ACHIEVED: `require_multi_thread_runtime` probe deleted, provider tests flipped `#[tokio::test(flavor="multi_thread")]`→plain `#[tokio::test]`. Remaining counted sites are ALL sanctioned FFI-sync-boundary exceptions: scp-node HTTP/3 (1), scp-runtime lifecycle_helpers flush pair (2) + trust.rs TrustProtocolRepository (6, the wasm carve-out). scp-runtime aggregate summary 14≠counted 8 = pre-existing tools_helpers_legacy slack (per-file enforcement → harmless, documented).

**Q5 family consistency = CONSISTENT.** Send-vs-?Send per ADR §165: transport+relay=Send (spawned); RecoveryBackend sole ?Send. Sync-prelude `impl Future+Send+use<'d,'c,...>` pattern replicated verbatim in `send_checkpoint`/`send_heartbeat` (state absent from `use<>`, PR-1 template). `&mut ClassSCell` held-across-await combinator (handle_send_heartbeat, +clippy needless_pass_by_ref_mut allow) matches ADR §165.

**BONUS (positive):** relay_persistence.rs block_in_place had NO multi-thread-flavor guard (unlike provider.rs) → on current_thread runtime the relay persist path would PANIC. This PR removes that latent panic.

**Compile verified:** `cargo check -p scp-transport -p scp-runtime --all-targets --features scp-runtime/testing` = exit 0.

**FALSE-ALARM LESSON (cost ~6 build cycles):** `DemoTransport` @ network_simulation.rs:1004 has an UNconverted sync `ContextTransportProvider` impl → looked like a completeness/compile-break gap. It is NOT: the file has `#![cfg(any())]` at line 10 (always-false, entire file gated out pending ADR-049 commit-12 ContextManager rewire; documented). Correctly untouched, doesn't compile, doesn't break CI. **LESSON: before flagging an unconverted trait impl in a `tests/` file as a break, `head` the file for a `#![cfg(...)]` inner attribute. ALSO: incremental `cargo test --no-run` in the scp-wt worktrees does NOT reliably rebuild individual `[[test]]` targets on source edits (fingerprint quirk) — a module-level `compile_error!` did not fire even after `cargo clean -p`; use full clean builds or a minimal repro, don't trust incremental "Finished" for a single test file.**

**VERDICT: APPROVED. Decision-7 architecturally COMPLETE** after PR-3 (modulo documented exceptions: OpenMLS-storage-adapter + FFI sync boundaries [scp-node HTTP/3, lifecycle flush pair] + trust.rs TrustProtocolRepository wasm carve-out). Closes #1940's spirit.
