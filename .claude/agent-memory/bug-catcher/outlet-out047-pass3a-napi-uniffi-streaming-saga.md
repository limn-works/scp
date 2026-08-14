---
name: outlet-out047-pass3a-napi-uniffi-streaming-saga
description: SCP-OUT-047 pass-3a NAPI+UniFFI streaming-saga FFI (open/poll/recover) review @fd33fadf2 — mostly clean mirror of PyO3; 1 MEDIUM active-state parity gap
metadata:
  type: project
---

SCP-OUT-047 pass 3a (branch feat/outlet-xctx-047-streaming-saga-ffi @fd33fadf2): NAPI+UniFFI streaming-saga exports mirroring PyO3 reference, shared driver scp_ffi_common::streaming_saga.

**MEDIUM (only real finding) — behavioral drift: UniFFI streaming-saga open omits the context active-state guard that NAPI streaming + BOTH bridges' UNARY sagas enforce.**
- NAPI `outlet_streaming_saga_open_on` (napi/src/outlet_stream.rs:1150-1163) rejects non-active source/target → OUTLET_6010/6011, "parity with the unary saga export" (napi/src/outlets.rs:611-630).
- UniFFI unary saga (uniffi/src/bridge.rs:13419-13442) checks `matches!(*source_handle.state.lock().await, ContextState::Active)` for both handles.
- UniFFI `outlet_streaming_saga_open_impl` (uniffi/src/outlet_stream.rs:747-786) has NO state check — goes straight from context_id clones to validate_context_id/validate_did. PyO3 streaming also omits it.
- Money-moving op: a Closing/Expired context (member+UCAN may still resolve) can open a new streaming-saga invocation via UniFFI but is blocked via NAPI. 3-way drift for the same op — exactly what the shared-driver "cannot drift" goal targets. Fix: add the two-handle active-state check to UniFFI streaming open mirroring bridge.rs:13419-13442 (and ideally PyO3 too).

**Verified CLEAN otherwise:**
- Async promptness: NAPI/UniFFI `.await` the single start_cross_context_streaming_outlet_invocation_saga (returns at Commit, seal spawned by runtime); UniFFI spawns impl on crate::runtime() + awaits JoinHandle; NAPI Box::pin().await on napi tokio rt. No block_on-in-async, no nested runtime. NAPI with_context/state() are sync (no await inside).
- Concurrency: no DashMap Ref / lock held across .await anywhere. poll_next clones receiver Arc out of shard guard before recv().await. recover clones entry fields out of guard. UniFFI resolve_context_active_signing_key_by_id clones custody Arc+KeyHandle out of registry ref before export().await.
- Security gates identical to PyO3: caller-principal binding before state read; recover 2-gate (hosted identity THEN invoker==pinned, PERM_3001), non-invoker rejected BEFORE key resolve, entry left intact (test asserts). caller_not_invoker_err = PERM_3001 all 3 bridges.
- poll_next None(abnormal-drop)/terminal(Some+evict)/unknown(distinct CTX_2001 err) identical. NAPI Option<Buffer> via Buffer::from correct.
- UniffiKeyCustody::export_ed25519_signing_key: enum dispatch exhaustive both feature configs (InMemory cfg'd, Callback always); both backends have the method (mirrors resolve_uniffi_signing_key).
- Feature-gating VERIFIED by isolated cargo: UniFFI clippy -D warnings clean lib+all-targets both feature states; NAPI clean --lib no-feat and --all-targets WITH feat. Test seam gated #[cfg(any(test,testing,allow_in_memory_custody))]; saga tests mod gated on allow_in_memory_custody.
- Enforcement STRENGTHENED: bridge-aliases.json filled uniffi/napi arrays + removed 6 exemptions; MIN_PARITY 106→109.

**Pre-existing (NOT introduced), informational:** `cargo clippy -p scp-ffi-napi --all-targets` (NO feature) is RED on unused imports in napi/src/identity.rs:56 (scp_dht::InMemoryDhtClient) + scpid.rs:240 (DidCache, NoOpRelayQuerier) — both #[cfg(test)] mods, untouched by this diff. Separate from the commit's cited scp-testing relay/node base-break. Becomes clean with the feature on.
