---
name: project-uniffi-saga-dashmap-ref-already-fixed
description: UniFFI tool_invoke_cross_context_saga DashMap-Ref-across-await hazard was already fixed before export commit d6baa211e landed; a later fix task was a no-op
metadata:
  type: project
---

The "fix DashMap `Ref` held across `tokio::sync::Mutex .await`" task for UniFFI `tool_invoke_cross_context_saga` (crates/scp-ffi/uniffi/src/bridge.rs, fn @~12305) was a NO-OP: the defect was not present in the current code.

**Why:** bug-catcher reviewed the hazard at commit `82e7b1e5e` (memory bug-catcher/uniffi_dashmap_ref_across_await.md describes the `context_handle_registry(&bi).get(...)` Ref-across-await shape). But by the time the export landed as `d6baa211e` (HEAD parent on branch feat/116-ffi-saga-export; enforcement = `12bf4ae0f` on top), the executor-handler snapshot was already authored against the OWNED `target_handle` Arc: `target_handle.tool_handlers.lock().await.get(&id).cloned()` — no DashMap Ref in scope. A code comment in the fn explicitly states "no DashMap `Ref` is held across the `tool_handlers.lock().await`".

**How to apply:** Before "fixing" a documented latent bug, diff the CURRENT target region against the commit the finding was written against — review memories are pinned to a SHA and the code may have moved. Full audit of every `.await` in the saga fn + its executor closure confirmed zero DashMap guards live across any await (enforce_caller_principal_binding uses `contains_key`→bool, dropped before its own `.await`; resolve_uniffi_signing_key takes `&ContextHandle`; tool_handlers is a tokio Mutex on the owned Arc; executor closure touches no DashMap). Gates on the unchanged tree: `cargo fmt --all --check` clean, `cargo clippy -p scp-ffi-uniffi --all-targets --features "allow_in_memory_custody testing" -- -D warnings` = exit 0, all 4 `xctx_saga` tests pass (incl. the Committed-reaching authenticated-caller test). Nothing committed. See [[feedback-read-tool-stale-verify-with-awk]].
