---
name: saga-2c-final-pass-8c6e5c0ce
description: APPROVED/ship final API confirmation of saga-2c worktree HEAD 8c6e5c0ce — comment-only PyO3 resume doc fix; cross-bridge consistency verified at source
metadata:
  type: project
---

Saga-2c feature final API-design confirmation. Worktree HEAD `8c6e5c0ce` = single comment-only commit ("docs(saga): fix stale PyO3 resume doc-comment"). APPROVED/ship; no merge-blocking API issue in the whole feature.

**What it fixes:** `PyScp::resume` doc in `crates/scp-ffi/src/scp.rs` (lines 250-256) previously claimed "caller must re-establish the relay connection explicitly — resume does not reconnect automatically." That contradicted behavior. Rewritten to describe real reconnect-then-restore.

**Behavior source of truth (verified at code):** `PyScp::resume` (scp.rs:262) calls `BridgeInstanceCore::resume(&*inner).await`; trait default body (`bridge_instance.rs:2544-2549`) runs `core().resume()` (flag flip) → `reconnect_transport_if_pending()` → `restore_all_persisted_contexts()`. ORDER matters: reconnect MUST precede rehydration so restored subscriptions attach to a live relay (documented at bridge_instance.rs:2518-2538). Per-bridge structs MUST NOT override the default (CI gate `scripts/check-bridge-instance-lifecycle.py`).

**Cross-bridge consistency (all describe reconnect-from-pending-URLs + persisted-context restore):**
- NAPI resume doc: napi/src/scp.rs:300-304
- UniFFI resume doc: uniffi/src/scp.rs:112-116
- Python SDK docstring: bindings/python/scp_sdk/scp.py:386-406 ("no longer need to re-invoke connect_relay")
- Inherent `CoreFields::resume` (flag-flip only, cheap, .await-free): bridge_instance.rs:1144 — accurate + unchanged.
PyO3 was the lone stale outlier; this commit aligns it.

**Why:** Final read-only confirmation before ship; the corrected doc removes a misuse hazard (Python caller redundantly re-calling connect_relay).
**How to apply:** Reference design for the bridge resume lifecycle (reconnect-before-rehydrate, no-override + CI-gate). If reviewing future resume/suspend changes, these 5 surfaces must stay in lockstep. No issue numbers leaked into corrected doc text (repo rule). See [[saga_2c_final_api_pass_15c1aef9c]] and [[saga_2c_final_pass_54f937e0f]] for prior passes of this feature.
