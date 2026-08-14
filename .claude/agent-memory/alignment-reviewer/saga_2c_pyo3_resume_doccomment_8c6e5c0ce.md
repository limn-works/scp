---
name: saga-2c-pyo3-resume-doccomment-8c6e5c0ce
description: saga-2c §17.16.4/§5.14.13 merge-readiness re-confirm at HEAD 8c6e5c0ce — one doc-only commit atop 54f937e0f fixes stale PyScp::resume doc-comment; ALIGNED, ship, zero findings
metadata:
  type: project
---

# saga-2c merge-ready re-confirm @ 8c6e5c0ce (2026-06-24) — ALIGNED, ship, ZERO findings

Worktree saga-2c, HEAD `8c6e5c0ce`. Single new commit atop the prior FINAL-pass [[saga-2c-final-comment-accuracy-54f937e0f]] (which was ALIGNED zero). `git diff 54f937e0f..8c6e5c0ce` = ONE file, 6 lines: `crates/scp-ffi/src/scp.rs` PyScp::resume doc-comment.

**The fix (doc-only, correctness):** old doc-comment claimed "the caller must re-establish the relay connection explicitly — resume does not reconnect automatically." That CONTRADICTED behavior. VERIFIED:
- `PyScp::resume` (scp.rs:262) block_on's `BridgeInstanceCore::resume(&*inner)` trait default.
- Trait default body (bridge_instance.rs:2544-2547): `core().resume().await?` (flag flip) → `reconnect_transport_if_pending().await?` → `restore_all_persisted_contexts().await`. So resume DOES reconnect + restore automatically.
- Inherent `CoreFields::resume` (bridge_instance.rs:1144) is flag-flip-only (`.await`-free), doc accurate + UNCHANGED — commit message's claim that the inherent + trait-default docs are "already accurate and unchanged" is TRUE.

**Parity confirmed (no stale straggler left):**
- NAPI wrapper (napi/src/scp.rs:300-304) + UniFFI wrapper (uniffi/src/scp.rs) already describe reconnect-automatic; new PyO3 text now matches near-verbatim (+1 sentence on no-explicit-reconnect).
- Python SDK wrapper (bindings/python/scp_sdk/scp.py:385) already correct ("automatically reconnects ... callers no longer need to re-invoke connect_relay"). The PyO3 bridge doc-comment was the LONE straggler still lying; now consistent with the SDK above it and the sibling bridges beside it.
- Whole-tree grep for "must reconnect / does not reconnect / re-establish ... resume" → only two test-assertion strings affirming the CORRECT behavior (relay URLs survive resume so reconnect works), not contradictions.

**Whole feature (`origin/main...8c6e5c0ce`) unchanged from 54f937e0f review** — still §17.16.4 restore-then-replay + §5.14.13 broadcast handshake; RestoredContexts witness token, §6.2.4/§17.16.4 lockstep, ADR-049 note, additive error codes, broadcast hosting_handshake.rs all as previously cleared. No scope creep — the new commit touches nothing but the one doc-comment.

LESSON: a doc-comment "this op does NOT do X automatically; caller must do X" is a high-value bug class when X actually IS done by a trait default body the local impl delegates to — verify by reading the delegated default, not just the local method. Confirm the corrected text matches the SDK wrapper one layer up AND the sibling bridges; a lone uncorrected bridge doc-comment is a real (if low-severity) misalignment in a system whose tenet is "self-evident, one happy path" APIs.

PRE-EXISTING (out of scope, untouched by this feature): Python SDK `scp.py:388/400` resume docstring embeds inline issue refs (#1678, #1549) — contravenes the project's no-issue-refs-in-code rule but predates this work and lives in an unmodified file.
