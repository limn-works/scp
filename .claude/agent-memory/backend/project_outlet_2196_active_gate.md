---
name: project-outlet-2196-active-gate
description: GROUP-R #2196 committed (68eeadbd1 + 6089-masking fold-in e5bb3d136, NOT pushed) — runtime ContextState::Active gate on outlet reserve paths + non-retryable error mapping
metadata:
  type: project
---

#2196 GROUP-R landed on branch `fix/outlet-2196-active-gate`: 68eeadbd1 (main
fix) + e5bb3d136 (review fold-in), based on origin/main fa28f925c, NOT pushed —
orchestrator handles review/CI/PR.

**Review fold-in (e5bb3d136):** the SAME error-masking bug also hit SCP-OUTLET-6089
(non-member same-context stream open — the reserve_outlet_stream_economy
membership gate; open_outlet_stream_phase1 does NO membership check first). The
catch-all routed it to CODE_TRANSPORT_FAULT (retryable). Fixed by a guarded arm
(before catch-all) → CaveatPostInputViolation{SLUG_AUTHORIZATION_DENIED} →
CODE_AUTHORIZATION_DENIED (SCP-OUTLET-6110, Never); added SCP_OUTLET_6089_MARKER
const (both producer + reverse-map). Persist-failure path stays retryable
(genuinely transient). Test: non_member_open_maps_to_non_retryable_authorization.
LESSON: when fixing an error-masking catch-all for ONE code, audit EVERY other
permanent error that flows through the same catch-all.

**Third commit (test-only, 1166bdaa2 — SHAs may shift on rebase):** CI caught a
stale test expectation local verification MISSED because I never ran
`cargo test -p scp-ffi` (e2e_bridge tests live there).
`scp-ffi::e2e_bridge::outlet_stream_open_path_wired_and_control_plane_not_found`
(e2e_bridge.rs:~2915) opens a stream as a NON-member and asserted the OLD 6160;
the 6089→6110 fix made it 6110. Only stale one (swept all 3 bridges + bindings).
LESSONS: (1) a runtime error-taxonomy change requires running the FFI-layer test
suites too — the e2e_bridge tests are in crates/scp-ffi/tests, not scp-runtime.
(2) FFI-suite feature invocation: `cargo nextest -p scp-ffi -p scp-ffi-napi
-p scp-ffi-uniffi --features scp-ffi/testing,scp-ffi/outlet-capability-test-grant,
scp-ffi-napi/testing,scp-ffi-napi/outlet-capability-test-grant,
scp-ffi-uniffi/testing,scp-ffi-uniffi/outlet-capability-test-grant` — do NOT add
`scp-runtime/testing`/`scp-core/testing`/`saga-witness-test-mint` to `--features`
when only FFI packages are selected (error: "none of the selected packages
contains these features"); they come TRANSITIVELY via scp-ffi/testing →
scp-core/testing → scp-runtime/testing. CI itself uses `--workspace` which is why
its string includes scp-runtime/*. outlet-capability-test-grant is REQUIRED or
AC6/AC8 e2e tests are silently filtered (0 skipped confirms none filtered).

**Fix:** `fn ensure_context_active(&ContextHandle) -> Result<(), ContextError>` in
outlets_helpers.rs — reads sync `handle.state()` (ArcSwap), returns SCP-OUTLET-6080
via `invocation_error_to_context(InvocationError::ContextNotActive)`. Called as the
FIRST predicate in `reserve_outlet_economy`, `reserve_outlet_stream_economy`,
`reserve_stream_grant_escrow` (all forward-debit). Settle/refund/reconcile helpers
left UNGATED (must run on Closing to unwind money).

**Why:** Only the SESSION path (session.rs) surfaced 6080; stream-open (OUT-037),
unary saga A-leg, streaming saga (OUT-047), and mid-stream grants could debit on a
non-active context. Root-cause runtime gate; per-bridge OUT-047 guards demoted to
defense-in-depth.

**Key facts (non-obvious):**
- TWO `InvocationError` enums exist: scp-protocol `context::outlets::mod.rs`
  (Display "context is not active (current state: X)") AND the RUNTIME
  `scp-runtime context::outlets::invoke.rs:59` (Display "context is not in Active
  state (current: X)"). outlets_helpers + dispatch use the RUNTIME one — assert
  test messages against "not in Active state", not "not active".
- Streaming saga reserve runs on the TARGET (supervisor.rs:6544
  `open_outlet_stream_phase1(&target_hex,...)`), so the runtime gate covers the
  TARGET axis; the CALLER/source axis has NO runtime backstop → bridge caller-axis
  guard (OUTLET_6010) stays PRIMARY. Bridge comments updated to reflect this
  (target=defense-in-depth, caller=primary).
- Error-masking fix: `reserve_error_to_open_rejection` + `open_stream_session`
  invoke_outlet map_err now route permanent failures to non-retryable classes.
  New `OpenStreamRejection::ContextNotActive{current_state}` reuses
  SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM / CODE_PROTOCOL_SESSION (SCP-OUTLET-6101,
  RetryPolicy::Never) — did NOT mint a new code. New helper
  `invocation_error_to_open_rejection` in dispatch.rs.
- 13044 signing failure = `SCP-SAGA-13044` (NOT OUTLET; OUTLET range is 6000-6999).
  check-error-codes.sh enforces ranges on comments too.

**Deferrals cited:** apply_outlet_cancel_verbatim → #2203 (cross-context
browser-initiated cancel). Related: [[project-c7-outlet-stream-ffi-grant-and-test-seams]],
[[project-outlet-streaming-manifest-frontier]], [[feedback-shared-cargo-target-contamination]].
