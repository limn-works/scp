---
name: outlet-stream-c7-revision-delta-be7f76acd
description: C7 outlet-streaming revision delta (a6bafe451/665e1838a/be7f76acd atop a96940ecf) — resolves prior GIL-DoS + budget-under-enforcement; 1 MEDIUM (testing seam false "never compiled in prod" claim via allow_in_memory_custody leak chain)
metadata:
  type: project
---

# C7 outlet-streaming revision delta (feat/outlet-streaming-ffi, 3 commits atop a96940ecf) — 2026-07-13

Re-review of the fixes for the prior round ([[outlet-stream-pyo3-bridge-c7-eb75ce608]]).

## RESOLVED — prior GIL-DoS HIGH
poll_next/grant/cancel/terminate now wrap `rt.block_on(...)` in `py.allow_threads(|| ...)`
(outlet_stream.rs). Ungil is COMPILE-TIME enforced by pyo3 — a smuggled `Py`/`Bound` in the
closure return would not compile; all closures return plain Rust (OutletStreamChunk / Result<(),
ScpPyError> / StreamSignerError), none capture Py/Bound. Custody sign + actor mailbox reserve run
inside allow_threads (no Python). Confirmed resolved.

## RESOLVED — prior budget under-enforcement MEDIUM
grant_credit now takes `grant: u32`, signs the OutletStreamCredit INTERNALLY under the pinned
invoker custody key (compute_credit_sig_preimage + resolve_stream_signer, mirroring cancel) and
auto-assigns monotonic_seq via per-StreamEntry `AtomicU64::fetch_add` (SeqCst, first grant=0).
Bridge saga: sign → `Supervisor::outlet_stream_reserve_grant` (DEBIT cost×grant) → apply_credit_grant(reserved)
→ `outlet_stream_reverse_grant` on apply-reject. Debit is inside `reserve_stream_grant_escrow`
(outlets_helpers.rs:1334) via `commit_class_s_keep_compensating`: overflow check (checked_mul) +
insufficient-funds check BEFORE record_spend, all on the SERIAL actor thread → check-and-debit
atomic without external lock. Money conserved: sequential fail→regrant reverses the debit; concurrent
grants serialized on actor mailbox + strictly-increasing `seen_seq` (stream.rs:544, `<=` → CreditReplay)
rejects the losing racer and reverses ITS debit. Debit is NOT atomic with apply (separate saga steps,
handle RwLock vs actor) — but that's the deliberate reference E2 design; escrow only extends AFTER a
successful debit; reverse-on-reject upholds `billed+refund==reserved`. Backstop is still the caveat
ceiling `min(credit_window,max_calls)` (max_billable clamps replenish), NOT billed≤reserved. Budget
cap now genuinely bounds real spend across open+grants. seq gap from a failed grant does NOT wedge
future grants (strictly-greater, not contiguous). Confirmed resolved.

## MEDIUM (NEW) — test_grant_member_capability compiled into allow_in_memory_custody builds despite "never compiled into production" claim
`Supervisor::test_grant_member_capability` + `MessagingCommand::TestGrantMemberCapability` variant +
`handle_test_grant_member_capability` are all `#[cfg(feature="testing")]`. It grants `outlet_call:*`
(OutletCallAll) to an ARBITRARY member via `commit_class_s_keep`, DELIBERATELY bypassing the capability
ceiling + governance role-assignment — an authority-ESCALATION primitive (stronger than TestInstallAccessKey).
The commit msg + doc comment claim "never compiled into production builds." That half is FALSE: `testing`
leaks into every `allow_in_memory_custody` build via `scp-ffi[allow_in_memory_custody] → dep:scp-testing
→ scp-testing normal-dep scp-core{testing} (Cargo.toml:20) → scp-core testing = scp-runtime/testing`.
scp-ffi Cargo.toml's OWN comment admits it: "the `testing` feature is always enabled in deps." This is the
EXACT chain scp-runtime/Cargo.toml:24-31 warns about and created `saga-witness-test-mint` (a dedicated
NON-leaking feature) to dodge. Safe ONLY because the OTHER half of the claim IS true: NO FFI/SDK export
(grep of scp-ffi/src + bindings = only e2e_bridge.rs test calls it); reachable solely by Rust code already
holding `&Supervisor` (full runtime control). So NOT exploitable, NOT a BLOCKER — safety rests entirely on
"no FFI surface," not on "not compiled in prod." Same class as the prior TestInstallAccessKey MEDIUM
([[adr049-2fb-9b-joiner-send]] gate-behind-non-leaking-feature precedent). Fix: gate behind a dedicated
non-leaking feature (saga-witness-test-mint precedent), OR at minimum correct the false "never compiled
into production" claim in docstring + commit.

## Confirmed clean
- terminate: `code` param dropped, derived internally via TerminateReason::from_slug(slug).code();
  from_slug closed-set (unknown→None→reject); caller==invoker via authorized_control. Unforgeable-by-
  construction. Auth still assertion-only (pre-existing LOW, now documented, OK under co-resident model).
- No new panic/unwrap on caller input (grant u32: checked_mul; removed the serde_json grant parse = surface
  reduced; request_id fixed array copy).
- Prod-reachable new supervisor fns (`outlet_stream_reserve_grant`/`_reverse_grant`) fail-closed on no-actor
  (ContextNotRegistered → bridge does NOT apply credit); reverse_spend saturating/infallible; bridge passes
  the authenticated caller_did as member_did + the exact `reserved` amount → no over-refund, no debit-other-
  member via FFI. `_reverse_grant` pub visibility is inherent (cross-crate bridge reach), no new FFI export.
- poll_next unknown-handle now distinct error (not None); terminal-chunk eviction closes the run-to-terminal
  registry leak; unreachable receiver()==None terminates pump to release escrow.
