---
name: restore-access-ctx2137-1904
description: #1904 RestoreAccess NothingToRestore CTX-2137 cross-bridge parity gap (NAPI/UniFFI miss the arm) + WASM ceiling/read-exclusion divergences
metadata:
  type: project
---

# #1904 RestoreAccess NothingToRestore (CTX-2137) review (commit e4374df28)

Change: WASM RestoreAccess handler gained native's NothingToRestore guard;
CTX_2137 added to error_codes.rs + PyO3 error.rs From<ContextError> + WASM.

**Why:** Native execute_restore_access (governance_helpers.rs ~1054-1072) rejects
no-op restores. WASM previously cleared read-exclusion with no guard.

**How to apply / findings:**

- Guard boolean logic WASM vs native is BYTE-IDENTICAL (is_none_or, .any,
  carve-out `!(read_requested && read_excluded)`). suspended_for is the single
  shared scp-protocol accessor. Guard runs before mutation. Correct.

- **HIGH cross-bridge gap:** commit says "BOTH bridges" but only PyO3 + WASM map
  NothingToRestore→CTX_2137. NAPI (napi/src/error.rs From<ContextError>) and
  UniFFI (uniffi/src/bridge.rs:1078 From<ContextError>) LACK the arm → fall to
  CTX_2001. Both route GovernanceAction::RestoreAccess via
  ExecuteGovernanceAction → dispatch_governance_command → execute_restore_access
  (which returns NothingToRestore) and surface the inner error via
  `.map_err(ScpNapiError::from)` / `.map_err(ScpError::from)`. So Node-TS +
  Swift/Kotlin get CTX_2001 where Python/browser-TS get CTX_2137. RECURRING
  PATTERN: dedicated-code added to PyO3+WASM but missed in NAPI+UniFFI (same
  "bulk change missing call sites" family). Fix: add `CE::NothingToRestore(_) =>
  ... CTX_2137` arm + parity test to both napi/src/error.rs and
  uniffi/src/bridge.rs From impls.

- **MEDIUM pre-existing (not introduced):** WASM RestoreAccess UNCONDITIONALLY
  calls read_exclusion_list.remove(did) (manager.rs ~4218), but native only
  removes when has_read (messages:read requested). For a non-read real-suspension
  restore on a read-excluded member, WASM wrongly clears the read-exclusion;
  native preserves it. Pre-#1904.

- **LOW pre-existing:** WASM RestoreAccess has NO MemberBan ceiling check; native
  checks ceiling FIRST and returns PermissionDenied. New guard makes WASM return
  CTX_2137 where native returns PermissionDenied (ceiling-missing + no-op).

- Tests: 3 WASM tests non-vacuous + mutation-sensitive. Carve-out test IS
  sensitive to removing `!(read_requested && read_excluded)` (guard would then
  reject). But carve-out test does NOT distinguish WASM unconditional-remove from
  native conditional-remove (read IS requested there). error.rs PyO3 test
  asserts CTX_2137 — non-vacuous. NAPI/UniFFI have NO NothingToRestore test
  (consistent with missing arm).
