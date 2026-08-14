---
name: sdk-coverage-broadcast-open-key-gap
description: CRITICAL — fail-closed SDK coverage gate (scripts/check-sdk-coverage.py) breaks on Messaging/broadcast_open_key; missing ALIASES entry makes CI red on branch fix/sdk-coverage-fail-closed-and-parity (HEAD d70c3c272)
metadata:
  type: project
---

# SDK coverage gate: broadcast_open_key missing ALIASES entry (CRITICAL)

Branch `fix/sdk-coverage-fail-closed-and-parity` made `scripts/check-sdk-coverage.py`
fail-closed: `_check_operation_in_sdk` now only checks ALIASES + domain-prefixed
auto-candidates (`messagingBroadcastOpenKey`, etc.). Bare-name/suffix matching removed.

**Bug:** `Messaging/broadcast_open_key` is marked `true` for all 4 SDKs in
`sdk-capability-matrix.json`. Real symbol is `broadcast_open_key` (Py) /
`broadcastOpenKey` (TS/Kotlin/Swift). Every sibling broadcast op (broadcast_subscribe,
broadcast_publish, …) has an ALIASES entry (lines ~455-496) but `broadcast_open_key`
was MISSED. Domain-prefixed candidate `messagingBroadcastOpenKey` never matches the
real bare symbol → gate exits 1 for all 4 SDKs.

**Impact:** CI is RED. `.github/workflows/ci.yml` runs BOTH
`pytest scripts/test_check_sdk_coverage.py` (Test 1 `test_gate_passes_on_real_matrix`
fails) AND `python3.12 scripts/check-sdk-coverage.py` (exit 1). The branch's OWN
self-test asserts the gate passes on the real matrix — it doesn't.

**Fix:** add to ALIASES:
```python
("Messaging", "broadcast_open_key"): {
    "python": ["broadcast_open_key"],
    "typescript": ["broadcastOpenKey"],
    "kotlin": ["broadcastOpenKey"],
    "swift": ["broadcastOpenKey"],
},
```
Verified: injecting this alias → gate EXIT 0, all 4 SDKs match.

**Lesson (recurring):** when making a name-matcher fail-closed (removing fuzzy
matching), enumerate EVERY matrix row that previously relied on the fuzzy path and
add an explicit alias. A bulk-removal of matching strategies is the same failure class
as bulk type/field conversions: grep ALL affected rows. Here, exactly one row
(broadcast_open_key) of the broadcast family was missed.

Everything else on the branch was clean: PERM-3030 re-raise correctly anchored BEFORE
UCAN classification in both trust.py (line 770) and trust.ts (line 461); both 3030
tests genuinely exercise re-raise (Python mock UcanError is a real Exception subclass +
_mock_name seam). test-guard freeze reads env at module load (Object.hasOwn vs proto
pollution). discovery.py TypedDict + economy.py types are pure type defs. Gate
predicate logic (missing-key, all-exempted guard, cell-value else-branch) is sound and
self-tests are mutation-robust.
