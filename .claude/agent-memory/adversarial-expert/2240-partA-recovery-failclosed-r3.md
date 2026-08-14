---
name: 2240-partA-recovery-failclosed-r3
description: #2240 Part A execute_recovery fail-closed — round-3 confirming review verdict (comment/docstring residue)
metadata:
  type: project
---

# #2240 Part A recovery fail-closed — round-3 confirm (commit 6ed5c5ff8)

execute_recovery fails closed (no wired backend; Part B = #2240). Ownership gate rejects
DIDs absent from the per-instance registry with SCP-IDENT-1020, uniform byte-identical
message across PyO3/NAPI/UniFFI ("populated only by identity_create* / migrate, never by
identity_load, on every binding").

**Why the round-3 comment is CORRECT (initially looked wrong):** PyO3 comment (identity.rs
~2555) says identity_load "only reads the registry and fails SCP-IDENT-1010 if the DID is
absent." identity_load (line 1516) reads STORAGE first (not-found → IDENT_1001), THEN on a
registry-miss (in storage, absent from runtime registry) emits the **SCP-IDENT-1010** message
(line 1595; also documented at identity_load docstrings 1487/1508). "only reads the registry"
= reads-but-does-not-populate (contrast vs create* which populates). Consistent with the
bridge's own convention. NOTE: line 1595 carries "SCP-IDENT-1010:" as a message-string prefix
while the typed `code` field defaults to IDENT_1001 — pre-existing quirk, not introduced here.
IDENT_1010 catalog doc says "UniFFI identity create error" — stale/overloaded, deferred to
Part B (catalog staleness already flagged in commit msg).

**Deferred to Part B (out of recovery scope, pre-existing):** custody-migration "created or
loaded via identity_create / identity_load" wording exists in BOTH napi/src/scp.rs:1233 AND
bindings/python/scp_sdk/scp.py:778 (identity_execute_custody_migration — a SEPARATE function,
SCP-IDENT-1024 gate). Commit msg named only the napi file; the Python SDK sibling docstring
carries identical wording. Part B should sweep both so they don't drift. NOT a recovery-path
finding.

Verdict: SHIP, zero new findings. Round-2 LOW (overstatement) fully resolved.
