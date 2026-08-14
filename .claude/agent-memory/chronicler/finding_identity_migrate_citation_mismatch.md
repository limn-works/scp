---
name: finding-identity-migrate-citation-mismatch
description: identity_migrate spec citation is wrong across SDKs — §3.2.1 is Custody Migration (preserves DID); the new-DID/pre-rotation path is §9.12
metadata:
  type: project
---

`identity_migrate` (bridge call, all SDKs) creates a **NEW DID** via the **pre-rotation key** mechanism and returns a `DidRotationEvent`. Per spec `03-identity.md:28`, that is the **Identity Key migration** path = **§9.12 / ADR-003 §4b**.

§3.2.1 ("Key Custody Migration Protocol", `03-identity.md:20`) is the *other* operation: it migrates custody WITHOUT changing identity (`03-identity.md:18`). Citing §3.2.1 for `identity_migrate` is semantically wrong.

RESOLVED on branch `fix/sdk-coverage-fail-closed-and-parity` at HEAD 6f4ba65ff (final-review 2026-06-20):
- Python `scp.py` `identity_migrate` now cites §9.12, ADR-003 §4b (commit ed14e6c77 "fix migrate citations" reverted the wrong 77fbfff4c §3.2.1 alignment; the stray "§3.2.1 step 4b." trailer that contradicted the §9.12 body on main was deleted).
- TS `scp.ts` `identityMigrate` now cites §9.12, ADR-003 §4b and states "creating an identity with a NEW DID" + "reveals the pre-rotation key."
- TS `identity.ts:114` `rotationEventJson` now cites "§9.12 (Identity Key Migration)" — corrected.
- `identity_execute_custody_migration` (scp.py:639) correctly RETAINS §3.2.1 (the DID-preserving custody op) — the distinction is now clean in both directions.
- Stale §9.3 citation (commit 71a8b8c0e) removed; remaining §9.9.3 refs are the catch-up/equivocation section (correct, unrelated).

**Why:** the two migration operations are distinct in the spec; a fresh agent reading the wrong citation will chase the custody-migration section and miss the pre-rotation/new-DID semantics.
**How to apply:** when reviewing identity-migration provenance, the new-DID/pre-rotation call cites §9.12 (+ADR-003 §4b); the DID-preserving custody swap cites §3.2.1. Do not conflate.
