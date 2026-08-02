# `identity_migrate` Cites §9.12 / ADR-003 §4b — Not §3.2.1

**Date:** 2026-06-20
**Source:** branch `fix/sdk-coverage-fail-closed-and-parity` — cross-SDK citation alignment
(Python `scp.py`, TypeScript `scp.ts` / `identity.ts`)

## The Rule

SCP has **two distinct migration operations** in the identity spec. They look similar in
the SDK surface but cite different sections, because they do different things:

| Operation | What it does | Cites |
|-----------|--------------|-------|
| `identity_migrate` (`identityMigrate`) | Creates a **NEW DID** by **revealing the pre-rotation key**; returns a `DidRotationEvent`. This is Identity Key migration. | **§9.12 / ADR-003 §4b** |
| `identity_execute_custody_migration` | Migrates custody (key storage substrate) **WITHOUT changing the DID**. The identity is preserved. | **§3.2.1** (Key Custody Migration Protocol) |

Citing **§3.2.1** for `identity_migrate` is semantically wrong: §3.2.1 is the
DID-preserving custody swap. The new-DID / pre-rotation-reveal path is §9.12.

## Context

The Python SDK's `identity_migrate` doc-comment had been "aligned" to §3.2.1 (and carried
a stray `§3.2.1 step 4b.` trailer that contradicted its own §9.12 body). TypeScript cited
§9.12 correctly. A fresh agent reading the wrong Python citation would chase the
custody-migration section and miss the pre-rotation / new-DID semantics — a phantom
provenance trap.

## The Fix

- Python `scp.py` `identity_migrate` → cites **§9.12, ADR-003 §4b**; the stray §3.2.1
  trailer removed.
- TS `scp.ts` `identityMigrate` and `identity.ts` `rotationEventJson` → cite **§9.12**
  (Identity Key Migration), stating "creates an identity with a NEW DID" / "reveals the
  pre-rotation key."
- `identity_execute_custody_migration` correctly **retains §3.2.1** — the distinction is
  now clean in both directions and consistent across SDKs.

## The Lesson

When reviewing identity-migration provenance:
- The **new-DID / pre-rotation-reveal** call cites **§9.12 (+ ADR-003 §4b)**.
- The **DID-preserving custody swap** cites **§3.2.1**.
- Do not conflate them. Two operations that share a verb ("migrate") are not the same
  operation; verify the citation matches the *behavior* (does the DID change?), not the
  name. Keep the citation identical across all SDK bindings — a divergence is a finding.

Spec anchors: `03-identity.md` §3.2.1 (custody migration, DID preserved) vs
`09-security-model.md` §9.12 + §9.7.4.1 (pre-rotation reveal, new DID).
