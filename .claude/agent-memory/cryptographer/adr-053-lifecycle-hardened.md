---
name: adr-053-lifecycle-hardened
description: ADR-053 hardened lifecycle review (HEAD d34097078) — consume handle-invalidation, migration flow ordering, generate() optionality, ucanValidate passthrough all SOUND
metadata:
  type: project
---

# ADR-053 hardened review (branch fix/sdk-coverage-fail-closed-and-parity, HEAD d34097078)

Supersedes the LOW finding in [[adr-051-prerotation-substrate]]: ADR §1 now spells
out the consume handle-lifecycle invariant my earlier review asked for.

## 1. Handle invalidation contract — SOUND
ADR-053 line 49: "CallbackPreRotationCustody adapter MUST invalidate the handle in
Rust immediately after consume returns — whether the callback succeeded or failed."
Matches the Rust trait `PreRotationCustody::destroy_after_migration` (scp-platform
traits.rs ~786) which takes `handle` BY VALUE and docs "subsequent calls with same
handle MUST return HandleNotFound." ADR `consume` == trait `destroy_after_migration`;
`public_key` == `reveal_public_key`. Adapter-level Rust enforcement (not foreign-impl
trust) closes the duplicated-handle / leaked-backstop attack. The by-value Rust
signature already makes the handle un-reusable structurally; the adapter caveat covers
the FFI marshalling layer where the foreign side could retain a copy of the opaque id.

## 2. Canonical migration flow — SOUND ordering, atomicity is best-effort
ADR line 51: consume(handle)→Zeroizing seed→KeyCustody::import_seed_bytes(seed)→
fresh pre-rotation generate. Ordering correct: handle invalidated in Rust BEFORE
operational import begins. NOTE: this is a multi-step bridge sequence, NOT a single
atomic transaction. If import_seed_bytes fails AFTER consume, the revealed seed is in
a Zeroizing wrapper (wiped on drop) and the OLD pre-rotation handle is already dead —
recovery is the existing partial-publish recovery handle (§9.7.4.1, ADR-003). That is
the correct backstop; do not demand DB-style atomicity across an FFI/keystore boundary.
The Zeroizing wrapper is the load-bearing safety property between consume and import.

## 3. generate() optionality for import-only backends — SAFE
ADR line 46: import-only backends (BIP39 restore, offline backup) MUST return a TYPED
ERROR from generate() and SDK offers from_mnemonic()/from_backup(). This does NOT
create a "claims to generate but imports weak seed" path: generate() and
import_seed_bytes() are DISTINCT methods. A backend cannot silently substitute import
for generate — generate() either mints in-substrate CSPRNG or hard-errors. Weak-seed
risk lives entirely in the import path, which is explicit and caller-chosen (the user
supplied the mnemonic/backup). Entropy of an imported seed is the user's backup quality,
not a substitution attack. SOUND.

## 4. ucanValidate raw-error passthrough — does NOT affect trust soundness
scp.ts:2372 ucanValidate deliberately skips mapBridgeError; trust.ts:445 evaluateTrust
classifies raw error. Verified mapBridgeError (errors.ts:265) COPIES error.message into
a new re-typed ScpError(extends Error). So message-prefix regex would still match post-
wrap; the real reason for passthrough is OBJECT IDENTITY + class for the PERM-3030
re-raise contract (trust.ts:461 throws the original error object). Classification is
fail-closed: unknown prefix → throw; [SCP-PERM-3030] → re-raise (caller misuse, not a
trust signal); recognized UCAN prefix → __PASSED_BEFORE stage-ordering, all-later-stages
false. No path leaves a CapabilityValidation field true on real failure. No key/secret
in messages. Crypto verdict: trust verification soundness UNAFFECTED. eventLogQuery has
the identical pattern ([SCP-CTX-] swallow-to-null) — also sound.

VERDICT: ADR-053 cryptographically SOUND as updated. Remaining items are the 3 ADR
"Open questions" (WASM scope, v1 backend floor, spec sub-clause) — design/scope, not
crypto defects.
