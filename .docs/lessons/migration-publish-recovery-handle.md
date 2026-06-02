# Multi-step operations that consume irreversible state mid-pipeline MUST surface a typed recovery handle

## Principle

Any multi-step operation that mutates external, irreversible state (cold-storage custody, on-chain commits, KMS-rotated material, third-party tokens) between fallible steps MUST NOT return a bare `Err` when a later step fails. Returning bare `Err` strands the caller: the irreversible mutation has already happened, the caller cannot retry the whole operation, and they have no path forward.

The function MUST instead return a typed recovery handle that:

1. Identifies WHICH step failed (the phase).
2. Carries the byte-identical artifacts later steps need (post-consumption-point inputs, signed proofs, derived keys).
3. Pairs with a separately-named resume entry point that picks up exactly where the failure occurred.

Bare `Err` is acceptable ONLY when every step before the failure is fully reversible.

## What the lesson is about

`DidDht::migrate_identity` performs eight steps. Step 5 (`destroy_after_migration`) consumes the OLD pre-rotation private bytes from cold custody — the operation is irreversible by design (spec §9.7.4.1 §6 "post-rotation key cycling"). Step 7 (publish NEW DID document) and step 8 (republish OLD document with `alsoKnownAs`) BOTH happen AFTER step 5. If either publish fails, the caller cannot retry: step 1 would fail at `reveal_public_key` against a missing handle.

The original code returned `IdentityError::DhtPublishFailed(...)` for both publish failures — the caller had no recovery handle. The fix introduces:

- `MigrationResumePhase` — an enum identifying which publish step failed.
- `MigrationPartialState` — a recovery handle carrying `(new_identity, new_document, rotation_event, new_pre_rotation_handle, old_identity, old_document)`.
- `IdentityError::MigrationPublishFailed { phase, partial: Box<MigrationPartialState>, source: Box<IdentityError> }` — the typed error variant.
- `DidDht::resume_migration_publish(state, key_custody)` — the resume entry point.

## Why "Why" matters

The lesson is general but its weight is load-bearing in three specific contexts of this codebase:

- **Per-SDK idiom (ADR-048 §7).** The structured recovery handle on the Rust core can be surfaced through each language SDK's most natural error envelope (Swift `Result.failure(.migrationPublishFailed(partial:))`, Python `MigrationPublishFailed` subclass with `partial` attribute, etc.). The point of the typed handle is to enable idiomatic per-SDK plumbing — NOT to dictate that all SDKs surface the same shape. The Rust core's job is to make the data carriable; the SDKs decide presentation.
- **Byte parity (spec §9.7.4.1).** A resume call MUST republish byte-identical artifacts. Re-deriving keys or re-signing proofs at resume time creates "parity drift" — the second-pass publish would carry a different `revealed_key` than the first-pass commitment, and `verify_migration`'s STRONG-assurance invariant (8) would reject the migration. The partial state is the byte-identical artifact set; tests MUST assert `SHA-256(revealed_key) == commitment` before and after resume. (ADR-046 governs *cross-bridge* byte parity — the seed concatenation order and ephemeral RNG window — which is a sibling concern: ADR-046 ensures that two SDKs running on the same seed bytes produce the same identity. Spec §9.7.4.1 ensures that a single SDK's resume produces byte-identical artifacts to its first-pass attempt.)
- **Spec authority.** The recovery handle is documented in `.docs/specs/09-security-model.md` §9.7.4.1 "Partial-publish recovery". Code without spec coverage is phantom provenance — the lesson here is that this kind of structural error decision belongs in the spec as much as the byte-format decisions do.

## Common failure modes

- **Returning a generic catch-all error.** `DhtPublishFailed(String)` is structurally equivalent to a panic message: the caller can read it but cannot act on it. Always introduce a typed variant when a structured caller response is needed.
- **Putting the resume logic inline behind a retry loop.** "Just retry on transient failure" works for steps BEFORE the irreversible mutation. It does not work once cold-custody state has been consumed.
- **Re-deriving instead of carrying.** "We can just regenerate the new_pre_rotation_handle on resume" is wrong: the handle was registered in cold custody at step 4 and is referenced by the published OLD-document commitment hash. Regenerating produces a new handle whose hash does not match the published commitment. Carry the original.
- **Forgetting OLD `#0` retention.** Step 7b destroys OLD `#active` and `#agent` but MUST retain OLD `#0` — step 8 needs it to sign the BEP44 publish of the OLD document. Resume documentation MUST surface this retention contract.

## Tests

The fix added 7 tests covering:

1. step-7 failure surfaces `MigrationPublishFailed { PublishNew, .. }` with full partial state (including `SHA-256(revealed_key) == commitment` invariant).
2. step-8 failure surfaces `MigrationPublishFailed { RepublishOldAlsoKnownAs, .. }` with OLD `#active` already destroyed and OLD `#0` retained.
3. resume after step-7 failure performs both publishes in `[new_did, old_did]` order.
4. resume after step-8 failure performs only ONE additional publish.
5. resume is idempotent (BEP44 sequence monotonicity).
6. byte-parity invariant holds before and after resume (`SHA-256(revealed_key) == commitment` byte-for-byte).
7. Failing → Failing resumes return partial state byte-equal to the first failure.

## Cross-references

- `.docs/specs/09-security-model.md` §9.7.4.1 — Partial-publish recovery paragraph (governs the resume byte-parity invariant).
- `.docs/adrs/phase-1.md` §4b — Partial-publish recovery bullet.
- `.docs/adrs/ADR-046-bridge-parity-harness.md` — Cross-bridge byte-parity (seed-window order, ephemeral RNG); the sibling invariant that the resume byte-parity invariant depends on at the seed-source layer.
- `.docs/adrs/ADR-048-scp-multi-instance.md` §7 — Per-SDK idiom (governs how the Rust handle gets plumbed through each bridge).
- `.docs/lessons/per-sdk-idiom-not-cross-language-dogma.md` — Companion lesson on resisting cross-language uniformity pressure.

## Apply this when

You are introducing a new multi-step operation OR auditing an existing one. Map each step's reversibility:

- Reversible (in-memory state, no external mutation): bare `Err` is fine.
- Reversible-with-cost (storage allocations that can be GC'd): document the leak, bare `Err` acceptable.
- Irreversible (cold custody, on-chain, third-party API): typed recovery handle REQUIRED.

If any step in the chain is irreversible and is FOLLOWED by a fallible step, you MUST introduce a recovery handle. The handle is part of the protocol surface — spec it, ADR it, test the byte parity.
