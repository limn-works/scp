---
name: scp294-custody-name-one-meaning
description: SCP-294 custody-string fail-closed reviews (2 rounds) — the doc surfaces a custody rename reaches, and the ADR phase files an author's exclusion list keeps missing
metadata:
  type: project
---

Branch `fix/scp-294-custody-name-means-one-thing` (base `5e7e5b4e67`, pull request #2414)
made `"platform"` return `SCP-IDENT-1003` on the PyO3 bridge and replaced
`CustodyMethod::Platform` / `::Software` with `CustodyMethod::Callback` in the UniFFI
bridge. Round 1 verdict INCOMPLETE; round 2 (head `56c6a0e880`) verdict INCOMPLETE again,
on a disjoint set of locations.

**Round 2's headline: an author who hands you an exclusion list has under-scoped it.**
The list named `.docs/architecture.md:915,:985`, `.docs/adrs/phase-4.md:689,:1066,:1068`,
and `ADR-048`. It missed `.docs/adrs/phase-5.md` (3 spots), `.docs/adrs/phase-6.md`
(7 spots, including `custody: String = "platform"` as a signature default and an
acceptance criterion promising a hardware-backed identity), `.docs/architecture.md:1006`
(`custody: .secureEnclave`, three lines from a declared exclusion), and
`.docs/adrs/phase-4.md:802` (a fourth stale spot in a file with three declared). The
story's own `files[]` and `actionItems` named phase-5 and phase-6; the commit edited
neither. **Grep the ADR phase files by name — `phase-1.md` through `phase-6.md` — never
trust a list of line numbers.**

**Surfaces a custody or UniFFI-enum rename reaches (both rounds):**
- `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` is CHECKED IN and generated;
  its Kotlin counterpart under `internal/uniffi/scp/scp.kt` is untracked and self-heals,
  so the Kotlin side reads correct while Swift keeps deleted variants and shifted FFI
  discriminants. Round 2: it was regenerated correctly (`case callback`, discriminants
  1/2/3), so re-verify before reporting it — see
  `.docs/lessons/re-verify-a-finding-your-own-agents-may-have-fixed.md`.
- A live error message can instruct a caller to pass the rejected string
  (`crates/scp-ffi/src/identity.rs` SCP-IDENT-1010).
- Scaffold and template SOURCE files, not just READMEs.
- A NEW test file's own header comment can describe an earlier iteration of the change:
  `CustodyCallErrorCodeTest.kt` says `CustodyType` "carries one entry, IN_MEMORY" while
  `SmokeTest.kt` in the same commit asserts three entries.
- A story's `actionItems` and `acceptanceCriteria` can contradict each other after a
  mid-flight redesign. Read both halves, not one.

**Residual cross-bridge divergence neither round closed:** `"file"` builds a key store on
PyO3 and draws `SCP-VALID-7005` on NAPI/UniFFI; `"software"` draws `SCP-IDENT-1003` on
NAPI/UniFFI and `SCP-VALID-7005` on PyO3. On a shipped PyO3 build `("platform", seed)`
draws `SCP-VALID-7008` where the other two draw `SCP-IDENT-1003`. Spec §3.2 of
`.docs/specs/03-identity.md` names four custody substrates in prose and defines no
create-selector string set, so no upstream artifact settles it — the SDK docs narrate the
divergence instead, which is the "document the residue" deferral CLAUDE.md forbids.

**`CustodyType` wiring differs per SDK** (check all four, never generalise from one):
Python and TypeScript take the enum/union on `identity_create`; Kotlin's public
`SCP.identityCreate` takes a bare `String` while only `CoroutineBridge.IdentityBridge.create`
takes the enum; Swift's `CustodyType` reaches ZERO call sites under
`bindings/swift/Sources/` — only tests and scaffolds use it.

Gates that PASS and therefore prove nothing here: `scripts/check-sdk-coverage.py`,
`scripts/check-pyi-generated.sh`, `scripts/validate-prd.py`. The `.pyi` types custody as
`Any`, so it never carried the vocabulary.

Watch for a dirty working tree: during round 2 other agents edited the branch's files
live while the review ran. Verify every finding with `git show <head>:<path>`, not by
reading the working tree.

See [[adr057_transport_wasm_surface_parity]] for the other shape of this failure: a
surface mirrored on one binding and not the other.
