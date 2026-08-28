---
name: custody-selection-surface-scp294
description: SCP-294 custody-naming review — the per-bridge custody-string matrix, the settled ruling that SDK CustodyType members stay pending OQ-9, the IDENT-1003/1008 doc-comment drift, and the Swift/Kotlin provider dead end
metadata:
  type: project
---

Branch `fix/scp-294-custody-name-means-one-thing` made `"platform"` fail closed on all
three bridges and renamed the UniFFI `CustodyMethod::Platform`/`Software` variants to a
single `Callback`, so `Identity.custody_type()` returns `"callback"` on all three bridges.

**Settled by the human — do NOT relitigate:** each SDK's `CustodyType` KEEPS all its
members (deleting them would answer open question OQ-9 downstream), and the
`"file"` vs `"software"` spelling stays with OQ-9. An earlier revision of this branch cut
the members; that was reversed.

**Custody-string → outcome matrix (re-derive from the three parse functions; do not trust
a code comment's parity claim):**

| string | PyO3 | NAPI | UniFFI |
|---|---|---|---|
| `in_memory` (shipped) | IDENT-1008 | IDENT-1008 | IDENT-1008 |
| `file` | FileKeyCustody, then IDENT-1059 | VALID-7005 | VALID-7005 |
| `platform` | IDENT-1003 | IDENT-1003 | IDENT-1003 |
| `software` | VALID-7005 | IDENT-1003 | IDENT-1003 |
| seed + `platform` (shipped) | VALID-7008 | IDENT-1003 | IDENT-1003 |

Only PyO3 enables the `scp-platform` `file` feature (`crates/scp-ffi/Cargo.toml`).

**Input-parameter asymmetry:** Python `CustodyType | str`, TypeScript `CustodyType`, Swift
and Kotlin bare `String`. Kotlin already has a typed overload at
`bindings/kotlin/.../bridge/CoroutineBridge.kt:1513` (`create(custody: CustodyType)`), so
nothing about UniFFI forces `String`. Swift's `CustodyType` has ZERO production call sites.

**Defaults diverge three ways:** Python `identity_create` defaults `CustodyType.FILE`
(writes `$HOME/.scp/keys.bin`), TypeScript defaults `"in_memory"` (always IDENT-1008 on a
shipped build), Swift/Kotlin `SCP.identityCreate` have none, Kotlin
`IdentityAdvancedBridge.createWithAgentKey` defaults `"in_memory"`.

**Output vocabulary is disjoint from input:** `Identity.custody_type()` returns
`in_memory | callback | external`; no SDK `CustodyType` carries `callback` or `external`,
so Kotlin `fromRawValue("callback")` and Swift `CustodyType(rawValue:)` return null/nil.

**Error-code drift:** `crates/scp-ffi/common/src/error_codes.rs` is normative and its header
(lines 36-39) says new purposes get NEW numbers and that drift is caught in review.
`IDENT_1003` reads "Identity already exists", `IDENT_1008` reads "Identity load failed";
both now carry custody meanings on three bridges, and 1008 also means "no agent key to
rotate" at `crates/scp-ffi/napi/src/identity.rs:793`. Free numbers: 1018, 1019, 1029, 1039.
The wire-contract objection to reallocating does not hold, because the same story removed
the `"platform"` alias outright on the grounds that the project is pre-release.

**The Swift/Kotlin dead end (still open):** `AppleKeyCustody`
(`bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:240`) declares
`public final class AppleKeyCustody: Sendable` and adds its methods in a plain
`public extension`, so it does not conform to the UniFFI `KeyCustodyProvider` that
`Scp.swift:758` requires. Kotlin's `AndroidKeyCustody` implements
`works.limn.scp.android.platform.KeyCustodyProvider`, not `uniffi.scp.KeyCustodyProvider`.
Both READMEs now disclose this in prose rather than fixing it.

**How to apply:** when reviewing any custody, error-code, or `CustodyType` change, re-derive
the matrix above from the three parse functions, and check
`.docs/standards/sdk-common.md` — it carries a §SCP-IDENT-1017 cross-bridge-contract
section as the template for exactly this kind of per-bridge code split, and it still has no
custody section. Related: [[cross-sdk-shape-parity]].
