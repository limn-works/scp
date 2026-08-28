---
name: custody-selection-surface-scp294
description: SCP-294 custody-naming review — the custody-string vocabulary per bridge, the IDENT-1003/1008 doc-comment drift, and the Swift/Kotlin dead-end where no shipped KeyCustodyProvider exists
metadata:
  type: project
---

Branch `fix/scp-294-custody-name-means-one-thing` made `"platform"` fail closed on all
three bridges and cut each SDK's `CustodyType` to what its own bridge builds.

**Custody-string → outcome matrix (verify before reusing; it changes):**

| string | PyO3 | NAPI | UniFFI |
|---|---|---|---|
| `in_memory` (shipped build) | IDENT-1008 | IDENT-1008 | IDENT-1008 |
| `file` | FileKeyCustody | VALID-7005 | VALID-7005 |
| `platform` | IDENT-1003 | IDENT-1003 | IDENT-1003 |
| `software` | VALID-7005 | IDENT-1003 | IDENT-1003 |

Only PyO3 enables the `scp-platform` `file` feature (`crates/scp-ffi/Cargo.toml`); the NAPI
and UniFFI Cargo.toml files omit it. Nothing architectural separates them — one Cargo
feature does.

**The dead end:** on Swift and Kotlin a released build reaches no key store from any custody
string, and `identityCreateWithCustody` takes `uniffi.scp.KeyCustodyProvider`, which
`AppleKeyCustody` does not declare conformance to and which Kotlin's `AndroidKeyCustody`
does not implement (it implements `works.limn.scp.android.platform.KeyCustodyProvider`).

**Why:** the doc-comment registry in `crates/scp-ffi/common/src/error_codes.rs` is normative
and its header says review is the only enforcement of purpose drift. `IDENT_1003` reads
"Identity already exists" and `IDENT_1008` reads "Identity load failed"; both carry custody
meanings on three bridges. Free numbers exist at 1018, 1019, 1029, 1039.

**How to apply:** when reviewing any custody, error-code, or `CustodyType` change, re-derive
the matrix above from the three parse functions rather than trusting a code comment's parity
claim — this change's own comments claimed cross-bridge agreement that two strings break.
Related: [[cross-sdk-shape-parity]].
