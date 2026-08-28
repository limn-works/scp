---
name: scp-294-custody-name-one-meaning
description: SCP-294 custody-string fail-closed change — the "platform" refusal is compelled, but the permanence doctrine written alongside it contradicts ADR-025/026/027/028, and the injection path it points every caller at does not compile on Swift or Kotlin.
metadata:
  type: project
---

Branch `fix/scp-294-custody-name-means-one-thing`, head `56c6a0e880`, base `5e7e5b4e67`.
Second pass, after the human restored `platform`/`software` in the four SDK enums and reserved
the `"file"`-vs-`"software"` spelling to open question OQ-9 and to §3.2 of the identity spec.

**Settled, do not relitigate:** restoring the SDK enum members was right; the spelling question
belongs to the human and to §3.2.

**Compelled and correct (keep):** PyO3's `"platform"` → `FileKeyCustody` substitution is severed,
and all three bridges answer the string with `SCP-IDENT-1003`. Naming a platform-native store and
receiving an encrypted file is a false guarantee about key location; the fail-closed builder tenet
decides it upstream of §3.2. `CustodyMethod::Platform`/`Software` deletion is also right — the
variants stamped an opaque injected provider with a substrate claim, and `Identity::custody_type()`
now answers `"callback"`, which the PyO3 and napi bridges already answered.

**The doctrine is not compelled and contradicts four Accepted ADRs.** The change wrote
"never by naming it here" (`crates/scp-ffi/src/identity.rs` `parse_custody` rustdoc), "That error is
the permanent behaviour, not a waiting state" (`.docs/lessons/uniffi-handle-count-shutdown-ordering.md`),
"No custody string selects it" (`bindings/kotlin/scp-kt-android/.../PlatformAdapter.kt:3`), and
"in every build" (`bindings/swift/Tests/SCPTests/CustodyTypeTests.swift:10`). Against:
`.docs/adrs/phase-6.md:411` — "The Kotlin SDK's `SCP.create()` factory calls
`AndroidPlatformAdapter.make(context)` when `custody = "platform"`" — and `.docs/adrs/phase-5.md:733`,
`public static func create(custody: CustodyMethod = .platform)`. Those ADRs make the custody string
the SDK-level selector for the injection; the change says no custody string selects it. Neither ADR
was amended, and the `SCP.create(custody:)` factory they describe was never built.

**The advertised alternative does not compile on the two named platforms.** The change's own READMEs
say it: `AppleKeyCustody` carries the `KeyCustodyProvider` method set but declares no conformance
(`bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:240` is `public final class
AppleKeyCustody: Sendable`), and `AndroidKeyCustody` implements
`works.limn.scp.android.platform.KeyCustodyProvider`, a different interface from
`uniffi.scp.KeyCustodyProvider`, with no adapter. Both are documented as "until that conformance
lands" / "until one lands".

**Root cause still unnamed:** `crates/scp-ffi/Cargo.toml:80` resolves `scp-platform` with the `file`
feature; `napi/Cargo.toml:86` and `uniffi/Cargo.toml:82` do not. Nobody decided that, and it is the
sole reason `"file"` exists on one bridge and `"software"` on two — which is the spelling question
OQ-9 holds.

**Human ruling that constrains any future answer** (§3.9.3 of the PR-#2411 spec, verbatim):
Alec, 2026-08-25 — "active generally would not go in hardware but it's an option. it would go behind
a passkey or something. so platform would be the expectation." And: "LET PEOPLE CHOOSE. LIKE IS
ALREADY FUCKING WRITTEN INTO THE GODDAMN PROTOCOL."

See [[scp-out-046-streaming-saga-seal-fsm]] for the contrasting case where an architecture-forced
split was SOUND and should not be re-litigated.
