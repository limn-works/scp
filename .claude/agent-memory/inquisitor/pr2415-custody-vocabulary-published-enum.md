---
name: pr2415-custody-vocabulary-published-enum
description: PR #2415 custody vocabulary — the request side (encrypted_file / os_keystore, fail-closed) is sound and fixes the `file`-feature root cause; the published side (a 3-value fused enum on extractability × unlock factor) is UNSOUND — its reachable image on shipped code is a singleton and both non-extractable values are unreachable.
metadata:
  type: project
---

Branch `spec/custody-vocabulary-names-the-backend`, head `ed57a9f552`, PR #2415, stacked on
#2411 (OPEN, clean) and merging #2414 (OPEN, DIRTY). Follows [[scp-294-custody-name-one-meaning]].

**Human authorization, exactly as far as it goes.** Alec: "Neither — §3.2 decides fresh" and
"ok proposal accepted. make sure it goes into spec" against three parts: (1) the request side
names the backend, (2) the published side names extractability and the unlock factor, (3) the
published value is derived, never declared. He did NOT decide: the two spellings, the *three*
published values, the fusion of two facts into one enum, the five `UnlockFactor` wire strings,
or that an uncovered pair publishes nothing. §3.2.2 admits the value set is the branch's own:
"the criterion above admits a value set and names none … This mapping derives from the
criterion; the criterion does not state it."

**Settled and correct — do not relitigate.** All three bridges now resolve `scp-platform` with
the `file` feature (this fixes the root cause named in the prior pass). `os_keystore` without a
provider fails closed with `SCP-IDENT-1003`. `CustodyMigrationTarget::InMemory` deleted from an
ungated production enum (D16). Rejecting `platform` on primary sources (WebAuthn §6.2.1 makes it
client-relative; Windows CNG binds it to the TPM) holds.

**The published enum's reachable image is a singleton.** Measured off shipped backends:
FileKeyCustody → `extractable-passphrase`; SqliteKeyCustody → that or nothing;
InMemory → nothing; `AppleKeyCustody.keyIsExtractable` returns `true` unconditionally
(`bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:1049`) so iOS/macOS publish nothing
under either policy; `AndroidKeyCustody.unlockFactor` returns `"unprotected"` for every key
(`.../AndroidKeyCustody.kt:648`) so Android publishes nothing, TEE key included. Both
`NonExtractable*` values are unreachable, and the one non-extractable store in the system
publishes nothing while the weakest backend publishes a value.

**Two facts fused into one enum is the root-cause decision.** `key_is_extractable: bool` plus the
already-existing `UnlockFactor` enum as two wire fields is complete by construction — no
`UnstatableCustody`, no absent state, no OQ-12, and Android TEE publishes honestly. The fusion
was copied from the enum being replaced (`HardwareBiometric`/`HardwarePin`/`Software`), which is
also where the cardinality 3 came from.

**The absent state is licensed by a signal this branch's own tree says is empty.** §3.2.2 cites
ADR-039 "Absence of attestation is itself a signal"; §27.4.4 / OQ-23 of `.docs/specs/27-attestations.md`
on the same branch: absence "reads absence uniformly across every identity and distinguishes
nothing", and §27.1 carries a standing audit finding "the ADR does not specify what the signal means".

**"Derived, never declared" holds only where it is uninteresting.** `encrypted_file` self-reports
and can only ever say `extractable-passphrase`. `os_keystore` takes both facts from a
`KeyCustodyProvider` the SDK consumer writes, so a four-line provider publishes
`non-extractable-biometric` over an in-process key. `crates/scp-did/src/attestation.rs:154`-`:157`
states the opposite unqualified. The struct is `Deserialize` and §27.4.4 confirms no verifier.

**Nothing publishes it.** `ScpKeyCustodyAttestation::derive` has zero production callers;
`set_custody_attestation` has none either (§27.4.4, OQ-23); and this branch's own
`.docs/standards/sdk-common.md` states "Every create path on every bridge returns
`SCP-IDENT-1059` in a shipped build". The evidence for a permanent wire commitment is fakes
the same PR wrote.

**OQ-13 is a manufactured question.** ADR-006 / ADR-021 / ADR-027 already decide that platform
key stores are reached through the UniFFI callback and that private keys never cross the FFI
boundary (`.docs/adrs/phase-6.md:81`). "Which Rust backend reaches a non-extractable store" has a
decided answer — none, by architecture — so recording it as undefined and routing it to ADR-006
hides the real defect, which is that the callback adapters that DO reach those stores report
pairs the vocabulary cannot state.
