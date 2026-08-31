---
name: custody-vocabulary-pr2415
description: PR #2415 (spec/custody-vocabulary-names-the-backend) review — two-value custody vocabulary meets identical-shape, but identity_published_custody is misnamed (local registry read, not DID-document read), unlock_factor's unknown-string fallback collides with both shipped adapters' real answer, and derive's Result has zero readers
metadata:
  type: project
---

Branch `spec/custody-vocabulary-names-the-backend`, PR #2415. Verdict NEEDS REVISION.

**What is settled and good — do not relitigate.** The two-value request vocabulary
(`encrypted_file` / `os_keystore`) is closed at type-check time in all four SDKs
(Python `enum.Enum`, TS string-literal union, Swift raw-value enum, Kotlin
`enum class(rawValue)`), and custody is a required argument with no default on every
one. That meets the agent-first "identical shape across all language bindings" tenet;
the per-language spelling difference is the repo's own per-SDK-idiom rule. Spec §3.2.2
of `.docs/specs/03-identity.md` is the governing artifact and is unusually complete
(records divergences D14–D17 and open questions OQ-10…OQ-14 against itself).

**The load-bearing findings.**

1. `identity_published_custody(did) -> Option<String>` is named and documented as
   "the custody value a DID document publishes for `did`", and reads the **local
   in-process custody registry** instead (PyO3 `with_identity`, NAPI `with_identity`,
   UniFFI `identity_custody_registry`). No DID resolution occurs. Calling it with a
   counterparty DID — the exact trust use the surrounding docs describe — always
   throws. Rename to say "this instance's own identity", or take a `DidDocument`.
2. `ScpKeyCustodyAttestation::derive` and `DidDocument::set_custody_attestation` have
   **zero production callers** (tests only). No DID document SCP publishes carries a
   custody attestation today.
3. `parse_unlock_factor` maps an unrecognised string AND the literal
   `"caller_supplied_key"` onto the same `UnlockFactor::CallerSuppliedKey`. Both
   shipped adapters answer with strings that publish nothing —
   `AppleKeyCustody.unlockFactor` returns `"caller_supplied_key"` under the default
   policy, `AndroidKeyCustody.unlockFactor` always returns `"unprotected"` — so an
   adapter author's typo is indistinguishable at runtime from the deliberate
   abstention. Only `encrypted_file` ever publishes a value (`extractable-passphrase`).
4. Registry-miss code split: PyO3/NAPI `SCP-IDENT-1001`, UniFFI `SCP-IDENT-1017`. The
   normative registry `crates/scp-ffi/common/src/error_codes.rs` documents 1017 as
   "Distinct from IDENT_1001 (identity not registered)", so UniFFI contradicts it.
   Recorded in `sdk-capability-matrix.json` as a known divergence rather than fixed.
5. `derive(...) -> Result<Self, UnstatableCustody>` models a protocol-valid absent
   state as an error; its only consumer, `published_custody_wire_value`, `.ok()`s the
   payload away. `Option<Self>` matches "absence of attestation is itself a signal".
6. `docs/guides/sdk-quickstart.md:215` passes the raw string `"encrypted_file"` to
   Python `identity_create(custody: CustodyType)`, whose body does `custody.value` →
   `AttributeError`. Python is the one SDK with no compile-time gate and no runtime
   coercion.

**Reusable checks for the next custody/vocabulary review.** Re-derive from source, do
not trust a doc's parity claim: (a) grep for production callers of any new
constructor before crediting it; (b) diff the input vocabulary against the read-back
vocabulary — `Identity.custody_type()` is a *third* set (`encrypted_file`,
`callback`, `in_memory`) that no SDK enum spells; (c) check that a fallback arm and a
legitimate value do not collapse onto the same variant.

Related: [[custody-selection-surface-scp294]], [[cross-sdk-shape-parity]].
