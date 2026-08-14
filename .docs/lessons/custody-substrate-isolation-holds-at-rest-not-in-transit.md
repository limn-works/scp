# Custody Substrate Isolation Holds At Rest, Not In Transit

**Source:** ADR-054 (pre-rotation custody substrate isolation), corrected Consequences §
**Applies to:** any cross-substrate secret handoff — pre-rotation seed migration, MLS
sender-key handoff, media key derivation, and similar construct.

## The Claim That Was Wrong

"The type system enforces §9.7.4.1 §3 storage isolation at compile time." This was an
overclaim that appeared in ADR-054's original Consequences section and in
`.docs/lessons/hash-commitment-preimage-lifetime.md`.

A separate Rust trait (`PreRotationCustodyProvider` distinct from `KeyCustodyProvider`)
prevents *one object* from serving both roles, but has no visibility into what two distinct
foreign callback objects actually do. Both could be closures backed by:

- the same Keychain access group
- the same biometric prompt (Face ID, Touch ID)
- the same secure-enclave key

The Rust type signature cannot verify any of these. Type distinctness is not substrate
distinctness. §9.7.4.1 §3 mandates a *substrate/auth-flow* property that no type can
enforce for opaque foreign implementations.

## What the Type System Does Enforce

- The *same object* cannot serve as both operational and pre-rotation custody (structural
  prevention of the trivially-wrong shape)
- `KeyHandle` and `PreRotationKeyHandle` have no `From`/`Into` (no accidental promotion)
- Handle single-use: the Rust adapter invalidates handles after `consume`, on success or
  failure, before the foreign implementation can act

## What It Cannot Enforce

- That two distinct foreign callback objects are backed by different hardware substrates
- That the operational and pre-rotation flows use different biometric prompts or access
  groups
- That the pre-rotation key is generated inside a secure enclave (vs. in process memory)

These remain **foreign-implementation obligations**, partially verified by a conformance
test: "a created identity's pre-rotation key is NOT recoverable from the operational
custody provider." That test is observable but not exhaustive.

## Migration-Reveal Transit: Isolation Holds At Rest, Not During Migration

The `consume(handle) → import_ed25519_signing_key(seed)` step necessarily transits the
32-byte pre-rotation seed through shared bridge process memory:

1. `consume` destroy-and-exports raw bytes from the pre-rotation substrate
2. Those bytes cross the FFI boundary as a `Zeroizing<[u8; 32]>`
3. `import_ed25519_signing_key` consumes them into the operational substrate
4. `Zeroizing` wipes the buffer on drop

`Zeroizing` narrows the exposure window but does not eliminate it: a core dump, debugger
attach, or cold-boot attack during steps 2-3 captures the pre-rotation seed in plaintext.

**The practical implication:** substrate isolation guarantees that the pre-rotation key is
not accessible through normal operational flows *at rest* — it does not guarantee that
the seed is never in shared memory. Migration is the designed exception: revealing the
pre-rotation seed during migration is not a bug; it is the protocol's intended handoff
mechanism. The obligation is to keep the `consume → import` sequence as tight as possible
(no intervening IO, logging, persistence, or copies).

For backends where the key never exists as raw bytes (HSM, Secure Enclave internal key
generation), a same-substrate rewrap could avoid this transit — but that is an optional
optimization, not a current requirement.

## Rule for Future Agents

When a new cross-substrate secret handoff is introduced:
1. Do NOT claim "the type system enforces substrate isolation" unless the type prevents
   *all* cross-substrate sharing, not just same-object reuse.
2. Document the transit window explicitly: which step materializes raw bytes, what
   zeroing is applied, and what the residual exposure is.
3. State the guarantee boundary: "holds at rest; transiently observable during handoff."

## See Also

- `.docs/lessons/hash-commitment-preimage-lifetime.md` — pre-rotation commitment scheme;
  contains the corrected type-isolation claim
- `.docs/adrs/ADR-054-pre-rotation-custody-substrate-isolation.md` — source of this lesson
- `crates/scp-ffi/uniffi/src/bridge.rs:686-692` — honest code comment: "Type-level
  isolation is satisfied... Substrate isolation is NOT yet satisfied"
