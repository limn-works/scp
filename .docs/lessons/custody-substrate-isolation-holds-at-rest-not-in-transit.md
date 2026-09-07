# Custody Substrate Isolation Holds At Rest, Not In Transit

**Source**: ADR-054, pre-rotation custody substrate isolation, and §9.7.4.1 §3 of the
security-model spec, `09-security-model.md`.
**Applies to**: any cross-substrate secret handoff — pre-rotation seed migration, MLS
sender-key handoff, media key derivation.

## Type distinctness is not substrate distinctness

"The type system enforces §9.7.4.1 §3 storage isolation at compile time" overclaims. A
separate Rust trait — `PreRotationCustodyProvider` distinct from `KeyCustodyProvider` —
prevents one object from serving both roles, and it has no visibility into what two
distinct foreign callback objects do. Both can be closures backed by the same Keychain
access group, the same biometric prompt, or the same secure-enclave key. §9.7.4.1 §3
mandates a substrate and auth-flow property that no Rust signature can enforce for an
opaque foreign implementation.

**What the types do enforce**: the same object cannot serve as both operational and
pre-rotation custody; `KeyHandle` and `PreRotationKeyHandle` have no `From` or `Into`, so
neither promotes into the other; and the Rust adapter invalidates a handle after `consume`,
on success and on failure alike, before the foreign implementation can act.

**What they cannot enforce**: that two distinct foreign callback objects are backed by
different hardware substrates, that the operational and pre-rotation flows use different
biometric prompts or access groups, or that the pre-rotation key is generated inside a
secure enclave rather than in process memory. Those stay foreign-implementation
obligations, partially verified by a conformance test asserting that a created identity's
pre-rotation key is not recoverable from the operational custody provider. That test is
observable and not exhaustive.

## Migration is the designed exception

The `consume(handle)` → `import_ed25519_signing_key(seed)` step transits the 32-byte
pre-rotation seed through shared bridge process memory: `consume` destroy-and-exports raw
bytes from the pre-rotation substrate, the bytes cross the FFI boundary as a
`Zeroizing<[u8; 32]>`, `import_ed25519_signing_key` consumes them into the operational
substrate, and `Zeroizing` wipes the buffer on drop. `Zeroizing` narrows the exposure
window rather than closing it: a core dump, a debugger attach, or a cold-boot attack while
the bytes are live captures the seed in plaintext.

Revealing the pre-rotation seed during migration is the protocol's intended handoff
mechanism, so the obligation is to keep the `consume` → `import` sequence tight, with no
intervening IO, logging, persistence, or copies. A backend where the key never exists as
raw bytes — a hardware security module, or a Secure Enclave generating the key
internally — could rewrap within one substrate and avoid the transit.

## Rules

1. **Do not claim that the type system enforces substrate isolation** unless the type
   prevents every form of cross-substrate sharing, not only same-object reuse.
2. **Document the transit window explicitly**: which step materializes raw bytes, what
   zeroing applies, and what exposure remains.
3. **State the guarantee boundary**: isolation holds at rest, and the secret is transiently
   observable during the handoff.

## See also

- `.docs/lessons/hash-commitment-preimage-lifetime.md` — the pre-rotation commitment scheme,
  which carries the corrected type-isolation claim.
- `.docs/adrs/ADR-054-pre-rotation-custody-substrate-isolation.md` — the decision this
  lesson corrects.
- `crates/scp-ffi/uniffi/src/bridge.rs`, in `generate_ephemeral_ed25519_seed` — the code
  comment recording that type-level isolation is satisfied while substrate isolation is not.
