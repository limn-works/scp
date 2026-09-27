# Custody Substrate Isolation Holds at Rest, Not in Transit

Applies to any secret handed from one custody substrate to another: pre-rotation seed
migration (ADR-054, §9.7.4.1 of `09-security-model.md`), MLS sender-key handoff, media key
derivation.

## Type distinctness is not substrate distinctness

"The type system enforces §9.7.4.1 item 3 storage isolation" overclaims. What the types do
enforce: one object cannot serve as both operational and pre-rotation custody, `KeyHandle`
and `PreRotationKeyHandle` have no `From` or `Into` between them, and the Rust adapter
invalidates a handle after `consume` whether the foreign call succeeded or failed. What they
cannot enforce: that two distinct foreign callback objects sit on different hardware, use
different biometric prompts or access groups, or generate the pre-rotation key inside a
secure enclave. Both callbacks can be closures over the same Keychain access group. Those
remain obligations on the foreign implementation, partly checked by a conformance test that
the operational provider cannot recover the pre-rotation key.

## Migration is the designed exception

The handoff destroy-and-exports the 32-byte key from the pre-rotation custody adapter, the
bytes cross the FFI boundary in a `Zeroizing` buffer, and the substrate imports them as the new
`#0`. `Zeroizing` narrows the exposure window and does not close it: a core dump, a debugger,
or a cold-boot read while the bytes are live captures the key. Keep the export and the import
free of IO, logging, persistence, and copies. A backend where the key never exists as raw
bytes, such as an HSM or a secure element, rewraps inside one substrate and avoids the transit.

## Rules

1. Do not claim the type system enforces substrate isolation unless the type prevents every
   form of cross-substrate sharing, not only same-object reuse.
2. Document the transit window: which step materializes raw bytes, what zeroing applies, and
   what exposure remains.
3. State the boundary: isolation holds at rest, and the secret is observable during the
   handoff.

`crates/scp-ffi/uniffi/src/bridge.rs` carries the code comment recording the same boundary.
