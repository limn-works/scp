# Cryptographer Memory

- [HPKE RFC 9180 core](hpke-rfc9180-conformance.md) — the one HPKE implementation, its traps (empty-string salt, hpke-rs empty-plaintext quirk, zeroizing DH copies), the custody Decap contract, the 48-byte wire form.
- [Custody-violation signing](custody-violation-signing.md) — preimages, domain separators, the load-bearing variant discriminator, verified newtypes, §25.25 Vectors 38/39.
- [Key files](key-files.md) — where each construction lives after the scp-core split.

## Standing facts and review checks
- **New signed constructions use `crypto/canonical.rs`:** raw UTF-8 domain separator (no prefix), BE32 length prefix on every variable-length field, fixed-width fields raw, integers big-endian, absent value = `SHA-256(0x00)`. A construction built by hand-concatenating variable-length fields is a finding.
- **Two UCAN digests, not interchangeable.** `compute_cid` returns `"bafyrei" + hex(SHA-256(JWT))` and keys delegation proofs (`prf`); despite the prefix it is not a real CIDv1, only an opaque id. `compute_revocation_cid` returns bare `hex(SHA-256(JWT))` and keys the revocation list. Using one where the other belongs silently breaks delegation chains or makes revocation a no-op.
- **Grep for non-strict Ed25519 verification.** Most paths use `verify_strict`, but plain `verify` has survived in places (for example `crates/scp-protocol/src/context/broadcast/mod.rs`). Flag any production `.verify(` on an Ed25519 key.
- **A nonce-dedup window must outlast the freshness window's skew.** `NonceDedup` uses a fixed 300-second window equal to the freshness window, which is safe only because the two coincide. A caller that widens clock-skew tolerance must make the dedup window strictly longer, or a replay slips through the gap where both windows end together.
- **SCP's `EpochGraceStore` records epochs but does not gate decryption.** `crates/scp-mls/src/ratchet.rs` adds the old epoch and discards the expired list; old-epoch secrets live in OpenMLS storage, so the 30-second grace window of spec §23.11 holds only as far as OpenMLS's retention allows. Check this before accepting any forward-secrecy claim that relies on the grace window.
- **MessagePack encodes `[u8; N]` without `serde_bytes` as an integer array, not `bin`.** A fixed nonce or key field missing `serde_bytes` (or a bounded serde helper) changes the wire format and breaks cross-language decoders.
- `EventType` serializes by variant name, so removing a variant cannot shift other leaves; a removed variant's tag is retired as a permanent gap (tag 59), never renumbered, which keeps the §25 known-answer vectors stable.
- `SigningKeyId` (`#active` / `#agent`) is inside the signed inner-envelope preimage, and `SigningKeyId::from_fragment` accepts only those two strings. Governance votes carry no key id and always verify against `#active`.
