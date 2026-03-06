# Spec-Level Cryptographic Audit Findings (2026-03-05)

## Summary: 9 CRITICAL, 11 HIGH, 8 MEDIUM, 5 LOW

### CRITICAL Findings
1. **CRYPTO-01/02**: InnerEnvelope + BroadcastEnvelope signature hashes lack length prefixes on variable-length fields (context_id, sender_did) -- concatenation ambiguity enables second-preimage attacks
2. **CRYPTO-02 addl**: BroadcastEnvelope has NO domain separator (InnerEnvelope has "SCP-INNER-ENVELOPE-V1:")
3. **CRYPTO-03**: Sender key HPKE is manual ECDH+HKDF+AEAD, NOT RFC 9180 -- no mode, no info string, no nonce derivation specified
4. **CRYPTO-04**: Sender key AES-256-GCM nonce generation completely unspecified
5. **CRYPTO-12**: Attestation signature canonical input undefined (no serialization format)
6. **CRYPTO-13/14**: ParticipationProfile signature input + signing key derivation both unspecified
7. **CRYPTO-18**: Broadcast key AES-256-GCM nonce, wire format, AAD all unspecified
8. **CRYPTO-23**: Encrypted context routing_id derivation missing entirely

### HIGH Findings
- CRYPTO-06: Ed25519_keygen(seed) semantics undefined (seed vs clamped scalar = cross-platform breakage)
- CRYPTO-07: Pseudonym HMAC key material differs by custody type (public key vs HSM-derived)
- CRYPTO-09: SenderKeyEpochAdvance signature lacks length prefixes + epoch encoding unspecified
- CRYPTO-10/11: HPKE suite mode and info string for sender key distribution not fully specified
- CRYPTO-16: Sender key encryption wire format (ciphertext + nonce struct) missing
- CRYPTO-19: Identity private state encryption algorithm/key/nonce completely unspecified
- CRYPTO-21: Merkle tree description in 9.5 says hash chain, not Merkle tree (contradicts impl)
- CRYPTO-22: KeyPackage signing key ambiguous (#0 vs #active)
- CRYPTO-24: SenderKeyRequest signature input undefined
- CRYPTO-28: Provenance hash serialization format undefined
- CRYPTO-32: UCAN CID computation not specified (known bridge bug PR #127)

### Key Pattern
The spec correctly uses length prefixes + domain separators in the migration proof (line 350) and key continuity fingerprint (line 663). These same patterns are MISSING from 8+ other hash/signature constructions. The fix is to apply the migration proof pattern universally.

### Missing Constructions (not specified at all)
1. Encrypted context routing_id derivation
2. Canonical serialization format for signed structures
3. CSPRNG mandate for key/nonce generation
4. Zeroization mandate for key material
5. Sender key encryption wire format
6. Broadcast key encryption wire format
7. HPKE mode selection for all HPKE usages
8. Nonce generation for non-MLS AES-GCM layers
