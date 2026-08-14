# ADR-051 Pre-Rotation Custody Substrate Isolation (Proposed, 2026-06-14)

Reviewed branch fix/sdk-coverage-fail-closed-and-parity @ f6caeb5dd. ADR is SOUND.

## Proposed PreRotationCustodyProvider FFI callback interface (4 methods)
- `generate() -> PreRotationKeyHandle` — generate keypair INSIDE separate substrate (HSM/SecureEnclave/cloud-vault/offline-wrapper), never shared process memory
- `public_key(handle) -> [u8;32]` — for SHA-256(public_key) commitment
- `import_seed_bytes(Zeroizing<[u8;32]>) -> handle` — reveal-time inverse of consume; closes the currently-Unsupported callback-custody migration block (CallbackKeyCustody.import_ed25519_signing_key fail-close, the SCP-1717 MEDIUM-open blocker for #1729)
- `consume(handle) -> Zeroizing<[u8;32]>` — atomic destroy-and-export at migration (§9.7.4.1 §6 / migrate_identity step-5 post-rotation key cycling)

## Why separate provider (not methods on KeyCustodyProvider)
§9.7.4.1 §3 forbids pre-rotation key reachable through operational custody/auth flow. Separate
callback interface enforces substrate isolation STRUCTURALLY (type system), not by doc. Combined
provider rejected — re-introduces the exact coupling §3 prohibits.

## Crypto boundaries preserved
- In-substrate generation for HSM/SecureEnclave (§1 on-device CSPRNG, never marshal raw bytes);
  bridge-side OsRng only OK for software/offline backends that inherently hold raw bytes.
- Backends §4: SecureEnclave/Keychain-ADP/FIDO2 (Swift), Keystore-StrongBox/FIDO2 (Kotlin),
  AES-256-GCM+Argon2id(64MiB/3/4)/Shamir-3of5-GF(2^8)/BIP39-24word (cross-platform).
- Codecs belong in scp-protocol (pure) or scp-platform (platform RNG), shared not per-language.

## Open implementation contracts (LOW, flagged in ADR, must resolve at impl time)
- consume() atomicity: if export succeeds but destroy fails (or vice versa) → backstop leaked or
  lost. Impl ADR must pin ordering + partial-consume recovery path (partial-publish recovery handle exists).
- §9.7.4.1 callback-custody sub-clause: spec change lands BEFORE code if §3 text insufficient (open Q3).
- WASM: explicit limitation per ADR-034, likely WebAuthn/passkey-PRF wrapping (open Q1).

## Other surfaces on this branch (all SOUND)
- trust.ts 4-layer UCAN classifier: faithful port of Python scp_sdk/trust.py. Prefix tables match
  UcanError Display (ucan/mod.rs #[error]). Order signatures→ceiling→token_parse→nonce→revoked→expiry
  matches validate.rs pipeline parse(1)→sig(2)→chain(3-5)→cap_match(6)→atten(7)→ceiling(8)→nonce(9)→
  revoke(10)→expiry(11). DIAGNOSTIC ONLY, not an auth gate; conservative approximation only under-claims.
- __extractCoreError parses NAPI `[SCP-PERM-X] permission error: <Display> — <advice>` (em-dash U+2014,
  From<UcanError> at napi/src/error.rs:401-409).
- identity.ts rotationEventJson: surfaces DidRotationEvent (document.rs:1138) = all PUBLIC (old/new DID,
  MigrationProof, optional PreRotationProof, rotated_at). No private bytes. Must distribute per §3.2.1 4b.
- internal/bridge.ts __setBridgeForTests: NODE_ENV!=production guard, injects Bridge not keys. Sound.
- mls/provider.rs doc-comments: stale "default no-op/override" (old trait design) → accurate "inherent
  method, no crypto trait indirection". Bodies verified accurate (rotate_sender_key AES-256 fresh+epoch++
  +HPKE-seal+skip-self; drain = mem::take).
