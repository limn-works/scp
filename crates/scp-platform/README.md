# scp-platform

Platform abstraction traits for [SCP](https://github.com/limn-works/scp) (Shared Context Protocol).

This crate defines the portable interfaces that let the protocol core stay
platform-agnostic: the runtime programs against these traits, and each host
(Apple, Android, desktop, in-memory test) supplies a concrete implementation.
Private key material lives behind `KeyCustody` and never leaves the platform
boundary (ADR-006).

## Traits (`traits.rs`, `encrypted.rs`)

- **`KeyCustody`** — signing, Diffie-Hellman, and pseudonym derivation over
  opaque key handles. Keys are created, used, and destroyed without their bytes
  crossing the trait boundary.
- **`PreRotationCustody`** — pre-generates and commits to the next signing key
  for hash-committed key rotation.
- **`DeviceAttestation`** — platform attestation (Apple App Attest, Android Play
  Integrity) binding an identity to a genuine device.
- **`Push`** — platform push delivery (`APNs` / FCM).
- **`Storage`** — persistent key-value storage. `EncryptedStorage` is a sealed
  marker sub-trait for backends that encrypt at rest.

## Feature flags

Concrete implementations are optional and gated so that a consumer pulls in only
the platform code and dependencies it needs:

| Feature | Provides |
|---------|----------|
| `software_platform` | In-process `Ed25519` / `X25519` crypto primitives (no HSM) |
| `testing` | In-memory custody / attestation adapters for tests (implies `software_platform`, `in-memory-storage`, and `in-memory-push`, ADR-006). No shipped artifact resolves this feature — `scripts/check-shipped-feature-graph.sh` fails the build when one does |
| `sqlite` | `SQLCipher`-encrypted `Storage` with raw-key or `Argon2id`-passphrase key material (spec §17.6) |
| `apple` | Apple `SQLCipher` storage adapter (key supplied from the Keychain) |
| `file` | Encrypted file-backed key custody (`Argon2id` + `AES-256-GCM`) |
| `filesystem` | Plain filesystem `Storage` adapter (spec §17.6) |
| `encrypting` | `EncryptingAdapter` wrapping any `Storage` with `AES-256-GCM` per-value encryption |
| `sync` | `SyncableStorage` wrapper adding a write-ahead changelog for P2P state sync |

## Usage

Most consumers depend on `scp-core` (which wires a platform implementation
through the runtime). Depend on `scp-platform` directly only to implement a new
host adapter or to select a specific storage / custody backend by feature.

## License

Apache-2.0
