# ADR-053: Pre-Rotation Key Custody — Substrate Isolation for Callback Custody

**Status:** Proposed
**Date:** 2026-06-14
**Phase:** Phase 6 (production readiness, security)
**Related:** ADR-003 (Identity Key Rotation & Migration — defines the pre-rotation reveal/commitment flow, §4b), ADR-021 (UniFFI Bridge — defines the `KeyCustodyProvider` callback-interface pattern used by mobile platforms), ADR-025 (Apple Platform Adapter — sibling platform-keystore integration), spec §9.7.4.1 (Pre-Rotation Key Custody), §9.12 (Identity Key Migration & Recovery)

## Context

SCP's pre-rotation key is the recovery backstop for the entire identity system — the last resort after Identity Key compromise (spec §9.12). Spec §9.7.4.1 specifies its custody with the same rigor as the Identity Key. Two of its requirements are **substrate** requirements, not merely type requirements:

- **§9.7.4.1 §3 (Storage isolation):** "The pre-rotation private key MUST be stored separately from the Identity Key and Active Signing Key. It MUST NOT be accessible through the same custody provider or authentication flow used for daily operations."
- **§9.7.4.1 §4 (Approved custody methods):** the pre-rotation key MUST live in one of: a hardware security key (FIDO2/U2F), a secondary-device secure enclave, a platform-backed cloud key store, an encrypted offline backup (AES-256-GCM + Argon2id), Shamir 3-of-5, or a BIP39 paper backup.
- **§9.7.4.1 §5 (SDK presentation):** at identity creation the SDK MUST present the user with custody options, guide them through the selected method, verify the backup, and only then publish the `PreRotationCommitment`.

The Rust core models this correctly: `DidDht::create(key_custody, pre_rotation_custody)` and `migrate_identity(...)` take a **separate** `PreRotationCustody` trait object from the operational `KeyCustody` (ADR-003 §4b), and the spec's two-substrate split is expressible at the trait boundary.

**The gap is at the FFI callback-custody boundary.** When a mobile app supplies its own operational custody via the `KeyCustodyProvider` callback interface (the App-Attest / Keychain / Keystore path), the bridge mints the *pre-rotation* key into `scp_platform::testing::InMemoryPreRotationCustody`:

- PyO3: `crates/scp-ffi/src/identity.rs:819-824` (and the `create_with_agent_key` / `create_with_custody` siblings at `:919-922`, `:1047-1052`).
- UniFFI: `crates/scp-ffi/uniffi/src/bridge.rs` — `generate_ephemeral_ed25519_seed` (≈ lines 677-712) generates the seed locally via `OsRng` and routes it into `InMemoryPreRotationCustody`. The in-source comment is explicit and honest: *"Type-level isolation is satisfied… Substrate isolation is NOT yet satisfied: the bridge process and the currently-shipped `InMemoryPreRotationCustody` co-reside in the same Rust process memory… A process-memory dump compromises both."*

This violates §9.7.4.1 §3: the pre-rotation key sits in the **same process memory substrate** as the operational key-handle space, reachable without the separate authentication flow §3 mandates. It also does not satisfy §4 (no approved backend) or §5 (no SDK custody-selection ceremony) on the callback path.

A second, coupled defect blocks the **migration reveal** path for callback custody. Migrating an identity (ADR-003 §4b, spec §9.12) requires installing the revealed pre-rotation private bytes as the new operational `#0` key. The `KeyCustodyProvider` callback interface has no "import a known seed and return a handle" method — only `generate_keypair`, which mints a fresh random key. So UniFFI's `import_ed25519_signing_key` correctly fail-closes rather than silently corrupting the migration:

```
Err(PlatformError::Unsupported(
  "callback custody cannot import pre-rotation seed bytes; \
   KeyCustodyProvider has no import_ed25519_seed_bytes method. \
   Identity creation via callback custody is unaffected."))
```

Identity **creation** via callback custody works; **migration** via callback custody is unreachable. Both halves of this ADR are required for callback custody to meet §9.7.4.1 end-to-end.

This was surfaced during the 2026-06-13/14 cross-SDK audit. The existing code is honest about the limitation (detailed comments, fail-closed error, type-level isolation already enforced), but per the builder tenets "no deferral / completeness is the baseline," a self-admitted "separate workstream" is a gap to close, not a steady state. Per the artifact-flow invariant, the design is fixed in an ADR (and the spec, if §9.7.4.1 needs a callback-custody clause) **before** any code changes.

## Decision (proposed)

Close the gap by introducing a **dedicated pre-rotation custody callback interface** — distinct from the operational `KeyCustodyProvider`, exactly as §9.7.4.1 §3 demands — plus the SDK-side backends and selection ceremony §4/§5 require. Three parts:

### 1. A separate `PreRotationCustodyProvider` FFI callback interface

Define a new callback interface (UniFFI `[Trait, WithForeign]`, with the matching PyO3 `Py<PyAny>` and NAPI threadsafe-function adapters) that the SDK implements **independently** of its operational `KeyCustodyProvider`. Modeling it as a separate provider — not new methods on `KeyCustodyProvider` — is the mechanism that enforces §3's "MUST NOT be accessible through the same custody provider or authentication flow." The interface extends the Rust-core `PreRotationCustody` trait the core already consumes (the existing trait stores externally-generated keys via `store_committed_pre_rotation_key`; `generate()` has no current trait counterpart — it is a new in-substrate generation method added by this ADR):

- `generate() -> PreRotationKeyHandle` — generate the keypair **inside the separate substrate** (hardware key, secondary-device enclave, cloud key vault, or an encrypted-offline/Shamir/BIP39 wrapper), never in shared process memory. **`generate()` is required for backends that mint keys in-substrate (HSM, Secure Enclave, cloud vault). Import-only backends (BIP39 mnemonic restore, pre-generated offline backup) MUST return a typed error from `generate()` and the SDK MUST offer an alternative creation path (e.g., `from_mnemonic()` / `from_backup()`). Each SDK backend documents its capability set.**
- `public_key(handle) -> [u8; 32]` — for the `SHA-256(public_key)` commitment.
- `import_seed_bytes(seed: Zeroizing<[u8; 32]>) -> PreRotationKeyHandle` — install a known seed into the substrate. This is the method whose absence currently blocks migration; it is the reveal-time inverse of `consume`, used when the new identity adopts the revealed bytes as its operational `#0` (ADR-003 §4b).
- `consume(handle) -> Zeroizing<[u8; 32]>` — destroy-and-export the private bytes atomically at migration time (the `migrate_identity` step-5 destroy-and-export described in the §9.7.4.1 "Partial-publish recovery" paragraph; §9.7.4.1 item 6 "Post-rotation key cycling" is the subsequent step — generating a fresh pre-rotation keypair after migration completes). **Handle lifecycle invariant:** each `PreRotationKeyHandle` is single-use. The `CallbackPreRotationCustody` adapter MUST invalidate the handle in Rust immediately after `consume` returns — whether the callback succeeded or failed — so subsequent calls to `consume(same_handle)` or `public_key(same_handle)` return `Err(HandleNotFound)` regardless of what the foreign implementation does. This adapter-level enforcement closes the duplicated-handle / leaked-backstop risk that foreign implementations cannot be trusted to self-enforce.

**Canonical migration flow (reveal → import, ADR-003 §4b):** at `migrate_identity` step 5, the bridge calls `consume(pre_rotation_handle)` to destroy-and-export the 32-byte seed, wraps the seed in `Zeroizing`, then calls the operational `KeyCustody::import_ed25519_signing_key(seed)` to install the revealed pre-rotation bytes as the new `#0` signing key. The pre-rotation handle is invalidated in Rust before the operational import begins. A fresh pre-rotation handle is then generated via the selection ceremony (§9.7.4.1 §5, §9.7.4.1 item 6 post-rotation cycling) before the migration transaction completes.

The bridge's `generate_ephemeral_ed25519_seed` / `InMemoryPreRotationCustody` path on the callback flow is replaced by a `CallbackPreRotationCustody` adapter that dispatches to this provider. `InMemoryPreRotationCustody` is retained **test-only** (it already lives under `scp_platform::testing`), consistent with the in-memory-storage-is-dev-only stance.

### 2. Real SDK backends (§9.7.4.1 §4)

Each SDK ships at least one approved backend so the callback provider is not a hollow shell:

- **Swift (iOS/macOS):** Secure Enclave on a secondary device; iCloud Keychain with Advanced Data Protection (platform-backed cloud key store); FIDO2 via `ASAuthorization` security keys.
- **Kotlin (Android):** Android Keystore with StrongBox; a platform cloud key vault where available; FIDO2/CTAP2.
- **Cross-platform (all SDKs, incl. Python/TypeScript for server/test parity):** encrypted offline backup (AES-256-GCM, key via Argon2id memory=64 MiB/iter=3/parallelism=4, ≥128-bit auto-generated passphrase entropy); Shamir 3-of-5 over GF(2^8); BIP39 24-word mnemonic.

The encrypted-offline / Shamir / BIP39 codecs are pure and belong in `scp-protocol` (or `scp-platform` where they need platform RNG), shared across SDKs rather than re-implemented per language.

### 3. SDK custody-selection ceremony (§9.7.4.1 §5)

At identity creation the SDK presents custody options ordered by security, guides the user through the selected method, verifies the backup (re-entry/re-scan for offline methods), publishes the `PreRotationCommitment` only after verification, and destroys the creating device's in-memory copy. This is SDK-layer UX wiring over part 1's provider; the protocol-level requirement is that creation does not complete (and the commitment is not published) until a §4 backend holds the key.

## Cross-language impact

This is a **breaking addition to the FFI surface** (a new callback interface), so it touches every callback-custody bridge and the SDKs that implement custody:

| Layer | Change |
|-------|--------|
| `scp-protocol` / `scp-platform` | `PreRotationCustody` trait already exists; add shared encrypted-offline / Shamir / BIP39 codecs; add `import_seed_bytes` if not already on the trait. |
| PyO3 (`crates/scp-ffi/src/`) | `PyPreRotationCustodyProvider` (`Py<PyAny>` adapter); thread it through `identity_create*` / `identity_migrate`; remove the `InMemoryPreRotationCustody` default on the callback path. |
| NAPI (`crates/scp-ffi/napi/src/`) | Threadsafe-function adapter for the provider record (`{ generate, publicKey, importSeedBytes, consume }`). |
| UniFFI (`crates/scp-ffi/uniffi/src/`) | New `[Trait, WithForeign]` interface; replace `generate_ephemeral_ed25519_seed` → in-memory routing; implement `import_ed25519_signing_key` via `import_seed_bytes` (removes the current `Unsupported` block). |
| WASM | Per ADR-034, no platform keystore; WASM keeps an explicit, documented limitation (browser pre-rotation custody is its own constrained story — likely WebAuthn/passkey-PRF wrapping). |
| Swift / Kotlin SDKs | Implement `PreRotationCustodyProvider` against Keychain/Keystore/Secure Enclave/FIDO2; implement the §5 selection ceremony. |
| Python / TypeScript SDKs | Implement the cross-platform offline/Shamir/BIP39 backends for server and parity testing. |
| Capability matrix | New operations registered across bridges; `check-sdk-coverage` (now fail-closed) enforces parity. |

### Canonical method names (locked across bindings)

Per-binding casing of the four interface methods — these names are fixed and MUST NOT drift:

| Concept | Rust trait | UniFFI (`[Trait, WithForeign]`) | NAPI (JS object field) | PyO3 (`Py<PyAny>` attribute) | Swift | Kotlin |
|---------|-----------|-------------------------------|------------------------|------------------------------|-------|--------|
| generate in substrate | `generate` | `generate` | `generate` | `generate` | `generate()` | `generate()` |
| read public key | `public_key` | `public_key` | `publicKey` | `public_key` | `publicKey()` | `publicKey()` |
| import known seed | `import_seed_bytes` | `import_seed_bytes` | `importSeedBytes` | `import_seed_bytes` | `importSeedBytes()` | `importSeedBytes()` |
| destroy-and-export | `consume` | `consume` | `consume` | `consume` | `consume()` | `consume()` |

The `CallbackPreRotationCustody` adapter derives its method-call names from this table; bridge aliases (`bridge-aliases.json`) must use the bridge-layer names in the NAPI/UniFFI columns.

## Consequences

- **Positive:** callback custody meets §9.7.4.1 §3-§6 end-to-end; a process-memory compromise no longer exposes the recovery backstop; callback-custody migration becomes reachable (closes the `import_ed25519_signing_key` block); the two-substrate model is structurally encouraged by the type system (separate provider type prevents the same object serving both roles), but hardware/OS-level substrate and auth-flow isolation remains a foreign-implementation obligation — the Rust type signature cannot verify that two distinct callback objects are not backed by the same Keychain access group or biometric prompt. The conformance test ("pre-rotation key NOT recoverable from the operational provider") is the primary observable enforcement.
- **Cost:** a new public FFI callback surface and per-platform keystore integrations — the largest single piece. The UX ceremony (§5) is real product work on mobile.
- **Risk:** key-handle lifecycle bugs across the FFI boundary are security-critical (a dropped/duplicated pre-rotation handle is a lost or leaked backstop). Mitigation: `Zeroizing` on all seed bytes at the boundary; a conformance test that a created identity's pre-rotation key is NOT recoverable from the operational custody provider; the existing partial-publish recovery handle (§9.7.4.1 "Partial-publish recovery", ADR-003) already covers migration interruption. **Migration-reveal transit:** the `consume → import_ed25519_signing_key` step necessarily transits the 32-byte pre-rotation seed through shared bridge process memory; `Zeroizing` narrows but does not eliminate this window. Substrate isolation holds at rest; during migration the seed is transiently observable to a process-memory attacker.
- **No migration burden:** SCP is pre-release with no deployed identities; the in-memory callback path is replaced outright (no back-compat shim), per the no-migration-pre-release stance.

## Alternatives considered

- **Keep `InMemoryPreRotationCustody` on the callback path (status quo).** Rejected: violates §9.7.4.1 §3 substrate isolation; the recovery backstop shares the operational substrate, defeating its purpose. The current code already flags this as not-yet-satisfied.
- **Add `generate_pre_rotation` / `import_seed_bytes` methods to the existing `KeyCustodyProvider`.** Rejected: §9.7.4.1 §3 explicitly forbids the pre-rotation key being "accessible through the same custody provider or authentication flow used for daily operations." A combined provider re-introduces exactly the coupling §3 prohibits. A separate interface enforces the boundary structurally.
- **Generate the pre-rotation seed bridge-side and hand it to the SDK to store.** Rejected for the generation step on hardware-backed platforms: §9.7.4.1 §1 requires on-device CSPRNG generation, and for HSM/Secure-Enclave backends the key MUST be generated *inside* the substrate and never marshalled as raw bytes. The provider's `generate()` keeps generation in the substrate. (Bridge-side `OsRng` generation remains acceptable only for the software/offline backends that inherently hold raw bytes.)
- **Defer to a tracking issue.** Rejected per CLAUDE.md ("never create tracking issues instead of doing the work"). This ADR is the design step; acceptance authorizes the implementation workstream.

## Open questions (for review)

1. **WASM scope.** Is browser pre-rotation custody (WebAuthn/passkey-PRF) in scope for this ADR, or a separate ADR gated on the WASM custody story (ADR-034)?
2. **Backend minimum.** Which §4 backends are mandatory for v1 per platform vs. additive (e.g., is encrypted-offline a sufficient floor for all SDKs, with hardware backends additive)?
3. **Spec clause.** Does §9.7.4.1 need an explicit "callback-custody pre-rotation provider" sub-clause, or is the existing §3 normative text sufficient to govern the implementation? (If a clause is needed, the spec change lands before code, per artifact flow.)
