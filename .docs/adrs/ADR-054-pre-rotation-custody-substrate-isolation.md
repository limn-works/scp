# ADR-054: Pre-Rotation Key Custody — Substrate Isolation for Callback Custody

**Status:** Proposed — design complete, recommended for acceptance; awaiting human sign-off (moves to Accepted on human sign-off).
**Date:** 2026-06-14
**Phase:** Phase 6 (production readiness, security)
**Amended (2026-07-14) — recovery-authority residence; OQ2/OQ3 resolved; recommended for acceptance:** A cryptographer analysis established that substrate isolation (§9.7.4.1 §3) is a property of WHERE THE RECOVERY AUTHORITY RESIDES, not of the cipher wrapped around the key — so §4's parameter checklist does not by itself satisfy §3, and encrypted-offline with an auto-generated passphrase is degenerate (isomorphic to InMemory) on a non-interactive server. The spec now owns this rule as normative **§9.7.4.1 item 3a (recovery-authority residence)**, added spec-first ahead of this amendment; this ADR realizes and schedules it. OQ2 is resolved with **per-profile floors** (non-interactive server floor = independent-principal KMS/HSM/cloud-vault, NOT encrypted-offline-auto-gen; interactive clients may use user-supplied-passphrase encrypted-offline), the full §4 menu remaining available per profile under the §3a residence rule. OQ3 is resolved **YES** (§3 prose constrained the provider object, not the secret's residence; the new §3a clause is required and lands spec-first). With OQ2/OQ3 resolved the design is complete; this amendment **recommends the ADR for acceptance**, which takes effect on human sign-off — the ADR remains **Proposed** until then. See the Amendment section for the per-backend §3-soundness table, the strengthened conformance-test pair, and the at-rest caveat. Prior content below is retained; this note and the Amendment section amend it.
**Amended by ADR-055 (2026-06-29):** the WASM bridge is removed (browser clients are remote thin clients to a server-side `scp-node`). Pre-rotation custody is therefore not an in-browser concern: a browser client has no in-process MLS or custody substrate, so its pre-rotation key is held server-side by the `scp-node` it connects to, governed by that node's platform custody (the rows/questions below for native bridges). The "Cross-language impact" WASM table row and Open Question 1 (browser pre-rotation custody / WASM custody story) have been reconciled to this thin-client model. No other current-state design content changes.
**Related:** ADR-003 (Identity Key Rotation & Migration — defines the pre-rotation reveal/commitment flow, §4b), ADR-021 (UniFFI Bridge — defines the `KeyCustodyProvider` callback-interface pattern used by mobile platforms), ADR-025 (Apple Platform Adapter — sibling platform-keystore integration), ADR-055 (WASM bridge removal), spec §9.7.4.1 (Pre-Rotation Key Custody), §9.12 (Identity Key Migration & Recovery)

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

Define a new callback interface (UniFFI `[Trait, WithForeign]`, with the matching PyO3 `Py<PyAny>` and NAPI threadsafe-function adapters) that the SDK implements **independently** of its operational `KeyCustodyProvider`. Modeling it as a separate provider — not new methods on `KeyCustodyProvider` — is the mechanism that enforces §3's "MUST NOT be accessible through the same custody provider or authentication flow."

**Relationship to the existing core trait.** The Rust-core `PreRotationCustody` trait already exists (`crates/scp-platform/src/traits.rs`) and is consumed by `DidDht::create` / `migrate_identity`. This ADR does **not** rename it. The new FFI callback interface is the *foreign-facing* surface; a `CallbackPreRotationCustody` adapter implements the core trait by dispatching to the foreign provider. The interface therefore has four FFI-facing methods, three of which map onto existing core-trait methods and one of which is genuinely new:

- `generate() -> PreRotationKeyHandle` — generate the keypair **inside the separate substrate** (hardware key, secondary-device enclave, cloud key vault, or an encrypted-offline/Shamir/BIP39 wrapper), never in shared process memory. This is the only **new** capability: the core trait has no `generate` counterpart (it only ever *stores* an externally-supplied keypair via `store_committed_pre_rotation_key`). **`generate()` is required for backends that mint keys in-substrate (HSM, Secure Enclave, cloud vault). Import-only backends (BIP39 mnemonic restore, pre-generated offline backup) MUST return a typed error from `generate()` and the SDK MUST offer an alternative creation path (e.g., `from_mnemonic()` / `from_backup()`). Each SDK backend documents its capability set.**
- `public_key(handle) -> [u8; 32]` — read the 32-byte public key for the `SHA-256(public_key)` commitment. Maps to the core trait's existing **`reveal_public_key`**.
- `import_seed_bytes(seed: Zeroizing<[u8; 32]>) -> PreRotationKeyHandle` — install a known, externally-generated seed into the substrate and return a handle. This is the FFI-facing analogue of the core trait's existing **`store_committed_pre_rotation_key`** (see "import vs. store" below); it is the method whose absence at the *callback* boundary currently blocks migration, and it is the reveal-time inverse of `consume`, used when the new identity adopts the revealed bytes as its operational `#0` (ADR-003 §4b).
- `consume(handle) -> Zeroizing<[u8; 32]>` — destroy-and-export the private bytes atomically at migration time. Maps to the core trait's existing **`destroy_after_migration`** (the `migrate_identity` step-5 destroy-and-export described in the §9.7.4.1 "Partial-publish recovery" paragraph; §9.7.4.1 item 6 "Post-rotation key cycling" is the subsequent step — generating a fresh pre-rotation keypair after migration completes). **Handle lifecycle invariant:** each `PreRotationKeyHandle` is single-use. The `CallbackPreRotationCustody` adapter MUST invalidate the handle in Rust immediately after `consume` returns — whether the callback succeeded or failed — so subsequent calls to `consume(same_handle)` or `public_key(same_handle)` return `Err(HandleNotFound)` regardless of what the foreign implementation does. This matches the core trait's documented contract that `destroy_after_migration` makes the handle return `HandleNotFound` thereafter; the adapter enforces it in Rust so foreign implementations cannot leak the backstop.

**`import_seed_bytes` vs. `store_committed_pre_rotation_key` — coexist, do not replace.** The two are the same underlying core-trait operation surfaced under different names: `import_seed_bytes` is simply the FFI-facing spelling that the `CallbackPreRotationCustody` adapter routes into `store_committed_pre_rotation_key`. The core trait's name is **unchanged**; no second "import" method is added to the trait. The reason the FFI method takes only the seed (and not the explicit `public_key` the core trait's signature carries) is that the public key is derivable from the Ed25519 seed inside the adapter before the core call; the adapter derives it and forwards both arguments to `store_committed_pre_rotation_key`. So at the core layer there is exactly one storage method; at the FFI layer it is exposed as `import_seed_bytes`.

**Canonical migration flow (reveal → import, ADR-003 §4b):** at `migrate_identity` step 5, the bridge calls `consume(pre_rotation_handle)` to destroy-and-export the 32-byte seed, wraps the seed in `Zeroizing`, then calls the operational `KeyCustody::import_ed25519_signing_key(seed)` to install the revealed pre-rotation bytes as the new `#0` signing key. The pre-rotation handle is invalidated in Rust before the operational import begins. A fresh pre-rotation handle is then generated via the selection ceremony (§9.7.4.1 §5, §9.7.4.1 item 6 post-rotation cycling) before the migration transaction completes.

The bridge's `generate_ephemeral_ed25519_seed` / `InMemoryPreRotationCustody` path on the callback flow is replaced by a `CallbackPreRotationCustody` adapter that dispatches to this provider. `InMemoryPreRotationCustody` is retained **test-only** (it already lives under `scp_platform::testing`), consistent with the in-memory-storage-is-dev-only stance.

### 2. Real SDK backends (§9.7.4.1 §4)

Each SDK ships at least one approved backend so the callback provider is not a hollow shell:

- **Swift (iOS/macOS):** Secure Enclave on a secondary device; iCloud Keychain with Advanced Data Protection (platform-backed cloud key store); FIDO2 via `ASAuthorization` security keys.
- **Kotlin (Android):** Android Keystore with StrongBox; a platform cloud key vault where available; FIDO2/CTAP2.
- **Cross-platform (all SDKs, incl. Python/TypeScript for server/test parity):** encrypted offline backup (AES-256-GCM, key via Argon2id memory=64 MiB/iter=3/parallelism=4, ≥128-bit auto-generated passphrase entropy) *(superseded for server rows — see Amendment 2026-07-14: auto-generated-passphrase encrypted-offline is not a conforming non-interactive-server floor)*; Shamir 3-of-5 over GF(2^8); BIP39 24-word mnemonic.

The encrypted-offline / Shamir / BIP39 codecs are pure and belong in `scp-protocol` (or `scp-platform` where they need platform RNG), shared across SDKs rather than re-implemented per language.

### 3. SDK custody-selection ceremony (§9.7.4.1 §5)

At identity creation the SDK presents custody options ordered by security, guides the user through the selected method, verifies the backup (re-entry/re-scan for offline methods), publishes the `PreRotationCommitment` only after verification, and destroys the creating device's in-memory copy. This is SDK-layer UX wiring over part 1's provider; the protocol-level requirement is that creation does not complete (and the commitment is not published) until a §4 backend holds the key.

## Cross-language impact

This is a **breaking addition to the FFI surface** (a new callback interface), so it touches every callback-custody bridge and the SDKs that implement custody:

| Layer | Change |
|-------|--------|
| `scp-protocol` / `scp-platform` | `PreRotationCustody` trait already exists (`store_committed_pre_rotation_key` / `reveal_public_key` / `destroy_after_migration` / `custody_kind`) and is **not** renamed; add the `CallbackPreRotationCustody` adapter that implements it over the foreign provider, plus shared encrypted-offline / Shamir / BIP39 codecs. The FFI `import_seed_bytes` routes into the existing `store_committed_pre_rotation_key` (the adapter derives the public key from the seed) — no new trait method. |
| PyO3 (`crates/scp-ffi/src/`) | `PyPreRotationCustodyProvider` (`Py<PyAny>` adapter); thread it through `identity_create*` / `identity_migrate`; remove the `InMemoryPreRotationCustody` default on the callback path. |
| NAPI (`crates/scp-ffi/napi/src/`) | Threadsafe-function adapter for the provider record (`{ generate, publicKey, importSeedBytes, consume }`). |
| UniFFI (`crates/scp-ffi/uniffi/src/`) | New `[Trait, WithForeign]` interface; replace `generate_ephemeral_ed25519_seed` → in-memory routing; implement `import_ed25519_signing_key` via `import_seed_bytes` (removes the current `Unsupported` block). |
| Browser (thin client, ADR-055) | No in-browser custody substrate: a browser is a remote thin client to a server-side `scp-node`, so pre-rotation custody is held server-side by that node and governed by the node's platform (the PyO3/UniFFI/NAPI rows above), not in the browser. No browser-side change. |
| Swift / Kotlin SDKs | Implement `PreRotationCustodyProvider` against Keychain/Keystore/Secure Enclave/FIDO2; implement the §5 selection ceremony. |
| Python / TypeScript SDKs | Implement the cross-platform offline/Shamir/BIP39 backends for server and parity testing. |
| Capability matrix | New operations registered across bridges; `check-sdk-coverage` (now fail-closed) enforces parity. |

### Canonical method names (locked across bindings)

Per-binding casing of the four **FFI callback-interface** methods — these names are fixed and MUST NOT drift. The final column maps each FFI method to the **existing** Rust-core `PreRotationCustody` trait method it routes through (`crates/scp-platform/src/traits.rs`); the core trait keeps its current names and is **not** renamed by this ADR. Only `generate` has no core-trait counterpart — it is the one new capability this ADR adds.

| Concept | FFI method (canonical) | UniFFI (`[Trait, WithForeign]`) | NAPI (JS object field) | PyO3 (`Py<PyAny>` attribute) | Swift | Kotlin | Core trait method (`PreRotationCustody`) |
|---------|------------------------|-------------------------------|------------------------|------------------------------|-------|--------|------------------------------------------|
| generate in substrate | `generate` | `generate` | `generate` | `generate` | `generate()` | `generate()` | *(new — no counterpart)* |
| read public key | `public_key` | `public_key` | `publicKey` | `public_key` | `publicKey()` | `publicKey()` | `reveal_public_key` |
| import known seed | `import_seed_bytes` | `import_seed_bytes` | `importSeedBytes` | `import_seed_bytes` | `importSeedBytes()` | `importSeedBytes()` | `store_committed_pre_rotation_key` |
| destroy-and-export | `consume` | `consume` | `consume` | `consume` | `consume()` | `consume()` | `destroy_after_migration` |

The core trait's diagnostic-only `custody_kind()` method has no FFI-callback counterpart; the adapter reports a fixed `PreRotationCustodyKind` for callback custody.

The `CallbackPreRotationCustody` adapter derives its foreign-call names from the FFI columns of this table and dispatches each into the mapped core-trait method (right column); bridge aliases (`bridge-aliases.json`) must use the bridge-layer names in the NAPI/UniFFI columns.

## Consequences

- **Positive:** callback custody meets §9.7.4.1 §3-§6 end-to-end; a process-memory compromise no longer exposes the recovery backstop; callback-custody migration becomes reachable (closes the `import_ed25519_signing_key` block); the two-substrate model is enforced by the type system (separate provider), not by documentation.
- **Cost:** a new public FFI callback surface and per-platform keystore integrations — the largest single piece. The UX ceremony (§5) is real product work on mobile.
- **Risk:** key-handle lifecycle bugs across the FFI boundary are security-critical (a dropped/duplicated pre-rotation handle is a lost or leaked backstop). Mitigation: `Zeroizing` on all seed bytes at the boundary; a conformance test that a created identity's pre-rotation key is NOT recoverable from the operational custody provider; the existing partial-publish recovery handle (§9.7.4.1 "Partial-publish recovery", ADR-003) already covers migration interruption.
- **No migration burden:** SCP is pre-release with no deployed identities; the in-memory callback path is replaced outright (no back-compat shim), per the no-migration-pre-release stance.

## Alternatives considered

- **Keep `InMemoryPreRotationCustody` on the callback path (status quo).** Rejected: violates §9.7.4.1 §3 substrate isolation; the recovery backstop shares the operational substrate, defeating its purpose. The current code already flags this as not-yet-satisfied.
- **Add `generate_pre_rotation` / `import_seed_bytes` methods to the existing `KeyCustodyProvider`.** Rejected: §9.7.4.1 §3 explicitly forbids the pre-rotation key being "accessible through the same custody provider or authentication flow used for daily operations." A combined provider re-introduces exactly the coupling §3 prohibits. A separate interface enforces the boundary structurally.
- **Generate the pre-rotation seed bridge-side and hand it to the SDK to store.** Rejected for the generation step on hardware-backed platforms: §9.7.4.1 §1 requires on-device CSPRNG generation, and for HSM/Secure-Enclave backends the key MUST be generated *inside* the substrate and never marshalled as raw bytes. The provider's `generate()` keeps generation in the substrate. (Bridge-side `OsRng` generation remains acceptable only for the software/offline backends that inherently hold raw bytes.)
- **Defer to a tracking issue.** Rejected per CLAUDE.md ("never create tracking issues instead of doing the work"). This ADR is the design step; acceptance authorizes the implementation workstream.

## Amendment (2026-07-14): Recovery-authority residence — recommended for acceptance

This amendment does not delete or contradict the design above; it sharpens the security property the design must satisfy, resolves OQ2 and OQ3, and **recommends the ADR for acceptance**. The design is complete; acceptance takes effect on human sign-off, and the ADR remains **Proposed** until then. Provenance: the normative rule is authored spec-first as **§9.7.4.1 item 3a** in `../specs/09-security-model.md`; this ADR cites and realizes it, per the artifact-flow invariant. The rule is upstream; ADR-054 does not author it.

### The refinement: residence of the recovery authority, not the cipher

Call the **recovery authority** the minimal secret, key handle, or authorization capability sufficient to recover the pre-rotation private key. §3's adversary is one who has compromised **operational custody**. Substrate isolation is therefore a property of *where the recovery authority lives*, not of the cipher wrapped around the stored key:

- If the recovery authority is reachable from operational custody, the cipher gives **zero** protection against the §3 adversary — that adversary simply uses the reachable authority to decrypt. So §4's parameter checklist (AES-256-GCM, Argon2id, ≥128-bit entropy) does **not** by itself satisfy §3.
- Encrypted-offline backup **with an auto-generated passphrase** on a **non-interactive server** is **not** a valid standalone §3 backend: the auto-generated passphrase must be stored somewhere the unattended server can reach to decrypt, which is — by construction — reachable from operational custody. It is isomorphic to `InMemory`. It is §3-sound only if the passphrase / KEK itself resides in a §3-isolated substrate (e.g., KMS/HSM), in which case *that substrate* is the real backend.
- The load-bearing property is **principal-distinctness**, not human interaction. Migration is a rare, separately-authorized event, not a daily operation, so a non-interactive server **can** satisfy §3 if migration-time recovery is gated by an authorization principal **distinct** from the operational signing principal (e.g., a separate KMS role assumed only for migration; the operational path holds no grant to it). The fatal condition is "the daily operational auth flow can itself reach the pre-rotation key."

### Per-backend §3-soundness

Each §9.7.4.1 §4 backend, evaluated against the §3a residence rule. The full menu remains available; soundness is **per profile**.

| §4 backend | §3a-sound? | Condition / rationale |
|------------|-----------|-----------------------|
| KMS / HSM / cloud-vault (independent principal) | **Yes — canonical non-interactive-server answer** | IFF the recovery authority is under a principal distinct from the operational-custody principal and the operational grant set excludes use/decrypt of the pre-rotation key/KEK. This is the mandated floor for the server profile. |
| Platform-backed cloud key store (same platform account) | **No (same-principal)** | §3a-sound only when the recovery/account principal is DISTINCT from the operational platform account. A store recoverable through the SAME platform account the operational device is signed into is operationally-reachable — treat it as the independent-principal cloud-vault row only when the account is provably distinct. |
| FIDO2 / CTAP2 hardware key | **Yes (interactive)** | Requires user presence. On a non-interactive server it has no present human, so it collapses to the KMS row (an unattended service invoking it is just holding a reachable credential). |
| Secondary-device secure enclave | **Yes** | The second device is a separate trust domain; its compromise is independent of the operational host's. |
| Shamir 3-of-5 | **Conditional** | Sound only if ≥3 shares reside in domains independent of the operational blast radius. All shares local to the operational host = **unsound** (the §3 adversary gathers ≥3 and reconstructs). |
| BIP39 24-word mnemonic | **No (not a server backend)** | Human/paper artifact. Not a substrate an unattended server can hold §3a-soundly. Interactive/human-custody only. |
| Encrypted-offline backup (AES-256-GCM + Argon2id) | **Conditional / degenerate** | Sound only when the passphrase/KEK inherits KMS/HSM/second-device isolation, OR is user-supplied per-recovery and never persisted server-reachably (→ interactive by construction). With an auto-generated, server-reachable passphrase it is degenerate (= InMemory) and **non-conforming on the server profile**. |

### OQ2 resolved — per-profile floors (full menu retained)

Backends are **not** one-size-fits-all; the mandatory floor depends on the deployment profile, and the full §4 menu remains available per profile under the §3a residence rule:

- **Non-interactive server profile (Python / TypeScript / `scp-node`).** The floor MUST be an **independent-principal KMS/HSM/cloud-vault** backend. Encrypted-offline-auto-gen, a locally-held Shamir share set, and a server-readable BIP39 seed are **NOT** conforming floors here. If no independent-principal substrate is available, identity creation MUST **fail closed** — no fallback to co-located storage (§3a(a)).
- **Interactive-client profile.** Clients with a present human MAY use encrypted-offline with a **user-supplied per-recovery passphrase never persisted server-reachably** (§3a(b)), in addition to the hardware/enclave/cloud backends. FIDO2, Secure Enclave, StrongBox are all first-class here. The interactive-client floor is at least one §3a-conforming backend; if a platform offers none, creation fails closed.
- **Full menu, per profile.** The complete §4 menu — encrypted-offline, Secure Enclave, StrongBox, FIDO2/CTAP2, cloud vault, Shamir 3-of-5, BIP39 — and the §5 selection ceremony remain in scope. Each is offered on the profiles where the per-backend table above marks it §3a-sound; the SDK MUST NOT offer a non-conforming backend as a standalone floor on a profile where the table marks it unsound/degenerate.

This supersedes the "encrypted offline backup ... ≥128-bit auto-generated passphrase entropy" line in **Decision part 2 (Real SDK backends)** for the **Python/TypeScript server** rows: auto-generated-passphrase encrypted-offline is not a conforming server floor. It remains valid as an interactive-client backend with a user-supplied passphrase, and as a server backend only when its passphrase/KEK resides in an independent-principal substrate.

### OQ3 resolved — YES, a spec clause was required

§3's prose was insufficient: it constrained the custody-provider **object** ("MUST NOT be accessible through the same custody provider or authentication flow"), which a co-located encrypted-offline-auto-gen backend can satisfy at the object level while still placing the recovery **authority** within operational reach. The gap is the difference between constraining the provider object and constraining the secret's **residence**. The normative fix is **§9.7.4.1 item 3a (recovery-authority residence)**, added spec-first ahead of this amendment. This ADR cites §3a as its governing requirement; it does not restate the normative rule as its own invention.

### Strengthened conformance test (the PAIR)

The Risk-line conformance test ("a created identity's pre-rotation key is NOT recoverable from the operational custody provider") is strengthened from a single assertion to a **pair** that both MUST pass:

1. **Negative-reachability adversary test.** Hand the harness the **full operational surface**: every operational `KeyCustody` handle/key, and every artifact readable by the operational principal (config, environment, keychain/keystore entries, on-disk files) — plus every resource the operational principal can read, decrypt, or obtain via a remote API using its own credentials or IAM/role grants (KMS, Secrets Manager, cloud key vaults) — enumerated from the operational principal's **full grant set**, not only local artifacts — and any resource reachable by **assuming a role the operational principal is permitted to assume**, followed **transitively** through every key-wrapping / key-derivation link to the chain root — **plus** the publicly-stored encrypted-offline ciphertext. Assert the harness **CANNOT** reconstruct the 32-byte pre-rotation seed. The search MUST include *locating and using* any auto-generated passphrase from operational-reachable stores (so a co-located-passphrase encrypted-offline backend fails this test by construction).
2. **Principal-distinctness assertion.** Assert that the recovery-authority residence identifier (KMS key id / IAM role / keychain access-group / TPM policy handle) is **structurally distinct** from the operational principal, and that the operational grant set excludes **read, use, decrypt, or assume/delegate** over **every secret, key, KEK, or role in the recovery-authority derivation/wrapping chain** (the pre-rotation key, its KEK, each KEK up to the chain root, and any passphrase secret) — not merely the terminal pre-rotation KEK. For Shamir: assert **fewer than 3** shares are reachable from the operational blast radius.

The negative-reachability test replaces the weaker "not recoverable from the operational provider" phrasing everywhere it appears in the Consequences/Risk section below.

### At-rest caveat (added to Risk/Consequences)

§3a is an **at-rest / daily-operations** property. It cannot prevent the pre-rotation seed being live in operational process memory during an **authorized** migration: `consume()` by construction yields the plaintext seed, which is then imported as the new operational `#0` (ADR-003 §4b, §9.12). The Consequences claim "a process-memory compromise no longer exposes the recovery backstop" is therefore scoped to **at-rest / daily operations** — NOT the migration instant, during which the backstop is necessarily plaintext in operational memory for the duration of the rotation transaction. This is inherent to the reveal→import migration model and is out of scope for §3a to prevent; mitigation for the migration instant is the existing `Zeroizing` boundary discipline and the single-use handle invalidation (Decision part 1), which bound the exposure window to the migration transaction.

### Forward note — the shipped `InMemoryPreRotationCustody` default (design-authority level, not a code edit here)

The shipped `InMemoryPreRotationCustody` default (traits.rs doc-comment "default in production … until backends wired in") is, under §3a, a fail-closed VIOLATION on the server profile — not a tolerable degraded default. The pre-rotation realization slice MUST make it compiled-available-but-never-runtime-selected-as-a-server-floor (present-in-binary ≠ runtime-selectable; fail closed at runtime), reconciling with ADR-062's residue framing. This note records the design-authority consequence; it does not edit downstream code, which the realization slice owns.

## Open questions (for review)

> **Resolution status (Amendment 2026-07-14):** OQ1 resolved by ADR-055 (below). **OQ2 resolved** — per-profile floors; see the Amendment section. **OQ3 resolved YES** — §9.7.4.1 item 3a authored spec-first; see the Amendment section. All open questions are now resolved; the ADR is **Proposed, recommended for acceptance, awaiting human sign-off** (it moves to Accepted on sign-off).

1. **Browser scope (resolved by ADR-055).** Browser pre-rotation custody is out of scope for this ADR and is not a separate in-browser custody story: per ADR-055 the WASM bridge is removed and browser clients are remote thin clients to a server-side `scp-node`. A browser holds no pre-rotation key locally; its pre-rotation custody is the server-side `scp-node`'s custody (the PyO3/UniFFI/NAPI provider work in this ADR). There is no WebAuthn/passkey-PRF in-browser substrate to gate on.
2. **Backend minimum. — RESOLVED (Amendment 2026-07-14): per-profile floors.** Not a single floor for all SDKs. The non-interactive server profile (Python / TypeScript / `scp-node`) floor MUST be an independent-principal KMS/HSM/cloud-vault backend — encrypted-offline-auto-gen is NOT a conforming server floor (it is degenerate against the §3 adversary). Interactive clients MAY use encrypted-offline with a user-supplied per-recovery passphrase never persisted server-reachably, plus hardware/enclave/cloud backends. The full §4 menu and the §5 ceremony remain available per profile under the §9.7.4.1 item 3a residence rule. See the per-backend §3-soundness table in the Amendment section.
3. **Spec clause. — RESOLVED (Amendment 2026-07-14): YES.** §3's prose constrained the custody-provider object, not the recovery authority's residence, so it was insufficient. The normative rule is now **§9.7.4.1 item 3a (recovery-authority residence)**, authored spec-first ahead of this amendment per the artifact-flow invariant; this ADR cites and realizes it. See the Amendment section.
