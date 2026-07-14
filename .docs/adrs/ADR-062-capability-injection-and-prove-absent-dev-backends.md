# ADR-062: Capability Injection — Real Backends and Test-Harness-Only Nullifiers

**Status:** Proposed (2026-07-14).

**Relates to / upstream basis:** The umbrella spec section **§17.17 — "Capability Selection Is Mandatory, Fails Closed, and Never Defaults"** (normative IDs **SCP-CAPSEL-8000/8001/8002** mandatory / fails-closed / never-default; **SCP-CAPSEL-8010/8011/8012** durability-only-vs-nullifier classification; **§17.17.3 / SCP-CAPSEL-8013** in-memory-DHT nullifier). Honest framing: §17.17 was authored on this branch alongside this ADR and §17.17.2 names ADR-062 as its realization — it is not an independently-pre-existing authority I am merely citing. Its force rests on its own argument (esp. §17.17.3's durability-vs-nullifier reasoning), not on age; this ADR realizes it and adds no exception to it. **ADR-054 (Pre-Rotation Key Custody — Substrate Isolation) is ACCEPTED (2026-07-14)** and is the design authority for the pre-rotation seam, the per-profile backend floors, and the §5 selection ceremony this ADR schedules; its normative rule lives spec-first as **§9.7.4.1 item 3a (recovery-authority residence)**. Also relates to: ADR-052 + `.docs/standards/construction.md` (M1–M5; **M2** @:59 required-or-fail-safe-defaulted, **M3** @:73 fail-loud-never-silent-no-op); ADR-048 (multi-instance FFI); ADR-049 (no `dyn`/lock on the lock-free-**read** hot path only); ADR-006 (in-memory adapters); ADR-025 (device-attestation backend — separate, unstarted; §Decision 3); ADR-055/-057 (browser thin-client; WASM removed). Spec §9.7.4.1 (Pre-Rotation Key Custody, incl. item 3a / §4 / §5 / §6), §9.12 (Migration & Recovery), §17.6/§17.7 (storage/BlobStore), §3.9/§3.10.3/§3.10.5/§3.10.6/§3.10.7/§3.10.10 (DHT resolution + Anti-Segmentation MUST).

**Motivating defects:** #627 (CLOSED, unmet — `production-dht` never enabled for PyO3/NAPI), #1518 (`ConcreteDidMethod` locks the shared FFI layer to `InMemoryDhtClient`), #1880 (rotation/migration publish through a fresh non-shared client that never reaches/invalidates the resolver). **#1733 (eliminate `scp_platform::testing` imports from production paths + CI enforcement) is FOLDED** and closed-as-folded at Slice 3 (§Folding #1733). Pre-rotation custody (E5) is **in scope** and built on the accepted ADR-054; there is no residue and no "future work" relabel.

## Context

SCP's provider capabilities each carry a "which implementation?" choice; a 2026-07 audit found several resolved to an **insecure in-memory arm reachable on the shipped path or offered as a runtime backend option**. Findings, descending severity:

- **E1 (HIGH) — DHT.** PyO3/NAPI ship `InMemoryDhtClient`; UniFFI ships real `PkarrDhtClient`. `production-dht` is on `uniffi/Cargo.toml` but not `scp-ffi/Cargo.toml`/`napi/Cargo.toml`. Chokepoints: `bridge_instance.rs:358` (`OnceLock<Arc<InMemoryDhtClient>>`), `server.rs:35` (`ConcreteDidMethod = DidDht<InMemoryDhtClient, SystemClock>`). #1880: rotation/migration mint a fresh non-shared client (`identity.rs:203-204`, `napi/identity.rs:246`, uniffi `make_dht_with_signer` `bridge.rs:~321`).
- **E2 (HIGH) — credentials.** `InMemoryCredentialStore` ("Not suitable for production," `credentials.rs:502-506`, `impl Default :556`) wired on shipped NAPI+PyO3 as a **hardcoded concrete type** (`napi/runtime.rs:313`).
- **E3 (MED) — blob storage.** `BlobStorageBackend::InMemory` un-`cfg`'d (`storage.rs:480`), `impl Default → in_memory()` (`:561`). Durability-only (a storage case).
- **E4 (MED) — relay querier.** `NoOpRelayQuerier` wired as relay-resolution.
- **E5 (HIGH) — pre-rotation custody.** `pre_rotation_custody: Arc<scp_platform::testing::InMemoryPreRotationCustody>` is an **ungated concrete field constructed on ~6 shipped create-path sites** (`scp-ffi/src/identity.rs:987`, `runtime.rs:1984`; `napi/src/identity.rs:1130`, `runtime.rs:1385`; `uniffi/src/bridge.rs:2467,9016,16716,20825,22590`), and `napi/Cargo.toml:55` pulls `scp-platform/testing` unconditionally to keep the type available. The pre-rotation key is SCP's recovery backstop (spec §9.7.4.1, §9.12); holding it in shared process memory violates §9.7.4.1 §3/§3a. Fixed by building the real backends per accepted ADR-054.
- **F1 (HIGH, the "other weld") — the `server` feature path.** `scp-ffi-common` `server = […, "scp-platform/testing"]` (`common/Cargo.toml:30`) is **unconditional**, and `server.rs` non-test code references `InMemoryKeyCustody`/`InMemoryStorage` (`:22` area), `IdentitySource<InMemoryKeyCustody>` phantoms (`:322`,`:435`), and `InMemoryDhtClient::new()` (`:455`). This is the same weld as E5 for the node-hosting artifact: severing the edge naïvely breaks the `server` build, tempting an executor to ship all nullifiers. `server.rs` + `common/Cargo.toml` MUST be enumerated in Slice 0 (storage path/feature) and Slice 6 (retype the phantoms to `FileKeyCustody`, drop the `testing` use).

**Root cause.** The FFI security switch that should select *primitives* is defined in terms of *use-cases*: `allow_in_memory_custody` (`scp-ffi:27`, `napi:15`, `uniffi:32` — already drifted) is a **runtime backend selector** that makes `FfiKeyCustody::InMemory` (`custody.rs:38`), in-memory attestation, and in-memory DHT runtime-selectable, and NAPI exposes a public `custody = "in_memory"` config value (`napi/src/scp.rs:379`). This treats an insecure nullifier as a legitimate menu option — the wrong model (§Ecosystem convention).

## Ecosystem convention (why this design)

Three-axis primary-source survey:
- **Axis 1 — test doubles are compile-time/test-code, not runtime options.** In-memory fakes live in a `*-test-util` dev-dep crate or a `testing`/`test-util` feature kept out of default/`full`, constructed in test code, absent from a normal build (idiomatic Rust; the shape `scp-testing`/`scp-platform/testing` already use).
- **Axis 2 — insecure custody/verifiers are never runtime-selectable; in-memory *storage* is a legitimate pluggable option.** `rustls` quarantines dangerous config behind a `danger` module; `webauthn-rs` gates insecure verification behind `danger-*`; OWASP "secure by default." Conversely **OpenMLS ships `MemoryStorage`** as a first-class pluggable provider — losing state is durability-only, not a nullification. This is §17.17's durability-vs-nullifier line.
- **Axis 3 — recovery custody is a pluggable backend menu.** Signal SVR, Apple ADP, passkey PRF expose recovery as a menu (HSM, cloud-HSM, device enclave, offline). ADR-054 specifies exactly this menu for pre-rotation custody and — post-acceptance — resolves the per-profile *floors* (server = independent-principal KMS/HSM; interactive = user-passphrase encrypted-offline + hardware).

## The split (execution units)

- **Unit 1 (clean, executable now, no upstream wait): Slice 0 (module structure) + Slice 1 (DHT E1).** Fixes the original E1 shipped-in-memory-DHT bug. Depends on nothing unsettled.
- **Unit 2 (built on accepted ADR-054): pre-rotation backends (per profile) + §5 ceremony + §6 re-selection (Slices 2–5) + nullifier severance (Slice 6).** ADR-054 is Accepted and §9.7.4.1 item 3a is authored spec-first, so Unit 2's upstream is settled.

## Decision

**Principle.** Every capability whose in-memory arm is a **security nullifier** (custody, device attestation, pre-rotation custody, DHT) is fixed by (1) shipping **real production backend(s)** behind a proper dispatch seam and (2) demoting the in-memory nullifier to a **test-harness-only** double — never runtime-selectable, provably absent from shipped artifacts (G1). A **durability-only** in-memory arm (storage, push, blob) stays a **legitimate explicit runtime option** in an honest module (§17.17 SCP-CAPSEL-8011). **The `allow_in_memory_*` runtime nullifier switch is deleted.**

### 0. Honest module structure + durability-only storage stays a runtime option (foundational)

Split `scp-platform`'s `pub mod testing` by truth: move `InMemoryStorage`/`InMemoryPush` to `scp-platform/src/in_memory/` behind `in-memory-storage`/`in-memory-push` features (compiled-available; the latter pulls `dep:uuid`), selected explicitly via `StorageConfig` (never default/fallback). Leave the nullifier doubles (`InMemoryKeyCustody`, `InMemoryDeviceAttestation`, `InMemoryPreRotationCustody`) in the `testing`-named module behind `testing`. Delete `pub use testing as software` (`lib.rs:52`). Delete `BridgeInMemoryStorage` (`bridge_runtime.rs:166` + `…Handle:275` + `…Repo:285` + `build_event_log_provider:315` third tuple element + the `common/src/lib.rs` re-export + the three bridge `runtime.rs` incl. `scp-ffi/src/runtime.rs:1112` + the `uniffi/Cargo.toml:63` comment); bridges use `EncryptingAdapter<scp_platform::in_memory::InMemoryStorage>` (the `EncryptingAdapter<S>` handle is generic, so the shape is preserved). **F1:** re-point `scp-ffi-common`'s `server` feature's `scp-platform/testing` edge to `scp-platform/in-memory-storage` and switch `server.rs`'s non-test storage construction to the `in_memory` path in this slice (the custody/DHT phantoms are retyped in Slice 6).

> **Module-naming note.** `in_memory/` houses only the durability-only types; the nullifier doubles stay in `testing/`. The durability-vs-nullifier split is therefore *not* inferable from module names alone (an `InMemoryStorage` under `in_memory/` and an `InMemoryKeyCustody` under `testing/`) — the classification lives in §17.17.2 and this ADR, and the module boundary encodes only "shippable vs test-only," which is the property that must be greppable for G1.

### 1. DHT (E1) — ship real Pkarr; in-memory DHT becomes test-harness-only

`production-dht` unconditional on `scp-ffi`/`napi`/`scp-ffi-common`. Shared `enum FfiDhtClient` in scp-ffi-common: a `Pkarr(PkarrDhtClient)` arm compiled unconditionally + an `InMemory(InMemoryDhtClient)` arm `#[cfg(any(test, feature = "testing"))]` — a **test-harness double, not a runtime option**. Retype `bridge_instance.rs:358` and `server.rs:35` onto `FfiDhtClient`; delete the throwaway clients so rotation/migration use the shared per-instance client (closes #1518/#1880, re-satisfies #627). `ClientDhtConfig { gateways }` + `DhtInitError`; **fail-closed** — unsatisfiable production DHT returns a typed error, never in-memory (M3).

> **scp-dht/testing (cross-crate).** `InMemoryDhtClient` (`dht_client/mod.rs:93`) is an ungated `pub struct` in an unconditionally-linked crate, and `#[cfg(test)]` does **not** cross crates. So gating it needs a **new `scp-dht/testing` feature** wired to the consuming crates' `[dev-dependencies]` (and `scp-node config.rs:1165` which also consumes it), not `cfg(test)`. Feature-absent ⇒ type-absent; G1 asserts `scp-dht/testing` absent from shipped graphs.

> **"Baseline" vs "select explicitly."** Calling Pkarr the "always-used baseline" is not in tension with §17.17.3's "select explicitly": DHT is Axis-A=1 (one real backend), so there is no runtime *backend* choice to make — only backend *parameters* (`ClientDhtConfig.gateways`) are caller-supplied. §17.17's mandatory-selection rule binds capabilities with ≥2 real backends (storage, blob); a single-real-backend capability is "selected" by being the only compiled arm, and its parameters are still explicit.

### 2. Key custody — real backends already ship; demote the in-memory arm to test-harness-only

`FfiKeyCustody` (`custody.rs:35`) already ships `File(FileKeyCustody)` (AES-256-GCM+Argon2id, §17.8) and `Callback(...)`, `SqliteKeyCustody` available; the `InMemory` variant is `#[cfg(feature="allow_in_memory_custody")]` — switch-gated, not welded. Demotion is clean: re-gate to `#[cfg(any(test, feature="testing"))]`, and **remove the public `custody="in_memory"` config value** + seed-import path (`napi/src/scp.rs:379`) from the shipped SDK surface. No real-backend work needed.

### 3. Device attestation — declines the capability (spec §9:187), not "Axis A = 0"

`InMemoryDeviceAttestation` is the only impl and is switch-gated (not welded). The authority for shipping *without* device attestation is the spec itself: **§9 (line ~187) states the absence of a device-attestation backend is an expected, conformant state** — this is a deliberate scoped decline, not an unbuilt "Axis A=0" gap that this ADR is papering over. Demote to `#[cfg(any(test, feature="testing"))]`; with the feature off, the operation returns a **typed `Err`** (the secure behavior already at `bridge.rs:3622`), never a silent attest-valid no-op. A real backend is ADR-025's separate, unstarted work; nothing here builds on it.

### 4. Pre-rotation custody (E5) — build the real per-profile backends now, per accepted ADR-054

ADR-054 is **Accepted**; §9.7.4.1 item 3a is the governing normative rule. This ADR **cites** ADR-054's resolved decisions (it does not re-decide them) and **schedules** the realization as explicit stories/gates (§Rollout). The realization:

**Seam (RPITIT → enum, mirroring `FfiKeyCustody`).** `PreRotationCustody` is RPITIT (`traits.rs:759/772/782`) → not object-safe → the seam is an **`enum FfiPreRotationCustody`**, NOT `Arc<dyn>`:

```rust
pub enum FfiPreRotationCustody {
    Callback(CallbackPreRotationCustody),   // ADR-054 §1 provider adapter (hardware/enclave/cloud via the FFI provider)
    IndependentPrincipal(KmsPreRotationCustody), // server floor: KMS/HSM/cloud-vault (§3a(a))
    EncryptedOffline(EncryptedOfflinePreRotationCustody), // interactive floor: user-passphrase (§3a(b))
    #[cfg(any(test, feature = "testing"))]
    InMemory(InMemoryPreRotationCustody),   // test-harness double only
}
```

The ADR's earlier "retype the field to CallbackPreRotationCustody" was wrong: a concrete `Arc<CallbackPreRotationCustody>` cannot hold the encrypted-offline or KMS backends, and it names the adapter, not a seam. **Retype all ~6 welded create-path sites** (E5 list) onto `FfiPreRotationCustody`. Add `PreRotationCustody` to the Dispatch-mechanism list (below).

**Per-profile floors (ADR-054 OQ2, spec §9.7.4.1 item 3a(a)/(b)) — cited, not re-decided:**
- **Non-interactive server (Python/TS/`scp-node`):** floor = **independent-principal KMS/HSM/cloud-vault** (`KmsPreRotationCustody`); the operational principal holds no read/use/decrypt/**assume/delegate** grant over the recovery authority or any KEK in its wrapping/derivation chain. **If no independent-principal substrate is configured, identity creation MUST fail closed** — no fallback to co-located storage (§3a(a)).
- **Interactive client:** floor = **encrypted-offline with a user-supplied per-recovery passphrase never persisted server-reachably** (§3a(b)), with a **minimum-strength check** on the passphrase (offline brute-force resistance against the published Argon2id params, since the ciphertext is adversary-visible), **plus** the hardware/enclave/cloud backends where the platform offers them.
- **Full §4 menu per profile** — encrypted-offline, Secure Enclave, StrongBox, FIDO2/CTAP2, cloud vault, Shamir 3-of-5, BIP39 — offered on the profiles where ADR-054's per-backend §3-soundness table marks each sound; **the SDK MUST NOT offer a non-conforming backend as a standalone floor on a profile where the table marks it unsound** (e.g. auto-gen encrypted-offline on a server).

**§5 selection ceremony + §6 re-selection (full scope, scheduled — NOT "future work").** §5 requires presenting custody options ordered by security, **filtered to §3a-conforming for the active profile**; the non-interactive-server branch replaces the plural human prompt with selection of an operator-configured independent-principal backend and **fails closed if none is configured**. §6 requires the post-migration key to re-enter §3a-conforming custody (re-run §5). **§5 plural-MUST assessment:** on the interactive profile the floor is "≥1 §3a-conforming backend," so a single-option menu is conformant only when the platform genuinely offers one conforming backend; where more exist (hardware + offline) they MUST be presented — the native-hardware backend stories (§Rollout 7–8) are what make the menu genuinely plural on those platforms, and are scheduled, not relabeled.

**Recovery-authority residence is the security property, not the cipher (§9.7.4.1 item 3a).** The encrypted-offline codec is pure/shared, so it **cannot structurally enforce** where the passphrase/KEK lives — residence is enforced at the backend/profile boundary (server floor = KMS principal; interactive = user-supplied, never persisted). The **conformance test is the negative-reachability adversary test** (ADR-054 §Strengthened conformance test): hand the harness the full operational surface (every operational `KeyCustody` handle/key, every artifact + remote resource readable/assumable by the operational principal, followed transitively through every wrapping/derivation link) **plus** the published ciphertext, and assert it **cannot** reconstruct the 32-byte seed. A co-located-passphrase backend fails this by construction. **Zeroize the derived AES key**, not only the seed bytes.

**`InMemoryPreRotationCustody` reconciliation (ADR-054 forward note).** It stays compiled-available (test-harness) but is **never runtime-selected as a server floor**: present-in-binary ≠ runtime-selectable, and selecting it on the server profile **fails closed at runtime** (§3a(a)). The `traits.rs` doc-comment "default in production … until backends wired in" is a §3a violation and MUST be fixed in the realization (the default is no longer InMemory).

### 5. Credentials (E2) — real durable backend + seam (later slice; severity-ordering argued)

`BridgeCredentialStore` is RPITIT → an enum seam (`FfiCredentialStore { Durable, #[cfg(any(test, feature="testing"))] InMemory }`), a real durable backend, delete `impl Default`. **Why E5 now, E2 later** (both are HIGH welded shipped nullifiers): E5 nullifies the identity *recovery backstop* — a compromise-recovery capability whose absence is unrecoverable and whose isolation is a spec MUST (§9.7.4.1 §3a); E2 nullifies *bridge-token durability* — RAM-only tokens are re-obtainable by re-authenticating, a bounded availability loss, not an unrecoverable security nullification. The ordering is a severity judgment, not a scope dodge; E2/E3/E4 are scheduled (§Rollout) and G1 tightens as each lands.

### 6. Delete the runtime nullifier switch; sever `testing` from shipped graphs; G1 (depends on 1–5)

Once no shipped path constructs a nullifier (DHT real §1, custody/attestation demoted §2/§3, pre-rotation real §4): **delete `allow_in_memory_custody` entirely** (feature defs, every `#[cfg]` site, scp-runtime doc-prose, CLAUDE.md clippy string, `ci.yml`/`release.yml` strings). Sever the unconditional `scp-platform/testing` edges (`scp-ffi/Cargo.toml:51`, `napi/Cargo.toml:55`, and **F1**: `scp-ffi-common` `server`) and `dep:scp-testing` into each bridge's `testing` feature / dev-deps. **F1 retype:** `server.rs`'s `IdentitySource<InMemoryKeyCustody>` phantoms (`:322`,`:435`) → `FileKeyCustody`, drop the `InMemoryDhtClient::new()` (`:455`) and the `testing` use. Add **G1**.

### Dispatch mechanism (per trait object-safety)
RPITIT traits — **not object-safe** — dispatch via a no-`Default` **enum** whose in-memory arm is `#[cfg(any(test, feature="testing"))]`: `scp_dht::DhtClient`, `KeyCustody`, **`PreRotationCustody`** (`traits.rs:759/772/782`), `Storage`, `BridgeCredentialStore`. Object-safe async-trait traits (`ContextPersistence`) → required non-`Option` `Arc<dyn Trait>`. ADR-049's ban is the lock-free-read hot path only; these are write/setup paths.

### Switch-dissolution corollary
With no runtime nullifier gate there is no `allow_in_memory_*` feature to name, mark `# DANGER`, single-source, or split 2-vs-5 — those debates dissolve. The remaining honest cargo features are positive capabilities: durability-only `in-memory-storage`/`in-memory-push`, and the pre-existing `testing` test-harness feature.

## Enforcement
- **G1 — prove-absence gate (`scripts/check-shipped-feature-graph.sh`).** For each shipped artifact, mirror its exact build invocation, derive the feature set from its own build config (never a hand-list), assert **provider features ⊆ an explicit per-artifact allowlist**. The nullifier-bearing test-harness features — `scp-platform/testing`, `scp-dht/testing`, `scp-testing` — MUST be absent from every shipped graph (run per artifact **including `--features server`**, which is F1's backstop); durability-only `in-memory-storage`/`in-memory-push` MAY be present. G1 tightens per slice (DHT at Slice 1; custody/attestation + pre-rotation at Slice 6). **Soundness invariant (must hold and be stated):** a bridge's `testing` feature (and any test-harness feature) MUST NOT define nullifier code reachable in a build that does *not* pull one of the three checked features — i.e. nullifier types are gated *only* behind the checked features, so feature-absence in the graph is equivalent to type-absence. If a nullifier could be reached without pulling a checked feature, G1's graph check would be unsound.
- **Semantic capability-matrix dimension** (`check-sdk-coverage.py`): record each binding's shipped backend per capability (DHT → Pkarr; custody → File/Sqlite/Callback; **pre-rotation → the real per-profile provider**). Slice 6 must also fix the **4 stale `allow_in_memory_custody` device-attestation strings** in `sdk-capability-matrix.json` (~:117-132) and Slice 2 must **add the pre-rotation-provider row** — the matrix is in those slices' `files[]` and grep ACs, `.json` included.
- **Not added:** no runtime nullifier switch; no `# DANGER` convention; no source/AST gate re-checking a type-system property.

## Folding #1733 (close as folded — at Slice 3/6, not Slice 0)
| #1733 goal | Disposition | Ships in |
|---|---|---|
| 1. Move software-only impls out of `testing/` | module rename storage/push → `in_memory/` | Slice 0 |
| 2. Delete `pub use testing as software;` | done | Slice 0 |
| 3. Test fixtures behind a `testing`-gated path / sibling crate | nullifier doubles `testing`-gated, reached only by test code | Slice 6 (severance completes it) |
| 4. CI enforcement (`check-no-testing-imports-in-prod.sh`) | superseded by **G1** (binary-layer absence > source-import grep) | Slice 6 |
| 5. Eliminate `BridgeInMemoryStorage` | done | Slice 0 |
| (row) `InMemoryPreRotationCustody` UNCONDITIONAL | resolved by the real backends (§4) | Slices 2–5 |

**#1733 is closed as folded at Slice 6** (the severance slice, where goal 3's fixture-gating and goal 4 = G1 complete) — not at Slice 0. Goals 1/2/5 (module rename, `as software` deletion, `BridgeInMemoryStorage`) land earlier at Slice 0, but the issue is not closed until the shipped-graph guarantee (G1) exists.

## Consequences
- **No *custody / attestation / pre-rotation / DHT* nullifier is reachable in a shipped artifact** — not by default, fallback, or runtime config. This scopes to the four capabilities *this* work closes; **E2 credentials, E3 blob, E4 relay-querier still ship their in-memory arms until their scheduled slices land** (disclosed; G1 tightens per slice — a posture note, not hidden residue).
- **The recovery backstop gets real §3a substrate isolation** (§4): a process-memory or operational-custody compromise no longer yields the pre-rotation key; callback-custody migration becomes reachable; the server profile fails closed without an independent-principal substrate.
- **In-memory storage stays usable** as an explicit honest runtime option (OpenMLS parity).
- **did:key / `scp-testing` chain severed by construction** (`scp-core/testing → scp-runtime/testing → scp-protocol/testing:47 → scp-did/testing`).
- **At-rest caveat (ADR-054):** the encrypted-offline ciphertext is adversary-visible by assumption; its confidentiality rests on passphrase/KEK residence, not the store.
- **Binary size/build time:** unconditional `production-dht` adds mainline+reqwest (rustls, pure Rust) to the bare PyO3 wheel + NAPI addon; a bare-production release job must exist so the graph is G1-checked.
- **No migration burden** (pre-release).

## Alternatives considered
- **Nullifiers runtime-selectable behind a well-named `allow_in_memory_nullifiers` switch — REJECTED** (Axis 2: insecure custody/verifier/resolver is never a runtime option; a well-named dangerous flag is still a shipped runtime path to a nullifier).
- **Document pre-rotation in-memory as a "backend-pending residue" + weaken SCP-CAPSEL-8012 — REJECTED and reverted** (the prior draft; it weakened a security MUST to fit a workaround). ADR-054 is accepted with real per-profile backends; build them.
- **`Arc<dyn>` for the RPITIT seams — rejected** (not object-safe; enum per Dispatch-mechanism).
- **`FfiPreRotationCustody = Arc<CallbackPreRotationCustody>` (name the adapter, not a seam) — rejected** (cannot hold the KMS/encrypted-offline/test arms).
- **In-memory *storage* test-harness-only too — rejected** (durability-only; removing it loses a legitimate dev option for no security gain).
- **Defer the pre-rotation menu / §5 ceremony to "future work" — REJECTED** (completeness is baseline; the backends + ceremony are scheduled stories/gates, not a relabel).

## Rollout — ordered slices (Unit 1 = 0,1; Unit 2 = 2–6 + SDK 7,8)
0. **Slice 0 — module structure (SCP-CAPINJECT-000, Unit 1).** storage/push → `in_memory/` + features; `testing` = union; delete `pub use testing as software`; delete `BridgeInMemoryStorage`; F1 storage-path re-point in `server`/`server.rs`; in-memory storage stays an explicit `StorageConfig` option.
1. **Slice 1 — DHT E1 (SCP-CAPINJECT-001, Unit 1).** `production-dht` unconditional; `FfiDhtClient` (Pkarr + `#[cfg(any(test,testing))]` InMemory; `scp-dht/testing` type-gate); `ClientDhtConfig`/`DhtInitError` fail-closed; chokepoint retype; delete throwaway clients; matrix DHT rows; ignored live-Mainline + release-selects-Pkarr assertion. Closes #1518/#1880, re-satisfies #627.
2. **Slice 2 — pre-rotation seam (SCP-CAPINJECT-002).** `PreRotationCustodyProvider` FFI interface (ADR-054 §1) + `CallbackPreRotationCustody` adapter + `enum FfiPreRotationCustody`; retype the ~6 sites; `bridge-aliases.json` for the per-binding-cased callback methods; matrix pre-rotation-provider row.
3. **Slice 3 — server floor (SCP-CAPINJECT-003).** `KmsPreRotationCustody` independent-principal backend (§3a(a)); server-profile creation fails closed with no configured substrate; negative-reachability conformance test; zeroize derived key.
4. **Slice 4 — interactive floor + cross-platform codecs (SCP-CAPINJECT-004).** `EncryptedOfflinePreRotationCustody` (user-supplied passphrase, min-strength check, §3a(b)) + Shamir 3-of-5 + BIP39 pure codecs; negative-reachability conformance test.
5. **Slice 5 — §5 selection ceremony + §6 re-selection (SCP-CAPINJECT-005).** Per-profile filtered menu; non-interactive-server branch (operator-configured, fail-closed); post-migration re-selection.
6. **Slice 6 — nullifier severance + delete switch + G1 (SCP-CAPINJECT-006).** Demote `FfiKeyCustody::InMemory` + `InMemoryDeviceAttestation`; remove public `custody="in_memory"`; delete `allow_in_memory_custody`; sever `testing`/`dep:scp-testing` (incl. F1 `server`/`server.rs` phantom retype); fix the 4 stale matrix strings; add G1. **#1733 closed-as-folded here.**
7–8. **Slices 7 (Swift) & 8 (Kotlin) — native hardware pre-rotation backends (SDK-layer, scheduled).** Implement `PreRotationCustodyProvider` against Secure Enclave / iCloud-Keychain-ADP / FIDO2 (Swift) and StrongBox / cloud-vault / FIDO2-CTAP2 (Kotlin); register into the §5 profile menu. These enrich the interactive menu beyond its encrypted-offline floor; the floor (Slice 4) does not wait on them.
- **E2 credentials, E3 blob, E4 relay-querier** — subsequent slices (§Decision 5; not yet storied).

## Non-goals / boundaries
WASM excluded (ADR-055/-057). No production device-attestation backend (ADR-025, separate). No `dyn` rewrite of RPITIT traits. **`NodeConfig.dht` keeps its `DhtMode::Memory` default (`config.rs:391`) — deliberate and unchanged:** a *node* publishing its address to the DHT discloses its network location, so the fail-safe direction is *no-publish* (M2), and a node that never publishes is still resolvable out-of-band; a *client* not publishing its DID document is a fail-**open** false-success (a retired key stays resolvable, §3.10.6/#1880), so the two surfaces have opposite fail-safe directions and the client fix (§1) does not touch the node default. No runtime nullifier switch.

## Provenance chain
§17.17 (co-authored this branch; force rests on §17.17.3) → ADR-054 **Accepted 2026-07-14** (§9.7.4.1 item 3a; per-profile floors; §5 ceremony; §Strengthened conformance test; forward note on InMemory default) + spec §9.7.4.1 item 3a/§4/§5/§6, §9 (~:187 attestation-absence-expected) → ADR-052 + construction.md M1–M5, ADR-048/049, ADR-006/025/055/057 → #627/#1518/#1880, #1733 (folded) → source anchors (origin/main): `scp-platform/src/lib.rs:46,52`, `src/testing/*`, `traits.rs:740` (`PreRotationCustody` trait; RPITIT `:759/772/782`); `scp-ffi/src/custody.rs:35,38`, `napi/src/scp.rs:379`; pre-rotation welds `scp-ffi/src/identity.rs:987`,`runtime.rs:1984`,`napi/src/identity.rs:1130`,`runtime.rs:1385`,`uniffi/src/bridge.rs:2467/9016/16716/20825/22590`; F1 `scp-ffi-common/Cargo.toml:30`,`server.rs:22/322/435/455`; `scp-ffi/Cargo.toml:27,51`,`napi:15,55`,`uniffi:32,63,66`; `scp-testing/Cargo.toml:20-25`,`scp-protocol/Cargo.toml:47`; `bridge_runtime.rs:166,275,285,315`; scp-dht `dht_client/mod.rs:93` (+ `scp-node config.rs:1165` consumer), `bridge_instance.rs:358`/`server.rs:35`; `device attest bridge.rs:3622`; CLAUDE.md clippy string + `.github/workflows/ci.yml`/`release.yml`; `sdk-capability-matrix.json` (~:117-132), `bridge-aliases.json`.

## Residual judgment calls
1. `DhtInitError` variant names + `ClientDhtConfig.gateways` spelling — PRD detail.
2. Whether the credential in-memory arm (Slice, §Decision 5) also becomes `testing`-only vs a durable-only enum — a per-Axis-C call when that slice is storied.
3. Exact `KmsPreRotationCustody` client surface (AWS KMS / GCP KMS / PKCS#11 HSM adapter shape) — Slice 3 detail; the §3a residence property is the invariant, the adapter is the mechanism.
4. Whether `in-memory-pre-rotation` warrants its own gate vs riding `testing` — it rides `testing` (test-harness-only; no runtime selection), which is sufficient for G1.
