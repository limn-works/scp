---
name: node-builder-typestate-vs-flat-config
description: ApplicationNodeBuilder typestate design, EncryptedStorage seal, RPITIT object-safety wall, and the flat-config-object proposal stress-test
metadata:
  type: project
---

Stress-test of decision to replace SCP construction idioms (typestate `ApplicationNodeBuilder`) with ONE flat config-object pattern, motivated by "LLM is the primary SDK consumer."

**Why:** User decided to do this; review's job was to surface what breaks/regresses, not rubber-stamp.
**How to apply:** When reviewing any "unify construction" / "flatten the builder" / "one config object everywhere" proposal for scp-node, scp-transport, or FFI bridges, pull these facts first.

## Load-bearing code facts (verified 2026-06-14, crates/scp-node/src/lib.rs)

- `ApplicationNodeBuilder<K: KeyCustody, D: DidMethod, S: Storage, Dom, Id>` — 5 type params, last two are PhantomData typestate markers (`NoDomain`/`HasDomain`/`HasNoDomain`, `NoIdentity`/`HasIdentity`). lib.rs ~2473.
- Typestate makes 3 illegal states unrepresentable: (1) build without domain XOR no_domain selected; (2) build without identity; (3) `build()` requires `S: EncryptedStorage`.
- `build()` (lib.rs ~3142) is `impl ... S: EncryptedStorage` → production path. `build_for_testing()` (~3168, ~4128) is `#[cfg(any(test, feature="allow_unencrypted_storage"))]` + `S: Storage` → test path. Two separate `build()` impls: one for HasDomain (~3142), one for HasNoDomain (~4106).
- `EncryptedStorage` (crates/scp-platform/src/encrypted.rs) is a SEALED marker trait (`private::Sealed`). Only `SqliteStorage`, `AppleStorage`, and `EncryptingAdapter<_>` implement it. External crates can require but NOT implement → compiler-enforced encryption-at-rest invariant (issue #695, spec §17.5). This is the production security property.

## The object-safety wall (decisive constraint)

- `KeyCustody` (scp-platform/src/traits.rs:324), `Storage` (traits.rs:853), `DidMethod` (scp-identity/src/lib.rs:366) ALL use `-> impl Future<...> + Send` (RPITIT / native async-fn-in-trait). They are **NOT object-safe / not dyn-compatible**. `Arc<dyn KeyCustody>` / `Arc<dyn Storage>` / `Arc<dyn DidMethod>` DO NOT COMPILE.
- The codebase ALREADY hit this wall and solved it with per-bridge ENUM DISPATCH, documented in 5+ places:
  - PyO3: `StorageProvider` enum, `InMemoryKeyCustody` concrete (scp-ffi/CLAUDE.md, src/custody.rs:33)
  - UniFFI: `KeyCustodyProvider` enum / `Box<dyn KeyCustodyProvider>` shim (uniffi/src/bridge.rs:781)
  - NAPI: custody enum (napi/src/custody.rs:4, runtime.rs:1276)
  - common server: enum, not `dyn Storage` (common/src/server.rs:457)
  - ProtocolRepository<S> is generic, not `Arc<dyn Storage>` (store/mod.rs:176)
- Consequence: a single FFI-shared flat config CANNOT carry these as trait objects. Flattening across the FFI boundary forces either (a) keep per-bridge enum dispatch (already exists), or (b) box behind NEW object-safe wrapper traits (async-trait/Box<dyn Future>) — which would touch hot paths and collide with the ADR-049 lock-free-read / no-Box-on-read-path posture.

## The flat-config pattern ALREADY EXISTS

- `HostSiteOptions` (scp-node/src/self_host.rs:706) is exactly the proposed flat named-field config: `Default`, all-public fields, runtime-validated, NO generics exposed, NO typestate. It wraps the typestate builder internally (`build_host_site_node` at :1656 calls `ApplicationNodeBuilder::new()...build()`).
- `RelayConfig` (scp-transport/src/native/server.rs:58) is also already a flat `Default` struct, no generics, no typestate.
- So the right architecture is the EXISTING two-layer split: flat config = high-level LLM-facing entry point; typestate builder = internal Rust-embedder construction kernel that the flat layer drives. The proposal to DELETE the typestate kernel is the risky part, not adding flat configs.

## Verdict shape
- SOUND: add/standardize flat config objects as the LLM-facing entry surface (HostSiteOptions is the template).
- PUSH BACK: deleting the typestate builder kernel. It converts 3 compile-time guarantees to runtime errors, and the EncryptedStorage seal is the only mechanical (non-doc) enforcement of production encryption-at-rest. A flat `enum StorageChoice` can preserve it ONLY if construction rejects unencrypted variants at runtime on the production path — strictly weaker than the seal.
- EXEMPT from config-object: provider/capability injection (KeyCustody/DidMethod/Storage) — these are trait-DI by architecture and can't be FFI-flattened anyway (object-safety). Boundary = "construction entry point → config object" vs "capability → trait injection (stays typed/enum-dispatched)".
