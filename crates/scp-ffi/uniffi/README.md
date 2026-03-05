# scp-ffi-uniffi

UniFFI bridge crate that generates Swift and Kotlin bindings from a single Rust definition.

## What this crate does

This crate is the Rust half of the Swift and Kotlin SDKs. UniFFI proc-macros (`#[uniffi::export]`, `#[derive(uniffi::Record)]`, `#[derive(uniffi::Error)]`, `#[uniffi::export(callback_interface)]`) define the FFI surface. UniFFI's code generator reads these annotations and produces:

- **Swift**: `async` functions via `CheckedContinuation`, classes for opaque objects, structs for records, enums, `throws` for errors.
- **Kotlin**: `suspend` functions via coroutine integration, classes, data classes, enums, exceptions.

The generated bindings are consumed by the pure-language wrapper layers in `bindings/swift/` and `bindings/kotlin/`, which add idiomatic APIs (Swift actors/`AsyncSequence`, Kotlin `Flow`/extension functions). This crate stays thin -- no protocol logic, no idiomatic wrappers.

## Architecture

### Proc-macro primary, UDL minimal

All types and functions are defined via proc-macros in Rust source. The UDL file (`src/scp.udl`) contains only the namespace anchor (`namespace scp {};`) required by `uniffi::include_scaffolding!`. Callback interfaces are also defined via proc-macros (`#[uniffi::export(callback_interface)]`).

### Module structure

- **`lib.rs`** -- Crate root. Re-exports all bridge items to the crate namespace (required by UniFFI). Contains the tokio runtime (`OnceLock<Runtime>`), handle reference counting (`HANDLE_COUNT`), `scp_shutdown`, and callback interface trait definitions (`MessageListener`, `KeyCustodyProvider`, `StorageProvider`, `PushProvider`, `DeviceAttestationProvider`).
- **`bridge.rs`** -- All `#[uniffi::export]` function definitions, opaque object `impl` blocks, record/enum derive macros, `ScpError` definition, `From` conversions from scp-core errors, and bridge trait adapters (`BridgeDidResolver`, `BridgeRevocationChecker`, `BridgeProofResolver`, `BridgeNonceTracker`).
- **`runtime.rs`** -- Context runtime registry (`DashMap<String, ContextRuntime>`), `with_context` accessor, `register_context` / `remove_context`.
- **`src/bin/uniffi-bindgen.rs`** -- Thin binary that calls `uniffi::uniffi_bindgen_main()` for binding generation.
- **`build.rs`** -- Generates scaffolding from `src/scp.udl` at build time.

### Type categories (ADR-021)

| Category | Rust | Swift | Kotlin |
|----------|------|-------|--------|
| Opaque objects | `Arc<T>` with `#[uniffi::export]` impl blocks | Classes | Classes |
| Records | `#[derive(uniffi::Record)]` | Structs | Data classes |
| Enums | `#[derive(uniffi::Enum)]` | Enums | Enums |
| Errors | `#[derive(uniffi::Error)]` | `throws` | Exceptions |

Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) track their lifetime via a global atomic handle counter. `scp_shutdown` blocks until all handles are released or timeout expires, preventing use-after-free on runtime teardown.

### Async bridging

All I/O-bound functions are `async fn`. UniFFI generates the appropriate concurrency bridge (Swift `CheckedContinuation`, Kotlin coroutine suspension). A shared multi-threaded tokio runtime (`RUNTIME`) executes all futures. It is lazily initialized via `OnceLock` on first use; if initialization fails, the process aborts.

### Callback interfaces

Platform-specific behavior is injected from Swift/Kotlin into Rust via callback interfaces:

| Trait | Swift impl | Kotlin impl |
|-------|-----------|-------------|
| `KeyCustodyProvider` | Secure Enclave / Keychain | Android Keystore |
| `StorageProvider` | Core Data / Keychain | Room / SharedPreferences |
| `PushProvider` | APNs | FCM |
| `DeviceAttestationProvider` | App Attest | Play Integrity |
| `MessageListener` | `AsyncStream<Message>` | `Flow<Message>` |

All callbacks execute on Rust tokio threads, not the Swift/Kotlin main thread. Implementations must be `Send + Sync` and dispatch UI work explicitly (`MainActor.run` / `Dispatchers.Main`).

## Build

### Native library

```bash
cargo build -p scp-ffi-uniffi
```

Produces both `cdylib` (dynamic) and `staticlib` (static) outputs. The static library is used for iOS linking.

### XCFramework (Apple platforms)

The script `bindings/swift/build-xcframework.sh` handles the full pipeline:

1. Builds a host dylib (`aarch64-apple-darwin`) for uniffi-bindgen code generation.
2. Runs `uniffi-bindgen generate --library <dylib> --language swift` to produce Swift bindings and the C header.
3. Cross-compiles for all Apple targets (iOS device, iOS simulator arm64/x86_64, macOS arm64/x86_64).
4. Creates fat libraries via `lipo` for simulator and macOS.
5. Packages a three-slice XCFramework via `xcodebuild -create-xcframework`.

```bash
cd bindings/swift

# Full build (iOS + macOS, 5 targets)
./build-xcframework.sh

# Dev build (macOS arm64 only, fast iteration)
./build-xcframework.sh --dev
```

The XCFramework build is part of the CI build matrix. See `.github/workflows/build-matrix.yml`.

### Feature flags

| Feature | Effect | When to use |
|---------|--------|-------------|
| `allow_in_memory_custody` | Enables `InMemoryKeyCustody` from `scp-platform/testing`. Stores private keys in unprotected heap memory. | Testing, CLI, desktop. |

**Production mobile builds (iOS/Android) MUST NOT enable `allow_in_memory_custody`.** This feature gates the `"in_memory"` custody path in `identity_create`. Without it, requesting in-memory custody returns `ScpError::Identity` with code `SCP-IDENT-1008`. See ADR-006 and GitHub issue #88.

The feature is automatically available in dev-dependencies (the `[dev-dependencies]` section enables `scp-platform/testing`), so `cargo test` works without passing it explicitly. However, CI clippy runs with it enabled explicitly:

```bash
cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody
```

## Testing

```bash
# Unit and conformance tests (allow_in_memory_custody available via dev-deps)
cargo test -p scp-ffi-uniffi

# CI clippy (includes the feature flag for full coverage)
cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing
```

Tests cover: runtime initialization, handle reference counting, custody method parsing, error formatting, identity creation (with and without the feature flag), context creation, message subscription with mock listeners, and shutdown ordering.

No `DYLD_LIBRARY_PATH` workaround is needed for this crate (unlike `scp-ffi`, which links against Python).

## Adding new bindings

To expose a new Rust type or function to Swift and Kotlin:

1. **Define the type in `bridge.rs`.**
   - Opaque object: define a struct, add `#[uniffi::export]` on the `impl` block. Wrap inner state in `Arc`. Add `increment_handle_count()` in the constructor and `decrement_handle_count()` in `Drop`.
   - Record (value type): `#[derive(uniffi::Record)]` on a struct with public fields.
   - Enum: `#[derive(uniffi::Enum)]` on an enum.
   - Error variant: add a variant to `ScpError` and a corresponding `From<>` impl.
   - Function: `#[uniffi::export]` on a free `async fn` or sync `fn`.

2. **Re-export from `lib.rs`.** UniFFI discovers types at the crate root. Add the new item to the `pub use bridge::{...}` block in `lib.rs`.

3. **Build and generate.** `cargo build -p scp-ffi-uniffi` compiles the Rust. Then run uniffi-bindgen to regenerate Swift/Kotlin:
   ```bash
   cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate \
       --library target/aarch64-apple-darwin/release/libscp_ffi_uniffi.dylib \
       --language swift \
       --out-dir /tmp/uniffi-out
   ```

4. **Add idiomatic wrappers.** The generated bindings go into `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` (auto-copied by `build-xcframework.sh`). Write the idiomatic Swift/Kotlin wrapper in the appropriate module file (`bindings/swift/Sources/SCP/`, `bindings/kotlin/`).

5. **Do not edit generated files.** `ScpBindings.swift` and `ScpFFI.h` are generated artifacts. Changes go in the Rust source or the language wrapper layers.

## References

- ADR-021 (`.docs/adrs/phase-4.md`) -- Full bridge specification.
- ADR-006 (`.docs/adrs/phase-1.md`) -- Platform abstraction and key custody.
- `.docs/standards/sdk-common.md` -- Cross-SDK standards including FFI async bridging risks.
- `.docs/scaffold/swift.md` -- Swift SDK build blueprint.
