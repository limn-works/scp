# Rust Standards

Rust coding standards, safety rules, linting, formatting, testing, and CI for the SCP core crates. For workspace layout, dependency map, and error type definitions, see `.docs/scaffold/rust.md`. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Rust edition | 2024 | Language edition (all crates) |
| rustc | stable (latest) | Compiler |
| cargo | stable (latest) | Build system, package manager |
| clippy | stable (latest) | Linter |
| rustfmt | stable (latest) | Formatter |
| cargo-deny | latest | Dependency license/advisory audit |
| cargo-nextest | latest | Test runner (parallel, better output) |

## Safety Rules

```rust
#![forbid(unsafe_code)]
```

Every crate sets `#![forbid(unsafe_code)]` at the crate root. Unsafe code is forbidden across the entire workspace. If an FFI bridge crate requires unsafe (e.g., cbindgen C ABI), it is the sole exception and must document every `unsafe` block with a `// SAFETY:` comment explaining the invariant.

Additional enforced rules:
- No `unwrap()` or `expect()` in library code — use `?` with typed errors
- No `panic!()` in library code — return `Result` instead
- No `println!()` — use `tracing` for all output
- No `std::sync::Mutex` — use `tokio::sync::Mutex` for async contexts
- No blocking I/O in async functions — use `tokio::fs`, `tokio::net`, etc.

## Error Types

Every crate defines errors via `thiserror`, following the hierarchy in `sdk-common.md`. See `.docs/scaffold/rust.md` for the full enum definition and variant structure.

## Clippy Configuration

`.clippy.toml` at workspace root:

```toml
cognitive-complexity-threshold = 25
```

`Cargo.toml` workspace-level lint configuration:

```toml
[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

## Rustfmt Configuration

`rustfmt.toml` at workspace root:

```toml
edition = "2024"
max_width = 100
tab_spaces = 4
use_field_init_shorthand = true
use_try_shorthand = true
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
```

## Testing

### Unit tests

- Tests live in `#[cfg(test)] mod tests { }` blocks within source files
- Use `proptest` for property-based testing on all crypto operations
- Use `tokio::test` for async test functions

### Integration tests

- Live in `tests/` directory at crate root
- One file per integration scenario
- Phase integration tests (see ADR phase documents) live in `tests/integration/`

### Property-based testing (proptest)

Required for:
- All crypto operations (MLS encrypt/decrypt roundtrip, signature verify, HKDF derivation)
- Envelope serialization/deserialization roundtrip
- Event log Merkle proof verification
- UCAN attenuation chain validation
- Bucket padding roundtrip

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    #[allow(clippy::unwrap_used)]  // proptest requires infallible runtime setup
    fn encrypt_decrypt_roundtrip(plaintext in any::<Vec<u8>>()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let group = create_test_group().await;
            let ciphertext = encrypt(&group, &plaintext).await.unwrap();
            let decrypted = decrypt(&group, &ciphertext).await.unwrap();
            prop_assert_eq!(plaintext, decrypted);
            Ok(())
        })?;
    }
}
```

### Test naming

```rust
#[test]
fn create_group_returns_group_with_one_member() { }

#[test]
fn encrypt_rejects_empty_plaintext() { }

#[test]
fn remove_member_advances_epoch() { }
```

Format: `{action}_{condition_or_expected_result}`.

## Async Patterns

- All I/O-bound operations are `async`
- Use `tokio::spawn` for concurrent tasks
- Use `tokio::select!` for racing futures
- Use `futures::StreamExt` for stream operations
- Cancellation safety: all async functions must be cancellation-safe or documented as not

## Documentation

- All public items have `///` doc comments
- Crate-level docs in `src/lib.rs` with `//!`
- Module-level docs in `mod.rs` with `//!`
- Examples in doc comments use ```` ```rust ```` blocks that compile (`cargo test --doc`)
- Cross-reference ADRs in doc comments: `/// See ADR-001 for MLS wrapper design.`

## CI Commands

```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Build (all crates)
cargo build --workspace

# Test (all crates)
cargo nextest run --workspace

# Doc tests
cargo test --workspace --doc

# Dependency audit
cargo deny check

# Generate docs
cargo doc --workspace --no-deps
```

## CI Matrix

| Job | Runs on | Trigger |
|-----|---------|---------|
| fmt | ubuntu-latest | Every PR |
| clippy | ubuntu-latest | Every PR |
| test | ubuntu-latest, macos-latest | Every PR |
| build-release | ubuntu-latest, macos-latest, windows-latest | Every PR |
| doc | ubuntu-latest | Every PR |
| deny | ubuntu-latest | Every PR, weekly |
| proptest (extended) | ubuntu-latest | Nightly, pre-release |
