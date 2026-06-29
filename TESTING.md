# Testing

## Quick Start

```bash
./scripts/test.sh          # all languages
./scripts/test.sh rust     # just Rust
```

## Per-Language Commands

### Rust

```bash
# Unit + integration tests (prefers cargo-nextest if installed)
cargo nextest run --workspace
# or
cargo test --workspace

# Doc tests
cargo test --workspace --doc
```

**Required environment variable** (macOS): scp-ffi links against libpython at test time.

```bash
export DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
```

On Linux, set `LD_LIBRARY_PATH` instead. The `scripts/test.sh` runner handles this automatically.

### Python

```bash
cd bindings/python
PYTHONPATH=. python3.12 -m pytest tests/ -v
```

Requires `maturin develop --release` first to build the native extension.

### TypeScript

```bash
cd bindings/typescript
bun install
bun test
```

### Kotlin

```bash
cd bindings/kotlin
eval "$(mise env)"    # sets JAVA_HOME
./gradlew test
```

### Swift

```bash
cd bindings/swift
swift test
```

Requires Swift 6.2. macOS ships 6.1 -- install 6.2 via [swift.org](https://swift.org/download/) or use `swift-actions/setup-swift@v2` in CI.

## Feature Flags

CI runs clippy and tests with four feature flags that enable in-memory key custody for testing. Always use these locally for CI parity:

```bash
cargo clippy --workspace --all-targets \
  --features scp-ffi-uniffi/allow_in_memory_custody,scp-ffi/allow_in_memory_custody,scp-ffi-napi/allow_in_memory_custody,scp-core/testing \
  -- -D warnings
```

Production builds for iOS and Android must **never** enable `allow_in_memory_custody`.

## Lint and Format

Run all checks before pushing -- CI enforces these:

| Language | Format | Lint |
|----------|--------|------|
| Rust | `cargo fmt --all` | `cargo clippy --workspace --all-targets --features ...` (see above) |
| Python | `python3.12 -m ruff format .` | `python3.12 -m ruff check .` |
| TypeScript | `bun run format` | `bun run lint` + `bun run check` |
| Kotlin | (auto via ktlint) | `./gradlew detekt` |
| Swift | `swiftformat .` | `swiftlint --strict` |

## Error Codes

```bash
bash scripts/check-error-codes.sh
```

Validates that all error codes follow the `SCP-{CATEGORY}-{NUMBER}` format with canonical prefixes defined in `.docs/standards/sdk-common.md`.

## Conformance Testing

The `scp-testing` crate provides conformance macros that validate trait implementations against the protocol contract:

- `storage_conformance!()` -- platform storage backends
- `blob_store_conformance!()` -- blob storage implementations
- `payment_adapter_conformance!()` -- payment adapter implementations

Integration tests live in `crates/scp-testing/tests/integration/`.

## CI Matrix

| Language | Platforms | Checks |
|----------|-----------|--------|
| Rust | ubuntu, macOS | fmt, clippy, nextest, doc tests, cargo-deny |
| Python | ubuntu | ruff format, ruff check, pytest |
| TypeScript | ubuntu | tsc, biome, bun test |
| Kotlin | ubuntu | ktlint, detekt, assembleRelease |
| Swift | macOS | swiftlint, swiftformat, build, test |
