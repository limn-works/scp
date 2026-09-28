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

# Doc tests. The two cloud-blobs features compile the PostgreSQL blob backend,
# whose doctest no default feature compiles.
cargo test --workspace --doc --features scp-node/cloud-blobs,scp-relay/cloud-blobs
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

CI's `rust-clippy` job runs five `cargo clippy` commands. The first lints the workspace with the features that enable in-memory key custody and the test-only grants. The workspace sweep compiles scp-transport with only the features a workspace member's dependency declaration requests (`sqlite-blob`, `redb-blob` and `startup`), and leaves the optional network transports and the `postgres-blob` and `s3-blob` features off, so the other four lint the optional network transports and the PostgreSQL and S3 blob backends, which scp-node and scp-relay compile only under their off-by-default `cloud-blobs` feature. Run the commands that cover the crates your change touches; together they give CI parity:

```bash
cargo clippy --workspace --all-targets \
  --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/outlet-capability-test-grant,scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/outlet-capability-test-grant \
  -- -D warnings
cargo clippy -p scp-transport --features quic,http3,udp,coap --all-targets -- -D warnings
cargo clippy -p scp-transport --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --all-targets -- -D warnings
cargo clippy -p scp-node --features cloud-blobs,testing --all-targets -- -D warnings
cargo clippy -p scp-relay --features cloud-blobs --all-targets -- -D warnings
```

Production builds for iOS and Android must **never** enable `testing`.

## Lint and Format

Before pushing, run the rows for the languages your change touches, scoping the Rust lint to the crates the change touches. CI runs every row on the pushed head:

| Language | Format | Lint |
|----------|--------|------|
| Rust | `cargo fmt --all` | the `cargo clippy` commands in Feature Flags above |
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
