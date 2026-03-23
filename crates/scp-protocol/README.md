# scp-protocol

Pure sync protocol types and logic for [SCP](https://github.com/limn-works/scp) (Shared Context Protocol).

This crate contains all protocol-level types, validation logic, governance engines,
trust evaluation, cryptographic primitives, and wire formats. It has **zero async
dependencies** and compiles for `wasm32-unknown-unknown`.

## Design constraints

- **No tokio, no async-trait, no scp-platform, no OpenMLS.**
- **Compiles for `wasm32-unknown-unknown`** — suitable for browser environments.
- Enforced by CI: tree-sitter async detection, dependency tree check, WASM compilation.

## Usage

Most consumers should depend on `scp-core` (the facade) rather than `scp-protocol`
directly. `scp-core` re-exports everything from both `scp-protocol` and `scp-runtime`.

Direct dependency on `scp-protocol` is appropriate for:
- WASM builds that cannot use tokio
- Libraries that only need protocol types (no runtime orchestration)

## License

Apache-2.0
