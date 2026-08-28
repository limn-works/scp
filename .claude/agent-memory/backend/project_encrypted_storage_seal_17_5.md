---
name: project-encrypted-storage-seal-17-5
description: EncryptedStorage seal (spec §17.5 / ADR-052) — in-memory FFI front door sealed; start_node_local still unsealed pending a human storage-backend decision; ADR-052 §AC-9 structural test now actually exists as compile_fail,E0277 doctests
metadata:
  type: project
---

Spec `.docs/specs/17-persistence-and-storage.md` §17.5 says verbatim that
"production code (FFI bridges, application nodes, SDK wrappers) must NOT
enable" `allow_unencrypted_storage` (the feature that relaxes
`ProtocolRepository::new` from `S: EncryptedStorage` to `S: Storage` and
exposes `Node::start_for_testing`). It was violated on `main`.

Branch `fix/encrypted-storage-seal-inmemory` (3 commits off d1ebc5ab9):
- `c082c3d02` — `scp_ffi_common::server::start_node_in_memory` now wraps
  `InMemoryStorage` in `EncryptingAdapter` (fresh `OsRng` key) and builds via
  the production `Node::start`. `ApplicationNode::dev` moved to the same
  storage type (forced: it is the auto-generate arm, both arms must agree on
  `S`) and also switched to `Node::start`. New alias
  `scp_ffi_common::server::EncryptedInMemoryStorage`; `RunningNode::InMemory`
  carries it. `scp-ffi-common`'s `server` feature gained `dep:rand` +
  `scp-platform/encrypting`.
- `98236e904` — the ADR-052 §AC-9 structural test.
- `432fd408d` — removed the FALSE doc claim on `start_for_testing`.

**Why:** a doc comment asserting a security property that does not hold is a
false guarantee (worse than absence — absence is detectable). Same class as the
"no dev/test-only stand-ins in production" tenet.

**How to apply:**
- STILL UNSEALED on purpose: both `Node::start_for_testing` arms in
  `scp_ffi_common::server::start_node_local` (persistent file-backed front
  door, plaintext `FilesystemStorage`). Blocked on a HUMAN decision: SQLCipher
  `SqliteStorage` vs `EncryptingAdapter<FilesystemStorage>`, plus a coupled
  breaking `passphrase` API change across four SDK surfaces. Do not "just fix"
  it.
- The four bridge manifest edges (`crates/scp-ffi/common`, `crates/scp-ffi`,
  `crates/scp-ffi/napi`, `crates/scp-ffi/uniffi` → `scp-node` with
  `features = ["allow_unencrypted_storage"]`) can only be removed AFTER
  `start_node_local` is sealed — removing earlier breaks the build.
- ADR-052 (`.docs/adrs/phase-2.md` ~:1883) claimed a structural test existed
  when it did not. `crates/scp-node/tests/encrypted_storage_seal.rs` on main
  only proved `EncryptedStorage: Storage` (strictly weaker — says nothing about
  rejection). Treat ADR "additionally backed by X" clauses as unverified until
  grepped.

**Compile-fail harness (repo convention, no new dependency):** rustdoc
```compile_fail,E0277``` doctests. The repo already used them (scp-protocol
broadcast, scp-runtime supervisor) — do NOT add trybuild: unpinned toolchain
(no `rust-toolchain.toml`) makes committed `.stderr` fixtures drift, which is
the non-convergent-enforcement failure mode. Two rules learned:
1. Pin the error code (`compile_fail,E0277`) — a bare `compile_fail` passes for
   a typo.
2. Always pair with a POSITIVE control (identical call, storage wrapped in
   `EncryptingAdapter`) or the negative proves nothing. Put the control in an
   integration test too, because `cargo nextest` does NOT run doctests — only
   CI's `Rust / doc` job (`cargo test --workspace --doc`) does.

See [[feedback-worktree-absolute-path]], [[feedback-never-inline-git-stash]].
