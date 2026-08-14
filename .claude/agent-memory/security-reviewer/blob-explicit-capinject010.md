---
name: blob-explicit-capinject010
description: SCP-CAPINJECT-010 blob backend made required explicit selection; storage_from_env fail-closed verification
metadata:
  type: project
---

# SCP-CAPINJECT-010 / ADR-062 slice10 — Blob backend explicit selection (feat/adr062-slice10-blob-explicit, a2a9a03b5)

Reviewed 2026-07-17. VERDICT: fails closed correctly, no findings.

- Deleted `impl Default for BlobStorageBackend` (scp-transport native/storage.rs). Enum now has NO Default. InMemory arm only via explicit `in_memory()`/`in_memory_with_capacity()`.
- `NodeConfig.blob_storage` changed `Option<BlobStorageBackend>` -> non-Option required field. `defaults()` takes it as required arg. Type system now enforces explicit selection at every construction site (omission = compile error). Removed two `blob_storage_opt.unwrap_or_default()` in build_node_domain/no_domain.
- **Prod full-node binary main.rs** previously silently defaulted to IN-MEMORY (SCP-CAPSEL-8011 durability violation on a shipped artifact). Now calls `startup::storage_from_env().await` — same as relay-only mode.
- `scp_transport::startup::storage_from_env` (startup.rs:103): default backend = **sqlite (durable)**. ALL misconfig paths `std::process::exit(1)`: sqlite/redb open failure, postgres missing SCP_RELAY_DATABASE_URL, s3 missing SCP_RELAY_S3_BUCKET, unknown backend name. `memory` reachable ONLY via explicit `SCP_RELAY_STORAGE_BACKEND=memory` (logs warn). NO silent degrade to in-memory anywhere.
- Backend arms feature-gated (`sqlite-blob` etc). scp-node Cargo.toml enables all four durable features, so default sqlite IS compiled. If a durable feature were absent, its arm falls to `other =>` catch-all → exit(1) (still fail-closed, never in-memory).
- self_host.rs build_host_site_node: opens SQLite blob store, `.map_err(...)?` fail-closed. FFI common/src/server.rs start_node_local threads durable redb; start_node_in_memory explicitly selects in_memory (honest dev front door).
- Path handling: SCP_RELAY_STORAGE_PATH is operator's own filesystem path (self-trusted config), no injection surface; constructor Result propagated.
- Durability-only capability: blob loss nullifies NO security property, so bar was "no silent degrade to in-memory" — MET.
