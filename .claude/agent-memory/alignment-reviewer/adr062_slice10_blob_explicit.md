---
name: adr062-slice10-blob-explicit
description: ADR-062 Slice 10 (SCP-CAPINJECT-010) blob-backend explicit-selection review @ a2a9a03b5 — ALIGNED, 0 findings
metadata:
  type: project
---

# SCP-CAPINJECT-010 / ADR-062 Slice 10 (E3 blob) @ `a2a9a03b5` — ALIGNED

Branch `feat/adr062-slice10-blob-explicit`, diff `origin/main...` (15 files +235/-63). Verdict ALIGNED, 0 divergences.

**Why:** Deletes `impl Default for BlobStorageBackend` (was a LIVE SCP-CAPSEL-8011 violation: runtime silently manufacturing the durability-only dev arm the operator never chose). Makes blob backend a required non-`Option` `NodeConfig::blob_storage` field + required 4th arg to `NodeConfig::defaults(reach, identity, storage, blob_storage)`.

**How to apply / verified facts (if re-reviewing later slices in this PRD):**
- AC greps all pass: `impl Default for BlobStorageBackend`=0, `fn default.*in_memory|BlobStorageBackend::default`=0 repo-wide, config.rs `unwrap_or_default`=0.
- Point 2 (durability-vs-nullifier) CORRECTLY applied: `InMemory(InMemoryBlobStorage)` variant at storage.rs:482 stays UN-`cfg`-gated, explicitly selectable via `in_memory()`. Coder did NOT over-apply the `#[cfg(feature="testing")]` nullifier-severance rule (that rule is Slice 6, for custody/attestation/DHT/pre-rotation ONLY — blob is classified durability-only in ADR table + §17.17.2).
- Point 4 (node-binary fix) SANCTIONED: `main.rs run_node_with` full-node path previously left `blob_storage:None`→`unwrap_or_default()`→silent in-memory (the violation). Now calls pre-existing `scp_transport::startup::storage_from_env()` (unchanged, NOT in diff) — same fn relay-only mode already used (main.rs:279). Defaults to durable SQLite; `memory` reachable only via explicit `SCP_RELAY_STORAGE_BACKEND=memory` w/ loud warn; unknown/open-err → `process::exit`. Fail-closed, matches §17.17.1 SCP-CAPSEL-8000/8001/8002. Legitimate operator config-default (explicit binary-boundary choice), not runtime-manufactured default.
- validate-prd passes (13 files, 370 stories) → AC5 ✓. AC4 (full workspace test) not independently run; changes are mechanical arg-threading.
- Observation only: diff touches more files than story `files` list (server.rs, main.rs, lib.rs, dev_api.rs, http.rs, dns_provider.rs, tests) — necessary fallout of removing the Option default (every caller must pass the arg); not a divergence. `dev()` (lib.rs:1556) hardcodes `in_memory()` = named dev affordance = legitimate explicit selection.
