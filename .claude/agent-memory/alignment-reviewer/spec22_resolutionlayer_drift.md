---
name: spec22-resolutionlayer-drift
description: Spec §22.11.3 uses DiscoveryContext/DiscoveryContextVerified but Rust core + TS + Python SDKs all use HandleRegistry/HandleRegistryVerified — spec is stale
metadata:
  type: project
---

Spec §22.11.3 (`.docs/specs/22-human-readable-addressing.md`) documents the
`ResolutionLayer` enum variant as **`DiscoveryContext`** and the `TrustLevel`
variant as **`DiscoveryContextVerified`** (the serde wire tags shown in the
spec tables at lines ~1026, ~1034, ~1044).

But every implementation uses **`HandleRegistry` / `HandleRegistryVerified`**:
- Rust core: `crates/scp-runtime/src/discovery/addressing.rs`
- TS SDK: `bindings/typescript/src/types.ts` (`HandleRegistryVerified`, layer `HandleRegistry`)
- Python SDK (added on branch fix/sdk-coverage-fail-closed-and-parity): `bindings/python/scp_sdk/discovery.py`

Spec 22 is internally inconsistent: 11 `DiscoveryContext` vs 5 `HandleRegistry`
occurrences — a partial rename that never completed. Code converged on
`HandleRegistry`; the spec lagged.

**Why:** A rename (DiscoveryContext → HandleRegistry) landed in code but the spec
was never fully updated. New discovery.py cites `§22.11.3` as authority for its
`HandleRegistry` literals — phantom provenance: it cites a section whose literal
type names contradict it.

**How to apply:** Per artifact-flow, fix spec §22 FIRST (rename DiscoveryContext
→ HandleRegistry throughout §22, or decide the canonical name and align code).
Any future discovery work citing §22.11.3 must resolve this drift. See
[[finding_runtime_eventlog_not_rfc6962]] for a similar code-vs-spec drift pattern.
