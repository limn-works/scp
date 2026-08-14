---
name: event-log-merkle-and-canonical-hash
description: RFC 6962 Merkle construction in scp-event-log, the open canonical-hash weaknesses (no domain separators / length prefixes, two incompatible attestation forms), deterministic serialization, and the §8.4 AppBound/AppUnbound leaf encoding
metadata:
  type: project
---

# Merkle tree (event_log/)

- RFC 6962 domain separation: leaf = `SHA-256(0x00 || data)`, interior = `SHA-256(0x01 || left || right)`
- Consistent across tree.rs, proof.rs, checkpoint.rs, metrics.rs, phase2_integration.rs
- Odd-leaf handling: **PROMOTION — the odd node is carried unchanged to the next
  level, NOT hashed with itself** (`tree.rs:541-544` incremental, `:616-619` full
  rebuild). Corrected 2026-08-10; the earlier "hash-with-self" note was wrong.
- `hash_pair()` has THREE definitions: `tree.rs:640`, `checkpoint.rs:1120`,
  `pruning.rs:562`. `proof.rs:502` imports tree's. Also FOUR copies of
  `compute_root_from_leaves` (checkpoint.rs:1099, proof.rs:504,
  tiered_storage.rs:764, runtime tests). Divergence risk. (Verified @8b7cbe7f8.)
- `verify_inclusion` (`proof.rs:338`) **ignores `proof.leaf_index`** and does not
  constrain `path.len()` ⇒ the stated index is unauthenticated and an interior
  node can be presented as a leaf. Existing consumers are safe (they bind
  leaf_hash + a locally trusted root, e.g. `tiered_storage.rs:721-734`), but any
  adjacency/index-based predicate built on it is unsound. See
  [[absence-proof-decision-rescope]].
- `compute_event_canonical_hash()` + `event_type_tag()` duplicated in 5 files

# Canonical hash weaknesses (open findings, PR #76)

- No domain separators across hash functions (event, claim, attestation, checkpoint)
- No length prefixes on variable-length fields in concatenated hashes
- Attestation type uses `Debug` formatting (not stable for canonicalization)
- `serde_json::Value::to_string()` is not canonical across languages/versions
- **CRITICAL**: claiming.rs:267 uses `to_be_bytes` + SHA-256 prehash; trust/attestation.rs:431 uses `to_le_bytes` + raw bytes — INCOMPATIBLE attestation verification. Two canonical forms exist; must consolidate.

# Deterministic serialization

- nesting.rs: `BTreeSet` for `requires_approval_for` ensures sorted serde_json
- `content_hash()` returns `Result` for proper error propagation

# PR #2235 AppBound/AppUnbound event log (§8.4, reviewed 2026-08-03)

- `AppBoundPayload{app_did,app_name,app_version,capabilities:Vec<String>}` + `AppUnboundPayload{app_did}` in scp-event-log/payload.rs. Positional `rmp_serde::to_vec`, fixarray len 4/1, NO `skip_serializing_if` in ANY payload struct → no positional-array misalign hazard. SOUND.
- Sort fix (app_sandbox.rs:876 `capabilities.sort_unstable()` before `encode_payload`) SOUND + necessary: `HashSet<Capability>` iteration is process-randomized; sort makes leaf bytes deterministic. Encoding is ALL in Rust core `bind_app` — 3 bridges (pyo3 context.rs:6194, napi 5097, uniffi bridge.rs:15808) call the same shared `bind_app` ⇒ Merkle leaf byte-identical cross-language by construction. `sort_unstable` safe (equal strings indistinguishable); HashSet dedups. Leaf = `SHA-256(0x00 || rmp_serde(Event))`, `Event.payload` IS a field ⇒ sort load-bearing.
- Capabilities stored as `Capability::Display` strings (roles.rs:578: `"messages:read"`, `"custom:{name}"`, …). Now a wire-stable Merkle contract but Display carries NO "never change" warning (unlike payload structs). Display-string change → silent leaf divergence. INFO.
- `declaration_content_hash` (app_sandbox.rs:1040, SHA-256 over JCS canonical decl minus sig) is DEAD CODE — only its own tests use it; NOT anchored into the AppBound leaf. `AppBoundPayload` does not bind to the exact signed declaration (no hash/sig/min_role/scp_version/constraints). Spec §8.4.2 only requires "which apps bound + capabilities" (met). Recommend wiring the hash in OR removing it.
- was-bound gate is bridge-instance-local in-memory `bound_apps_registry` (uniffi bridge.rs:15891), NOT event-log-derived. Core `unbind_app` has NO was-bound check. Restart/multi-instance divergence → false CTX_2059 reject or AppUnbound-with-no-AppBound. Not a crypto break.
- WASM (4th binding) NOT shipped. If WASM later reimplements per ADR-034 it MUST replicate Display strings + sort + positional rmp exactly or roots diverge.
- No BLOCKER. Verdict: encoding/sort/leaf SOUND.
