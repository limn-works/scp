---
name: adr055-canonical-context-id-resolver
description: ADR-055 Model A context-id keying — single resolver chokepoint; watch for context_id_to_bytes vs decode_canonical_context_id two-name redundancy
metadata:
  type: project
---

ADR-055 (Model A, #1924) fixed a double-hash bug: a context's canonical identity IS its 32-byte digest and the id STRING is `hex(digest)`, so keying crypto/event-log must DECODE the hex (recover the digest) for a real 64-hex id, NOT re-hash it. The fix routes ~77 keying sites in `crates/scp-runtime/src/context/` through a single resolver in `state.rs`: `if id is exactly 64 lowercase-hex { hex::decode } else { SHA-256(id) fallback }`. Synthetic ids (`"identity-private-state"`, `"standing-"+hex`, `"ctx-…"`) are never 64-hex so hash exactly as before — byte-identical, no behavior change.

**Why:** double-hash diverged from the raw digest the §6.2.4 cross-context tool saga compares `target_context_id` against on the wire; creation keyed crypto under `SHA-256(id)` while live `PerContextState.context_id` would key under the digest → every real-context send/receive misses the MLS group.

**How to apply:** The approach is convergent and sound (closed transformation, not a denylist) — NOT a BLOCKER. The standing simplification finding is the **two-name redundancy**: `context_id_to_bytes` is a one-line delegate to `decode_canonical_context_id` — behaviorally identical, yet call sites use both names interchangeably, implying a distinction that doesn't exist. If reviewing follow-up work in this area, push to collapse to ONE name (prefer `context_id_to_bytes` — established, minimal diff), calling the raw `scp_protocol::context::context_id_bytes` primitive directly only where synthetic-ness is the explicit point (e.g. supervisor PSK-rotation seal path). Also: per-call-site ADR-055 doc prose is over-duplicated — one authoritative explanation on the resolver + one-line pointers at call sites (the messaging_helpers.rs terse form) is the target. See [[project_commit12_helpers_logic_split]].
