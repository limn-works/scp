---
name: project-uniffi-knowncontext-discovery-registration
description: FFI KnownContext discovery-registration parity — which context-standing-up ops register, and why import isn't unit-testable
metadata:
  type: project
---

Discovery `KnownContext` registration (relay-probe map for context discovery, SCP-213/ADR-015) lives at the **FFI bridge layer**, not the runtime: `CoreFields::register_known_context` in `crates/scp-ffi/common/src/bridge_instance.rs` (typed accessors: `has_known_context` / `known_context_count` / `all_known_contexts` / `known_contexts_for_member` / `remove_known_context`; cap `MAX_KNOWN_CONTEXTS = 10_000`, LRU-evicts by `last_seen`).

**Reference (PyO3) registers on exactly two ops: `context_create` + `context_join_from_welcome`.** NOT plain `context_join`, NOT `context_import`. Verified at `crates/scp-ffi/src/context.rs` (only two `register_known_context_on` callsites: create ~2112, welcome ~2527).

Field mapping (mirror across bridges): `routing_id` = the op's derived §9.10.4 pseudonym; for BROADCAST (no per-member pseudonym) fall back to `scp_core::context::broadcast_routing_id(ctx)` else `context_routing_id(ctx)` (both re-exported from scp-protocol). `relay_url` = **None on UniFFI** — the connected relay lives on the caller-held opaque `TransportManager` handle, not queryable from `CoreFields` inside create/join/import (the handleless `transport_manager_status` documents this and always returns None). `member_did` = local identity DID. `last_seen` = `scp_primitives::Clock::now_secs(&SystemClock)`. Post-commit + infallible (no rollback).

**Why:** commit a6b014a3b (branch feat/adr049-2j-ffi-slice) closed a UniFFI gap: welcome-join registered but `context_create` didn't → created contexts invisible to discovery. Fixed create (now matches PyO3) + added plain `context_join` (additive, coordinator-directed, tested via creator-rejoin).

**How to apply:** `context_import` registration was investigated and LEFT OUT: its success path is **not reachable in the bridge unit-test harness** — same-instance import fails `SCP-CTX-2001` ("context already exists") before the registration line; cross-instance import is blocked because reusing the importer `Arc<Identity>` on a second `Scp` fails handle-affinity. Reference PyO3 also omits import. Don't add import registration without an E2E harness or a coordinated all-bridge change. If cross-bridge parity on join/import discovery is ever wanted, do it in PyO3 + NAPI + UniFFI together, not UniFFI-alone (divergence). See [[feedback-read-tool-stale-verify-with-awk]] — this file's Read tool was ~150 lines desynced from disk; all edits done via python heredoc + `assert count==1` + git-diff proof.
