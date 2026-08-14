---
name: pr2235-app-bound-unbound-eventlog
description: PR #2235 feat/app-bound-unbound-event-log alignment review — §8.4 AppBound/AppUnbound durable appends across 3 bridges + 4 SDKs; ALIGNED w/ 2 WARNINGs (stale base, minor-version compat)
metadata:
  type: project
---

# PR #2235 feat/app-bound-unbound-event-log (branch HEAD f7392e538) — ALIGNED, 2 WARNING

Reviewed as alignment reviewer. Verdict: implementation matches §8.4 (05→08-products-and-apps spec) + ADR-011 (phase-2.md). Runtime `bind_app`/`unbind_app` in `crates/scp-runtime/src/context/app_sandbox.rs`.

**Why / provenance:** §8.4 "Capability Declaration Contract" lives in `.docs/specs/08-products-and-apps-in-the-graph.md` (NOT 05-contexts, which is 5.x-numbered — the task's "spec §8.4 in 05-contexts" pointer was wrong). §8.4.1 wire format + §8.4.2 SDK enforcement/auditability. Payload FIELD schema is grounded in ADR-011 `.docs/adrs/phase-2.md:868-869` (AppBound{app_did,app_name,app_version,capabilities}; AppUnbound{app_did}).

**STALE-BASE (WARNING, mirror of [[two-dot-diff-stale-base-trap]]):** branch is **18 commits BEHIND origin/main** (merge-base 83e3d2f29). `AppBoundPayload`/`AppUnboundPayload`/`EventType::AppBound`+`AppUnbound`/`MIN_PARITY=109` ALL already exist on main, IDENTICAL (`git diff origin/main branch -- payload.rs / lib.rs` == EMPTY). So the payload structs + EventType variants in the three-dot `main...branch` diff are stale-base NOISE — the branch's REAL net-new = runtime app_sandbox `bind_app`/`unbind_app` + FFI wiring (3 bridges) + 4 SDK wrappers + matrix entries + error codes CTX_2056-2059 + MIN_PARITY +2. `fn bind_app` count on main = 0 (confirms net-new). Two-dot `main..branch` renders main's 18 newer commits as phantom deletions (did_record.rs -845, relay_querier.rs -533, outlet_registration -964) — ignore. **Action: rebase onto main; MIN_PARITY comment narrates 106→109 streaming-saga bump that's ALREADY on main (main=109) — post-rebase it collapses to a clean +2→111.** 111 floor reachable (saga ops present in branch bridges).

**Minor-version compat (WARNING, real spec divergence):** §8.4.1 table says scp_version — "SDKs MUST support declarations with same MAJOR and any MINOR <= current"; validation step 1 "verify scp_version is compatible." `CapabilityDeclaration::validate_structure` (app_sandbox.rs ~343) checks only `decl_major != current_major` — a declaration targeting a FUTURE minor (e.g. 1.5 vs SDK 1.0) is silently ACCEPTED, authorizing capabilities against protocol semantics the SDK doesn't implement. Should reject minor > current.

**Confirmed-correct (positive):**
- CapabilityDeclaration struct fields EXACTLY match §8.4.1 wire format (scp_version, app_id, app_name, app_version, capabilities[CapabilityEntry], min_role, signature hex). JCS RFC-8785 canonical bytes via scp_protocol::jcs, Ed25519 verify against app_id DID.
- validate_declaration order = §8.4.1 steps 1-4: structural(incl version) → signature → ceiling+role all-or-nothing (OutletCallAll/OutletQueryAll wildcard shortcuts mirror roles.rs CapabilityCeiling::contains) → ScopedHandle.
- Error codes CONSISTENT across ALL 3 bridges: bind CeilingExceeded|InvalidDeclaration|SignatureVerificationFailed→2056, EventLogFailed→2057, _→2058; unbind not-bound→2059, EventLogFailed→2057, _→2059. Doc comments in error_codes.rs:379-385 match.
- Was-bound check present in ALL 3 bridges (PyO3 st.bound_apps, NAPI st.bound_apps, UniFFI bound_apps_registry) — runtime unbind_app is stateless (correctly), gate is at bridge where per-instance binding registry lives.
- capabilities.sort_unstable() before Merkle encode in bind_app + test `bind_app_payload_fields_match_scoped_handle` asserts sorted ("must be sorted for Merkle convergence").
- All 4 SDK wrappers REAL (python scp.py, ts scp.ts, kotlin Scp.kt appBind→NativeScp, swift Scp.swift appBind→inner). Matrix marks all 4 true.

**INFO:** (1) "tag 74/75" = 1-based taxonomy POSITION (AppBound is 74th of 77 in all_event_types), NOT a numeric wire tag — EventType serde-serializes as variant-NAME string; "tag" wording in matrix notes/comments slightly misleading but internally consistent. (2) §8.4.1 step 5 "stored in context's OUTLET registry" — impl stores ScopedHandle in bridge bound_apps + event-log append (§8.4.2 auditability); functionally satisfied, naming differs. (3) §8.4.2 rule 3 runtime call-site capability enforcement on ScopedHandle not added by this PR (ScopedHandle.allowed_capabilities exists; enforcement wiring separate scope). (4) actor_did+timestamp_secs caller-supplied to append (consistent w/ existing append_context_event_with_payload pattern).
