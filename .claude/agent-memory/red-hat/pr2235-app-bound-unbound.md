---
name: pr2235-app-bound-unbound
description: Red-team findings for PR #2235 §8.4 AppBound/AppUnbound durable event-log appends (tags 74/75) across PyO3/UniFFI/NAPI
metadata:
  type: project
---

# PR #2235 feat/app-bound-unbound-event-log (assessed 2026-08-03)

§8.4 app bind/unbind durable appends. Core: `crates/scp-runtime/src/context/app_sandbox.rs` (`bind_app`/`unbind_app`). Bridges: pyo3 `scp-ffi/src/context.rs:app_bind/app_unbind`, napi `scp-ffi/napi/src/context.rs:app_bind_on/app_unbind_on`, uniffi `scp-ffi/uniffi/src/bridge.rs:15724/15870`.

**Why:** durable audit-log feature; enforcement handle (`ScopedHandle`) stored in in-memory `bound_apps` map.
**How to apply:** these findings are the red-team assessment; root causes below.

- **RED-2235-1 (BLOCKER): bound_apps never rehydrated from durable log.** Map is `HashMap::new()` (pyo3/napi per-context `FfiBridgeState`) / `DashMap::new()` (uniffi `bound_apps_registry`) — only ever populated by live `app_bind`. On restart: durable AppBound persists, map empty ⇒ (a) enforcement `ScopedHandle` gone, (b) `app_unbind` hits was-bound gate → CTX_2059 forever (durable AppUnbound can NEVER be recorded), (c) re-running app_bind appends duplicate AppBound (no dedup). Permanent durable/memory divergence.
- **RED-2235-2 (WARNING): was-bound check not atomic with durable append (TOCTOU).** All 3 bridges: read/is_bound in one lock scope, `block_on`/`await` durable append with NO lock held, then insert/remove in a separate lock scope. Concurrent unbinds both pass is_bound → two AppUnbound leaves for one bind. Concurrent bind+unbind: bind appends AppBound before inserting into map, so a racing unbind sees is_bound=false and rejects while the app is already durably bound. Realistic under free-threaded Python + uniffi async (spawn+await) concurrent tasks.
- **RED-2235-3 (WARNING): no replay protection on AppBound.** Signed declaration has NO nonce/expiry/context-binding in signed body; `timestamp_secs` is unsigned caller param. Captured declaration_json replayable indefinitely, timestamp forgeable, append path (`builder.rs:255 append_context_event_with_payload`→`append_event`) does no dedup/timestamp-bounds/monotonicity check.
- **RED-2235-4 (WARNING, chain): app_id self-asserted.** `verify()` checks sig against app_id's OWN key → attacker self-signs a decl with attacker-generated did:key. Signature = integrity only, NOT authorization. Real gate is `member_has_capability(actor_did,...)`; with tracked unauthenticated actor_did, attacker who knows any privileged member DID binds an arbitrary attacker-controlled app DID with that member's full caps, durably logged as authorized.
- **RED-2235-5 (INFO): no "may bind apps" capability gate.** Any member can bind an app up to own caps; no admin-only gate. Check spec §8.4 intent.
- **RED-2235-6 (INFO): AppBoundPayload omits declaration hash/signature/timestamp** (only app_did/name/version/capabilities). Durable log can't later prove which signed declaration authorized the bind.
- Bind/unbind bypass ContextActor + Class-S fail-closed persistence entirely (issue #2230 tracked). This is WHY 1&2 exist: no atomic "persist-then-ack" combinator around the map+log pair.
- Not findings (tracked): #2230 actor routing, #2231 durable CapabilityDeclaration, #2232 check_scoped_capability gap, actor_did unauthenticated, declaration context-agnostic.
