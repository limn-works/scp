---
name: pr2235-app-bind-unbind
description: Attack surfaces in PR #2235 §8.4 AppBound/AppUnbound durable event-log appends (app_sandbox.rs + 3 FFI bridges)
metadata:
  type: project
---

# PR #2235 — AppBound/AppUnbound (tags 74/75) attack surfaces

Files: `crates/scp-runtime/src/context/app_sandbox.rs` (bind_app L855, unbind_app L911),
PyO3 `crates/scp-ffi/src/context.rs` app_bind L6147 / app_unbind L6247,
NAPI `crates/scp-ffi/napi/src/context.rs` L5055/L5149,
UniFFI `crates/scp-ffi/uniffi/src/bridge.rs` L15724/L15870.

NOT findings (tracked): #2230 route-through-actor, #2231 persist declaration,
#2232 check_scoped_capability write-only, actor_did unauthenticated, declaration context-agnostic.

NEW findings I raised:
1. WARNING unbind_app has ZERO authorization — no capability gate at all (bind at least
   intersects role_caps; unbind checks nothing). Orthogonal to actor_did-auth; survives fixing it.
   Any actor can append valid AppUnbound + detach any app (e.g. a security monitor).
2. WARNING no "already-bound" guard on bind → repeated bind = multiple AppBound leaves,
   no intervening AppUnbound, registry HashMap silently overwrites. Capability rotation w/o
   audit-visible unbind. state.rs treats AppBound/AppUnbound as passthrough (no replay
   reconstruction) so log is append-only + unreconciled — divergence is permanent.
3. WARNING was-bound TOCTOU: is_bound check / async append / registry remove are 3 separate
   critical sections (lock dropped between). Concurrent unbind → duplicate AppUnbound leaves.
   Most acute in UniFFI (runtime().spawn on multithread rt, genuinely concurrent).
4. WARNING app_version NEVER length-validated (validate_structure skips it) + no declaration_json
   size cap at any bridge → self-signed publisher crafts huge app_version, copied verbatim into
   every durable AppBound leaf = storage/log amplification DoS, NOT capability-gated.
5. WARNING caller-supplied timestamp_secs unvalidated → backdate/postdate/collide bind/unbind
   leaves; undermines durable provenance/audit ordering.
6. WARNING stale ceiling snapshot for bind validation (UniFFI handle.ceiling_strings; PyO3/NAPI
   st.ceiling_strings, needs manual sync) → grant caps exceeding current lowered ceiling.
7. INFO min_role declared, validated non-empty, never enforced (decorative).
8. INFO Custom(format!("{category}:{action}")) from unbounded resource/action → unbounded leaf
   strings when in ceiling+role.
