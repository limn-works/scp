# Phase 2E — OwnedIdentityDid → ActorDeps + gate strengthening (worktree saga-2e, HEAD 6619631ca)

2026-06-16. SECURITY-CLEAN. Gate change = NET STRENGTHENING. One MEDIUM (stale doc in pre-existing handle.rs), one Observation.

## The capability model (ADR-049 §5)
`OwnedIdentityDid` = unforgeable token proving an actor owns a given identity (cross-identity isolation boundary). Lives at `crates/scp-runtime/src/context/supervisor/identity_capability.rs`. Unforgeability rides on TWO compile-time facts, NOT on struct name-visibility:
1. `issue_for_actor(DID)->Self` is `pub(super)` (only supervisor-module code mints from a raw DID).
2. single field `did` is PRIVATE (no struct-literal outside module).
Phase 2E widened struct name-visibility `pub(super)`→`pub(in crate::context)` and module `mod`→`pub(in crate::context) mod` so `ActorDeps` (in sibling `crate::context::actor`) can hold it by-value and `SupervisorHandle` methods take `&OwnedIdentityDid`. Added `reissue(&self)->Self` (`pub(in crate::context)`) for `ActorDeps::clone_for_spawn` — clones held DID, takes NO `DID` param, strictly weaker than mint. `as_did()->&DID` is `pub` (read-only, safe; no `From<&DID>`, no reconstruct).

## Gate change verdict: STRENGTHENING (verified)
Old gate (origin/main) had NO constructor inspection — relied SOLELY on struct-vis `pub(super)` as a PROXY for the mint guarantee (`_scan_root` returned only `(decls, impls)`; no `issue_for_actor`/`reissue`).
New gate asserts the REAL guarantee DIRECTLY: G.1 `issue_for_actor` must be `pub(super)`; G.2 it must EXIST (refuses gutted/renamed type); G.3 if `reissue` exists it must take `&self` + NO raw-DID param (no 2nd mint path). Plus B (struct `pub(in crate::context)` exactly — rejects `pub`/`pub(crate)`), and retained C/D/E/F (derives/manual-impls/public-fields/type-alias).
Net: new gate catches EVERYTHING old caught EXCEPT old's literal `pub(super)`-struct assertion (which is now CORRECTLY relaxed because the struct legitimately must be wider) — and ADDS the direct mint-constructor assertions the old gate only had by proxy. No bypass shape regressed: a forged-token attempt via struct-literal=blocked by E(private field)+private-field-by-construction; via `issue_for_actor` widening=G.1; via second-mint `reissue(DID)`=G.3; via derive/impl Clone/From=C/D; via type alias=F; via wrong location=A. Fixture exercises 11 modes incl new wrong_ctor_visibility (BYPASS 10, second inherent impl `pub fn`) + reissue_takes_did (BYPASS 11). self-test PASS, real gate PASS.

## Mint site (supervisor.rs:1416-1422, build_actor_deps)
`owned_identity = OwnedIdentityDid::issue_for_actor(owning_did.clone())` minted from the SAME `owning_did` param that builds key_package_store + crypto scope. No wrong-owner possible. clone_for_spawn reissues SAME owner. VERIFIED no escalation: actor/handler code under crate::context can now NAME+CALL reissue but only on a token they already hold (same owner). Build (isolated target) + 3 unit tests PASS w/ --features testing.

## MEDIUM — stale doc in handle.rs (NOT touched by 2E, but 2E invalidates it)
`crates/scp-runtime/src/context/supervisor/handle.rs:266-276` + `:294-296` doc-comments still say struct is `pub(super)` / "type is more private than the method" and carry `#[allow(private_interfaces, dead_code)]` (lines 278, 298, and similar on my_key_package_store). After 2E the struct is `pub(in crate::context)` — SAME visibility as these `pub(in crate::context)` methods — so `private_interfaces` no longer triggers; the `#[allow(private_interfaces)]` is now redundant (NOT a CI failure: plain `#[allow]` unfulfilled does not warn, only `#[expect]` would) and the rationale comments are now factually wrong/contradictory. Recommend: update comments + drop the now-dead `private_interfaces` allow. Defense-in-depth/clarity, not exploitable.

## ADR amendment: faithful
ADR-049 §5 retitled + rewritten to the two-mechanism model, documents reissue + mint site + gate. No contradictory security claims left. Old "No public re-export — reachable only as &OwnedIdentityDid" line removed. Other refs (09-security-model.md:311, 05-contexts.md:1815) remain accurate ("capability proof issued at actor spawn time and unconstructable from handler code").

## Gotcha for future passes
Default `target/` lock is SHARED across worktrees — a concurrent build in another worktree produced a phantom `E0624 _forge_probe issue_for_actor private` error referencing a `mod _forge_probe` that does NOT exist on disk (file is 1844 lines, no such module; Read tool also showed a stale cached view). Use `CARGO_TARGET_DIR=/tmp/...` to isolate. Test build needs `--features testing` (send_induce_panic is cfg-gated).
