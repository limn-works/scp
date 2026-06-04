# Process-Global Policy State Is a Realm-Local RCE Pivot

## Problem

After the multi-instance refactor migrated bridge state into per-`BridgeInstance` `CoreFields`, a process-global `OnceLock<Mutex<StdioAllowlist>>` survived inside `crates/scp-mcp/src/allowlist.rs` — a *depended-on* crate, not the bridge itself. The `scp_mcp::allowlist::*` free functions (`configure`, `disable_enforcement`, `reset`, `get_state`, `validate_command`) all read and wrote that singleton.

Each FFI bridge faithfully forwarded its `mcp_*_stdio_allowlist` methods to those free fns. The per-instance facade was clean; the policy underneath was global. Calling `scp.mcpDisableStdioAllowlist()` on **any** `SCP` instance unrestricted subprocess spawning across **every** other instance in the same process. From there, `scp.mcpClientConnectStdio(["sh", "-c", "..."])` on any instance executes — a realm-local RCE pivot.

This is structurally distinct from the [single-tenant FFI registry](./ffi-global-registry-single-tenant.md) lesson:

- **Registry leakage** is about cross-tenant *data* visibility (context IDs, identity routing secrets) through shared-key lookup.
- **Policy leakage** is about cross-tenant *authority* — one tenant's policy decision (turn off the allowlist) immediately reshapes every other tenant's enforcement surface.

The detection heuristic differs too: registry leakage shows up as `static REGISTRY: OnceLock<DashMap<...>>` in bridge source. Policy leakage hides one crate deeper.

## Why the existing detection misses it

`scripts/check-no-bridge-globals.sh` scans `crates/scp-ffi/{src,napi/src,uniffi/src,common/src}` only. The MCP allowlist singleton lived in `crates/scp-mcp/src/allowlist.rs` — **outside the gate's scan path**. The gate was correct for its scope, but a per-instance refactor at the bridge layer didn't catch the policy-state regression hiding in the depended-on crate.

This is the load-bearing class of bug: clean per-instance bridges that delegate to a depended-on crate can re-export process-global semantics through a per-instance API. The bridge's accessor lies; the underlying state is shared.

## Detection heuristic for reviewers

After migrating bridges to per-instance `CoreFields`, audit every depended-on crate the bridges call into. The patterns to grep for:

```
grep -rn 'OnceLock<.*Mutex' crates/scp-mcp/ crates/scp-platform/ crates/scp-transport/ ...
grep -rn 'LazyLock<.*Mutex' crates/scp-mcp/ ...
grep -rn '^static .*: Mutex' crates/scp-mcp/ ...
grep -rn '^static .*: RwLock' crates/scp-mcp/ ...
```

Pay particular attention to crates that expose **policy** decisions: allowlists, deny lists, capability ceilings, rate limits, nonce caches, cooldowns. Each of these is a per-instance concern even if it looks like a process invariant — the moment you have two tenants in one process, "process invariant" means "tenant A controls tenant B's policy."

`check-no-bridge-globals.sh` should not be widened to scan all crates (that produces noise on legitimate process state). Instead, every PR that promotes a bridge to per-instance must explicitly enumerate the depended-on policies and either (a) prove they have no shared mutable state, or (b) hoist them into `CoreFields` alongside the bridge state.

## Fix pattern

1. Hoist the policy state into `CoreFields` as an owned `Mutex<PolicyType>` (not an `Arc<Mutex<PolicyType>>` — owned-by-value forbids accidental sharing).
2. Add a `pub const fn policy_name(&self) -> &Mutex<PolicyType>` accessor on `CoreFields`. Mirror it on the `BridgeInstanceCore` trait if the spawn path or other plumbing needs the raw `&Mutex` for cross-module passing.
3. Add a `with_policy_name<T>(&self, f: impl FnOnce(&mut PolicyType) -> T) -> Result<T, GuardError>` helper on `CoreFields` for the common single-op-then-drop case. The closure-shape forces the guard to drop before any FFI / GIL / `await` work runs.
4. Document the lock-ordering rule on the field's doc-comment AND on the trait method's doc-comment AND on the helper's doc-comment. Three repetitions are not redundant — bridge authors will only see one of them depending on entry point.
5. Delete the global. Hard-delete, not deprecation-shim. Per "no DOA decisions": if the new shape is correct, the old shape should not coexist.
6. Plumb any audit-log identifiers (e.g. `instance_id: u64`) through the policy methods so multi-tenant operators can identify which tenant invoked the policy change. The bridge layer reads `bi.core.instance_id()` and passes it through.
7. Two-instance regression test in **every** bridge: construct two `*BridgeInstance` (or `Scp`) instances, mutate policy on instance A, assert instance B is unaffected. The test must drive the **public** SDK method, not reach into `core.policy_name().lock().unwrap()` directly — the latter doesn't catch a regression where the public method silently locks the wrong mutex.

## Reference

- PR #1725 — landed the per-instance MCP stdio allowlist migration.
- `crates/scp-mcp/src/allowlist.rs` — the `OnceLock<Mutex<StdioAllowlist>>` was deleted; `StdioAllowlist` is now an owned struct.
- `crates/scp-ffi/common/src/bridge_instance.rs::CoreFields::mcp_allowlist` — the new home, plus the `with_mcp_allowlist` helper.
- ADR-048 §1 multi-instance neutrality is the upstream principle this lesson grounds in.

## Lesson

A clean per-instance bridge facade is necessary but not sufficient. Audit the depended-on crates. A `OnceLock<Mutex<...>>` two layers down can re-export process-global semantics through a per-instance API, and the bridge-globals gate won't catch it. Policy state is per-instance state; treat it the same way as data state.
