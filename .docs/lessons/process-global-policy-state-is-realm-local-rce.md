# Process-Global State Behind a Per-Instance Bridge Crosses Tenants

Several `SCP` instances can live in one process, for example a server serving many users
(ADR-048). Any mutable process-global state reachable from a bridge method is then shared
between them, however clean the per-instance facade looks.

## Two forms

- **Data leakage.** The PyO3 bridge once kept contexts, known-context metadata, the relay
  connection, and identity routing secrets in `OnceLock<DashMap<…>>` statics, so one tenant
  could reach another's contexts and routing secrets. PyO3 now keeps that state in
  per-instance `BridgeInstance` fields, as NAPI and UniFFI always did.
- **Authority leakage.** After that migration, `crates/scp-mcp/src/allowlist.rs` still held
  the MCP stdio allowlist in a `OnceLock<Mutex<StdioAllowlist>>`. Calling
  `mcpDisableStdioAllowlist()` on any instance disabled subprocess-spawn enforcement for every
  instance, so `mcpClientConnectStdio(["sh", "-c", …])` then ran on any of them: a
  realm-local remote-code-execution pivot. The allowlist now lives in `CoreFields` as
  `mcp_allowlist`, reached through `with_mcp_allowlist`.

## Why the gate missed it

`scripts/check-no-bridge-globals.sh` scans the bridge source directories under
`crates/scp-ffi/` only, and the singleton sat one crate deeper. Widening the gate to every
crate would flag legitimate process state, so the check is a review obligation: a change
that makes a bridge per-instance enumerates the policies the bridge's dependencies hold
(allowlists, deny lists, capability ceilings, rate limits, nonce caches, cooldowns) and
either shows they hold no shared mutable state or moves them into `CoreFields`.

## Fix pattern

- Hold the policy in `CoreFields` by value (`Mutex<Policy>`, never `Arc<Mutex<Policy>>`), with
  a closure helper (`with_<policy>(|p| …)`) so the guard drops before any FFI, GIL, or
  `await` work.
- Delete the global outright; do not leave a deprecation shim.
- Pass the instance id into policy methods so an operator can tell which tenant changed a
  policy.
- Add a two-instance test in every bridge that changes the policy on instance A through the
  public SDK method and asserts instance B is unaffected.
