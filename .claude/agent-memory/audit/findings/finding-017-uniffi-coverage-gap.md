# Finding 017: UniFFI bridge covers only ~33% of PyO3 exports

## Severity: moderate

## Summary

The UniFFI bridge exports ~40 functions vs PyO3's 122. Entire feature categories are absent, making them unavailable on Swift/Kotlin (mobile) platforms.

## Evidence

**File:** `crates/scp-ffi/uniffi/src/bridge.rs`

Missing entire categories (0 functions exported):
- **MCP** — server creation, client connect, tool listing, invocation
- **Discovery** — context discovery, address resolution, petname management
- **Economy** — cost estimation, budget management, relay pricing, anti-spam
- **Media** — session lifecycle, signaling (offer/answer/ICE)
- **Provenance** — quality evaluation, attachment, chain depth checking
- **Bridge Connector Credentialing** — credential provision/rotate/revoke, OAuth PKCE
- **Tool Sessions** — cross-context invocation, session create/invoke/close

**Comparison:** PyO3 exports 122 functions across all categories. NAPI exports 98 (~80%).

## Impact

Swift and Kotlin SDKs lack MCP, discovery, economy, media, and provenance capabilities. These features are completely unavailable on iOS and Android platforms.

## Suggested Fix

Incrementally expand UniFFI bridge coverage, prioritizing:
1. Discovery (context discovery, address resolution) — needed for mobile onboarding
2. Economy (cost estimation, budget) — needed for paid contexts
3. MCP (server/client) — needed for tool integration
4. Media (session lifecycle) — needed for real-time communication
5. Provenance (quality, attach) — needed for cross-context data flows
