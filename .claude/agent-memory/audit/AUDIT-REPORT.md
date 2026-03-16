# SCP Comprehensive Code Audit Report

**Date:** 2026-03-16
**Branch:** `claude/comprehensive-code-audit-5Kn1p`
**Methodology:** Full code path tracing across all layers — only code-backed findings

---

## Executive Summary

The SCP codebase is remarkably mature for its scope. **Zero `todo!()` or `unimplemented!()` macros exist** in the entire Rust codebase. **Zero `NotImplementedError` in Python**. The scp-core library (`crates/scp-core/`) is production-quality with comprehensive implementations across identity, context lifecycle, cryptography (MLS, UCAN, sender keys, access keys), trust scoring, discovery, economy, sync, and provenance. The PyO3 bridge (reference bridge) has the most complete FFI coverage.

However, the audit identified **10 confirmed findings** — primarily **cross-bridge parity gaps** where functionality implemented in one bridge is stubbed or missing in another. The most critical finding is the UniFFI bridge's no-op crypto provider, which means messages in the mobile SDK path are not MLS-encrypted.

### Finding Summary

| # | Severity | Category | Description |
|---|----------|----------|-------------|
| 001 | **Major** | Wiring gap | NAPI MCP ContextProvider entirely stubbed |
| 002 | Moderate | Placeholder | Hardcoded `did:key:placeholder` in PyO3 tool definitions |
| 003 | Moderate | Security | NoOp UCAN validators on broadcast subscription (3 bridges) |
| 004 | Moderate | Wiring gap | UniFFI trust event counts return hardcoded (0, 0) |
| 005 | **Major** | Security | WASM bridge missing role-based capability check on tool invoke |
| 006 | Moderate | Wiring gap | SSE MCP transport not implemented in NAPI/UniFFI |
| 007 | Moderate | Wiring gap | MCP resource subscriptions are no-ops (all bridges) |
| 008 | Minor | Code quality | 47 `#[allow(dead_code)]` annotations |
| 009 | **Major** | Security | PyO3+UniFFI bridges use no-op crypto for MLS group management (CORRECTED) |
| 010 | Minor | Code quality | Silent Result discarding in transport server |

**By severity:** 3 Major, 5 Moderate, 2 Minor

---

## Detailed Findings

### Finding 001: NAPI MCP ContextProvider is entirely stubbed
**Severity:** Major | **Category:** wiring-gap

The NAPI bridge's MCP ContextProvider returns stub/error responses for ALL methods:

| Method | File:Line | Behavior |
|--------|-----------|----------|
| `agent_role()` | `crates/scp-ffi/napi/src/mcp.rs:338-348` | Returns `None` |
| `context_tools()` | `crates/scp-ffi/napi/src/mcp.rs:354-356` | Returns empty `Vec` |
| `validate_capability()` | `crates/scp-ffi/napi/src/mcp.rs:358-368` | Returns error |
| `invoke_tool()` | `crates/scp-ffi/napi/src/mcp.rs:370-380` | Returns error |
| `context_members()` | `crates/scp-ffi/napi/src/mcp.rs:382-384` | Returns empty `Vec` |
| `context_events()` | `crates/scp-ffi/napi/src/mcp.rs:386-388` | Returns empty array |
| `subscribe_resource()` | `crates/scp-ffi/napi/src/mcp.rs:390-392` | Returns error |

**Comparison:** PyO3 (`crates/scp-ffi/src/mcp.rs:615+`) and UniFFI (`crates/scp-ffi/uniffi/src/bridge.rs:4462+`) both have full implementations.

**Impact:** The TypeScript SDK's MCP server cannot serve tools, validate capabilities, or provide context information to MCP clients.

---

### Finding 002: Hardcoded placeholder DID in PyO3 tool operator field
**Severity:** Moderate | **Category:** placeholder

**File:** `crates/scp-ffi/src/context.rs:1417`
```rust
operator_did: scp_identity::DID("did:key:placeholder".to_owned()),
```

Also at same location: `implementation_hash: [0u8; 32]`, `test_vectors: vec![]`, `signature: Vec::new()`. Multiple fields of `ToolDefinition` are zeroed/empty.

**Impact:** Tool provenance is broken — tools appear to be operated by a non-existent identity.

---

### Finding 003: NoOp UCAN validators on broadcast subscription (all non-WASM bridges)
**Severity:** Moderate | **Category:** security

All three non-WASM bridges use `NoOpDidResolver`, `NoOpNonceTracker`, `NoOpRevocationChecker`, `NoOpProofResolver` for broadcast subscription:

| Bridge | File:Line |
|--------|-----------|
| PyO3 | `crates/scp-ffi/src/context.rs:1582-1620` |
| NAPI | `crates/scp-ffi/napi/src/context.rs:902-906` |
| UniFFI | `crates/scp-ffi/uniffi/src/bridge.rs:8030-8075` |

**Impact:** Gated broadcast mode (which requires UCAN tokens for subscription) has no actual token validation. Any token — expired, revoked, wrong issuer — would pass.

**Note:** The WASM bridge (`crates/scp-ffi/wasm/src/ucan.rs`) implements the full 11-step UCAN validation pipeline.

---

### Finding 004: UniFFI bridge trust event counts return hardcoded (0, 0)
**Severity:** Moderate | **Category:** wiring-gap

**File:** `crates/scp-ffi/uniffi/src/runtime.rs:596-601`
```rust
pub const fn query_trust_event_counts(_context_id: &str, _did: &str) -> (u64, u64) {
    (0, 0)  // stub
}
```

Parameters prefixed with `_` (unused). Function is `const fn` (cannot access runtime state).

**Impact:** Trust scoring on Swift/Kotlin SDKs always computes with zero participation data.

---

### Finding 005: WASM bridge tool invocation missing role-based capability check
**Severity:** Major | **Category:** security

**File:** `crates/scp-ffi/wasm/src/manager.rs:~1870`

No `has_tool_invoke_capability` call anywhere in the WASM bridge (confirmed via comprehensive grep). Tool invocation dispatches directly to handler/echo mode without verifying the invoker's role grants the `tool_invoke:{tool_id}` capability.

**Documented in:** `crates/scp-ffi/wasm/CLAUDE.md` — "Tool Invocation — Capability Check" section explicitly acknowledges this gap.

**Comparison:** PyO3, NAPI, and UniFFI all perform capability checking before tool dispatch.

**Impact:** Any WASM client can invoke any tool regardless of role assignment.

---

### Finding 006: SSE MCP transport not implemented in NAPI and UniFFI bridges
**Severity:** Moderate | **Category:** wiring-gap

| Bridge | File:Line | Error Message |
|--------|-----------|---------------|
| NAPI | `crates/scp-ffi/napi/src/mcp.rs:313-319` | "SSE client transport not yet implemented for NAPI" |
| UniFFI | `crates/scp-ffi/uniffi/src/bridge.rs:4417,4424` | "SSE client transport not yet implemented for UniFFI" |

**Comparison:** PyO3 has real SSE via `SseClientTransport` using raw TcpStream with HTTP/1.1 SSE parsing.

**Impact:** TypeScript and Swift/Kotlin SDKs can only use stdio for MCP client connections, not SSE.

---

### Finding 007: MCP resource subscriptions are no-ops across all bridges
**Severity:** Moderate | **Category:** wiring-gap

| Bridge | File:Line | Behavior |
|--------|-----------|----------|
| PyO3 | `crates/scp-ffi/src/mcp.rs:1029-1033` | Accepts silently, does nothing |
| UniFFI | `crates/scp-ffi/uniffi/src/bridge.rs:4825-4829` | Accepts silently, does nothing |
| NAPI | `crates/scp-ffi/napi/src/mcp.rs:390-392` | Returns error |

**Impact:** MCP clients that subscribe to resources (e.g., context events) will never receive updates.

---

### Finding 008: Excessive `#[allow(dead_code)]` annotations
**Severity:** Minor | **Category:** code-quality

47 annotations across the codebase. Notable clusters:
- `crates/scp-transport/src/native/client.rs` — 8 annotations
- `crates/scp-ffi/uniffi/src/bridge.rs` — 7 annotations
- `crates/scp-ffi/napi/src/identity.rs` — 3 annotations
- `crates/scp-platform/src/testing/key_custody.rs:194,213` — "Retained for future pseudonym wiring"

---

### Finding 009: PyO3 AND UniFFI bridges use no-op crypto for MLS group management
**Severity:** Major | **Category:** security

**CORRECTION:** Initial assessment stated UniFFI-only and claimed "messages are not encrypted." Deeper tracing reveals:

1. **Both PyO3 and UniFFI** use no-op crypto providers (`NoOpCryptoProvider` and `FfiBridgeCrypto` respectively)
2. `encrypt_message` **returns an error** in both — messages cannot silently go unencrypted
3. MLS **group management** operations (create group, add/remove member, validate key package, sender key rotation) all **succeed silently as no-ops**

**Files:**
- PyO3: `crates/scp-ffi/src/runtime.rs:147` — `Box::new(NoOpCryptoProvider)`, lines 323-388 for impl
- UniFFI: `crates/scp-ffi/uniffi/src/runtime.rs:474` — `FfiBridgeCrypto`, lines 476-551 for impl
- NAPI: `crates/scp-ffi/napi/src/runtime.rs:169` — `Box::new(MlsCryptoProvider::new(did))` — real MLS

**Impact:** In PyO3 and UniFFI bridges:
- Key package validation is bypassed (any joiner accepted without valid MLS key package)
- Member removal doesn't trigger key rotation (no forward secrecy)
- Encrypted mode contexts cannot send messages (encrypt_message errors out)
- In practice, only broadcast mode works; encrypted mode is broken
- NAPI is the only non-WASM bridge with real MLS crypto (issue #1294)

---

### Finding 010: Silent Result discarding in transport server
**Severity:** Minor | **Category:** code-quality

~15 instances of `let _ = tx.send(...)` in `crates/scp-transport/src/native/server.rs` (lines 776, 809, 829, 977, 1046, 1061, 1075, 1094, 1111, 1144) and `crates/scp-transport/src/quic/adapter.rs` (lines 381, 416).

Most are acceptable fire-and-forget patterns. The `let _ = forward_handle.await` at line 829 could mask panics in the forwarding task.

---

## Cross-Layer Coverage Matrix

See `matrix.md` for the full operations × targets matrix.

**Key gaps identified:**
- NAPI MCP: 7/7 ContextProvider methods are stubs
- PyO3+UniFFI crypto: No-op MLS group ops (NAPI only bridge with real MlsCryptoProvider)
- WASM capability: No role-based checks on tool invocation
- Broadcast UCAN: NoOp validators in 3/4 bridges
- SSE transport: Missing in 2/4 bridges
- Resource subscriptions: No delivery in 4/4 bridges
- Trust event counts: Stub in 1/4 bridges

## Code Quality Assessment

### Strengths

1. **Zero stubs in Rust core** — `todo!()` count: 0, `unimplemented!()` count: 0
2. **`#![forbid(unsafe_code)]`** in scp-core (`crates/scp-core/src/lib.rs:20`)
3. **Comprehensive test suites** — integration tests in `crates/scp-testing/tests/integration/` cover 30+ scenarios
4. **Clean error hierarchy** — typed errors with SCP error codes throughout
5. **Cryptographic soundness** — MLS (OpenMLS), Ed25519, HKDF-SHA-256, SHA-256 hash chains all correctly implemented
6. **Identity module** — 217 tests, zero stubs, full spec compliance (§3.2-3.11, §9.12)
7. **Store module** — 15 domain submodules with version-enveloped persistence and key sanitization
8. **Input validation** — all FFI boundary inputs validated (DID format, context ID, tool name, etc.)
9. **Transport diversity** — 7+ transport adapters (native relay, QUIC, WebTransport, WebRTC, Nostr, CoAP, UDP/DTLS)
10. **SDK parity** — 4 language SDKs (Python, TypeScript, Kotlin, Swift) with extensive conformance tests

### Architecture Observations

1. **PyO3 is the reference bridge** — most complete, most tested, most mature
2. **UniFFI bridge delegates crypto to platform** — by design, but current no-op default is dangerous
3. **WASM bridge re-implements algorithms** — per ADR-034, verified through conformance tests
4. **ContextManager pattern** — shared across all bridges, good centralization
5. **DashMap for concurrent access** — appropriate for multi-threaded bridges (PyO3, NAPI)
6. **Thread-local for WASM** — appropriate for single-threaded WASM environment

---

## Recommendations

### Immediate (P0)

1. **Wire real MLS crypto in PyO3 and UniFFI bridges** (Finding 009) — NAPI pattern (#1294) is the template
2. **Add capability checks to WASM tool invocation** (Finding 005) — Security gap
3. **Wire NAPI MCP ContextProvider** (Finding 001) — Functional gap blocking TypeScript MCP

### Short-term (P1)

4. **Wire real UCAN validators for broadcast subscription** (Finding 003) — All non-WASM bridges
5. **Replace placeholder DID in PyO3 tool definitions** (Finding 002)
6. **Wire UniFFI trust event counts to real data** (Finding 004)
7. **Port SSE transport to NAPI/UniFFI** (Finding 006) — Or extract to scp-ffi-common

### Medium-term (P2)

8. **Implement MCP resource subscription delivery** (Finding 007) — Requires transport integration
9. **Clean up `#[allow(dead_code)]` annotations** (Finding 008)
10. **Add logging for discarded Results** (Finding 010)
