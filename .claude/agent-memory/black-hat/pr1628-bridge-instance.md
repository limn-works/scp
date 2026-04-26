---
name: PR #1628 BridgeInstance Adversarial Review
description: Full adversarial review of BridgeInstance extraction — singleton consolidation, lifecycle, shutdown hooks, placeholder DIDs, capacity bypasses
type: project
---

## PR #1628 BridgeInstance Extraction -- Adversarial Review (2026-04-14)

### BLACK-301: Post-shutdown ghost operations (all bridges)
- context_manager() and bridge_instance() return warn-only on AlreadyShutDown
- ContextManager Arc still alive after shutdown, MLS groups destroyed but provider active
- Creating contexts after shutdown produces inconsistent state
- Files: scp-ffi/src/runtime.rs:112-134, napi/runtime.rs:140-162, uniffi/runtime.rs:105-129

### BLACK-302: DashMap capacity bypass via concurrent registration
- register_known_context has TOCTOU between len() check and insert
- Eviction race: between drop(oldest) and remove(&oldest_key), another thread can insert same key
- File: scp-ffi/common/src/bridge_instance.rs:650-671

### BLACK-303: Placeholder DID identity confusion (NAPI + UniFFI)
- ensure_bridge_instance uses "did:unknown:napi-bridge" / "did:unknown:bridge"
- OnceLock prevents later correction; MLS credentials bound to unresolvable DID
- Files: napi/runtime.rs:240, uniffi/runtime.rs:210

### BLACK-308: Rate limiter ephemeral bypass under load
- When MAX_RATE_LIMITERS (1000) reached, creates ephemeral tracker with zero history
- Attacker fills registry with 1000 DIDs, target DID gets unlimited auto-accept
- File: scp-ffi/common/src/bridge_instance.rs:727-750

### BLACK-309: Economy state unbounded growth
- economy_budgets and economy_antispam have NO capacity limits
- Unlike known_contexts (10K) and rate_limiters (1K), no eviction
- File: scp-ffi/common/src/bridge_instance.rs:759-798

### Confirmed Working
- Shutdown idempotency (atomic swap)
- Transport RwLock + Arc pattern
- Hook panic isolation (catch_unwind)
- SeqCst ordering on flags
- DID resolver OnceLock immutability
- Bridge connector per-context isolation
