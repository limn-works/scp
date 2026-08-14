---
name: adr062-slice1-dht-e1
description: ADR-062 Slice 1 / SCP-CAPINJECT-001 DHT capability-injection API review — DhtMode, FfiDhtClient, ClientDhtConfig, DidDht constructor changes
metadata:
  type: project
---

# ADR-062 Slice 1 (SCP-CAPINJECT-001, DHT E1) API review — branch feat/adr062-slice1-dht-e1

Verdict: APPROVE-WITH-CHANGES. Reviewed on FIXED code (diff 9ff9eadde..e54de4fae).

**Why:** Removes the in-memory DHT nullifier (§17.17.3) from all shipped paths; makes it inexpressible by omission.

## Core design (all sound)
- `DhtMode` (scp-node/src/config.rs): `Disabled` (default, shipped, no-publish + honest Ok(None) resolve), `Memory` (`#[cfg(any(test,feature="testing"))]` only), `Production`. Shipped bindings show only 2 variants — clean for LLM authorability. "Disabled" is accurately named: whole DHT layer off (publish AND resolve, relay-only), more accurate than "NoPublish".
- `DidDht<D: DhtClient, C=SystemClock>` — removed the `D = InMemoryDhtClient` type-param default AND deleted `new()`/`Default`. Now every caller names its client explicitly (with_client / with_client_and_cache / with_client_and_signer / testing-only with_in_memory_custody). Strong misuse-resistance win, no typestate.
- `FfiDhtClient` (scp-ffi/common/src/dht.rs, NEW): Pkarr arm unconditional, InMemory arm `#[cfg(testing)]`. `ClientDhtConfig{gateways}.into_client()->Result<_,DhtInitError>` fails closed (M3).
- construction.md upstream artifact updated in lockstep (Memory→Disabled everywhere) — artifact flow intact.

## Findings worth remembering (recurring-pattern candidates)
1. **IDENT_1001 overloaded for DHT-init failure** (uniffi bridge.rs:266, napi identity.rs:88). IDENT_1001 is documented (error_codes.rs:46-55) as "generic identity error / identity NOT REGISTERED (registry-miss)". Reusing it for "failed to init production DHT client" conflates with the code SDK consumers switch on for registry-miss. Consistent across both bridges (good) but semantically wrong code. → wants a dedicated IDENT_10xx.
2. **Two parallel Pkarr builders with DIVERGENT gateway validation**: `ClientDhtConfig::into_client` (scp-ffi/common) fail-closes via `validate_gateway_url` (scheme+host); `scp-node::self_host::build_pkarr_client` accepts any non-empty trimmed string. Same input concept, two validation semantics.
3. **ClientDhtConfig.gateways + validate_gateway_url currently unreachable in FFI layer** — every caller uses `ClientDhtConfig::default()` (empty). NodeConfig.dht_gateways is dropped in split_config; the real gateway path is build_pkarr_client. Premature surface but internal (common crate, not developer-facing SDK). Simplifier's flag confirmed.
4. `DhtError::Disabled` flattened into `IdentityError::DhtPublishFailed(String)` (lib.rs:295) — loses typed distinctness above scp-dht. Message honest.
5. napi process-global SHARED_DHT_CLIENT vs uniffi per-instance set_dht_client (#2151) is INTERNAL — does not leak into developer-facing API shape (developer never names the DHT client).
