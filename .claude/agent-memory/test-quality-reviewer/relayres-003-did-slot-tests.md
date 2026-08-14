---
name: relayres-003-did-slot-tests
description: Test-quality assessment of SCP-RELAYRES-003 relay DID-slot / slot-exclusivity tests (crates/scp-transport did_slot.rs + 4 transport handlers)
metadata:
  type: project
---

SCP-RELAYRES-003 (relay-side DID-record validation + slot-exclusivity), branch relayres-003-fixes, final commit cf02ee7a4.

**Test locations**
- Unit: `crates/scp-transport/src/native/did_slot.rs` `#[cfg(test)]` (~670 lines). Real `BlobStorageBackend::in_memory()`, injected `ClockFn` (AtomicU64) for all TTL/expiry tests — deterministic, no wall-clock sleeps.
- e2e per transport `#[cfg(test)]`:
  - WS `native/server.rs`: flood variants a/b/c/d, wrong-routing_id, delete_of_claimed, **delete_of_cold_index**, **query_of_cold_index** — strongest coverage. Real RelayServer over real tungstenite socket, validation Enabled (RelayConfig::default()).
  - QUIC `quic/listener.rs`: slot_exclusivity, lower_seq_rejected, delete_of_claimed, **delete_of_cold_index**. Real QUIC listener+client.
  - UDP `udp/listener.rs`: slot_exclusivity, delete_of_claimed. Real DTLS. NO cold-index e2e.
  - WebTransport `webtransport/session.rs`: one combined test via `dispatch_message_multi` on real handler (not over-the-wire — drives real gate through real dispatch). NO cold-index e2e.

**Verdict: essentially ADEQUATE.** Genuine e2e over real relay+storage, no mock bypasses the gate, strong discrimination on nearly every axis.

**Weaknesses (non-blocking):**
1. `delete_gate_is_rate_limited` uses an ABSENT blob → only weakly/transitively covers the security-critical "rate-limit BEFORE the CPU-amplifiable Ed25519 classify" ordering. Stronger: exhaust budget against a PRESENT protected frame, assert RATE_LIMITED (not DID_RECORD_REJECTED), proving the limiter short-circuits before classify.
2. Cold-index DELETE + cold-index QUERY e2e exist only on WS+QUIC, not UDP/WT. Low marginal value (gate_delete/gate_query are a shared chokepoint; wiring path is identical warm vs cold) but an empty matrix cell.
3. `partial_cold_index_query_does_not_warm_to_older_frame` depends on InMemoryBlobStorage.query returning ascending stored_at order + limit truncation keeping oldest. Deterministic for the in-memory backend but couples the test to storage ordering impl.

Good patterns: variant (c) reject + variant (d) accept-when-unclaimed *pair* to precisely discriminate rule (a). generation-gate tests have both positive (no-op on refreshed) and negative (removes matching-gen) branches. fail-closed test uses a FailingGetStorage stub.
