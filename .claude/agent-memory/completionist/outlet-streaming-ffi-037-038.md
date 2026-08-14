---
name: outlet-streaming-ffi-037-038
description: SCP-OUT-037/038 done-marking audit — implementation COMPLETE, ~11 ACs STALE (superseded designs), no functional gaps
metadata:
  type: project
---

# SCP-OUT-037 / SCP-OUT-038 done-marking audit (@ae9ccb6bc, feat/outlet-streaming-ffi)

Verdict: IMPLEMENTATION COMPLETE + tested end-to-end across all layers; STORY ARTIFACTS carry ~11 STALE ACs describing superseded designs. No UNMET functional gaps. Both stories honestly done-able AFTER reconciling the stale ACs (phantom provenance otherwise).

**Why:** the branch superseded an earlier abandoned design. Prior (abandoned, NOT ancestor of HEAD) commits f3f40a8bf/e0bb8a5ca had a full WASM streaming bridge at `crates/scp-ffi-wasm` + `bridge_ratchet_baseline.json`. Current design: WASM=`crates/scp-client-wasm` (2 pure ops only, ADR-057 scope fence), alias-driven conformance (`scripts/bridge-aliases.json`, 212 ops), FFI-signed credits (ADR-006).

**How to apply:** when re-auditing outlet streaming, the correct bridge shape is SCP-OUT-006 single-verb: bridge `outlet_stream_open`→handle-id String + `outlet_stream_poll_next`→Option<chunk bytes>; SDK builds the iterator/AsyncSequence/Flow. NOT bridge-returns-iterator.

STALE clusters (all grounded, no gap):
- 037 AC1-4 (bridge returns async iterator) → bridge returns handle+poll_next; SDK builds iterator (SCP-OUT-006 item 32 + 038 AC1).
- 037 AC4/16/17(wasm)/18(wasm) (full WASM streaming pump) → ADR-057 scope fence: browser participates (signs/verifies own steps) but does NOT coordinate economy; only `outletStreamComputeCaveatsBinding`+`outletStreamVerifyChunkSignature` (scp-client-wasm/src/lib.rs:668,715).
- 037 AC13 (bridge_ratchet_baseline.json) → file does not exist; ratchet = bridge-aliases.json + MIN_PARITY floor (106, not "107").
- 037 AC14/19 (PARITY_OPERATIONS/WASM_SOURCES/WASM_REQUIRED_OPERATIONS/"NAPI_SOURCES include outlet_stream.rs") → alias-driven; napi #[napi] exports live in napi/src/scp.rs:2926+ (delegate to outlet_stream.rs _on helpers); no WASM in ffi_conformance.rs (WASM tested in scp-client-wasm's own vectors).
- 037 AC18 (StreamAdmissionTracker on BridgeInstance) → parked in RUNTIME supervisor `outlet_stream_admission: HashMap<ctx_id, Arc<RwLock<StreamAdmissionTracker>>>` (supervisor.rs:1499) + operator-scoped OriginAdmissionTracker; persistent-per-context substance MET+tested. No `BridgeInstance` type exists.
- 038 AC3(signing clause)/AC11 ("SDK tracks counter locally and signs") → FFI bridge signs OutletStreamCredit + auto-assigns monotonic_seq (ADR-006, invoker key never leaves custody). Matches 038's OWN description; AC11 self-contradicts the description.

MET substance: CRITICAL#1 caller_did gate (all 3 native, `caller_not_invoker_err`→PERM_3001), CRITICAL#3 runtime-derived next_seq (`current_next_emission_seq` dispatch.rs:894), Credit newtype `.value` reject 0/neg/≥2³²→InvalidGrant (all 4 SDKs), StreamAlreadyClosed under Protocol-class parent, all integration tests (a-e) present all 4 SDKs.

LOW observations to resolve (not blockers): (1) spec §5.4.5:549 says caller-mismatch SHOULD slug authorization.denied SCP-OUTLET-6110; code+AC5/AC15 use SCP-PERM-3001 — reconcile per one-way flow. (2) both stories' `files[]` cite nonexistent paths `crates/scp-ffi/wasm/src/{outlet_stream,manager}.rs` + `crates/scp-ffi/bridge_ratchet_baseline.json` — should be `crates/scp-client-wasm/src/lib.rs`, drop ratchet file. (3) AC13 Kotlin parent named `OutletProtocolException` not `ProtocolError`; Swift flat enum not "nested under Protocol assoc value" — semantic same-depth intent met.
