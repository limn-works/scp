---
name: outlet-stream-out039-conformance-wave2
description: SCP-OUT-039 C12 conformance-test SECOND-WAVE re-review (dedup into common.rs, caveats-binding KATs, bounded drain timeouts) — CLEAN
metadata:
  type: project
---

# SCP-OUT-039 C12 conformance re-review — WAVE 2 (feat/outlet-streaming-ffi, uncommitted @ scp-wt-ffi)

Re-review of the second wave of fixes to the outlet-streaming conformance tests. **CLEAN — zero correctness defects.** All binaries compile with no warnings; ran the 3 scp-testing integration binaries: 2+9+9 pass.

**Why:** double-zero re-review; tests all green, hunt latent defects the green run hides.

**How to apply:** if these files change again, the invariants below are the load-bearing ones.

## What was verified
1. **DEDUP into `outlet_stream_vectors_common.rs`** (included by both `outlet_stream_conformance.rs` runtime-direct + `..._through_open_path.rs` supervisor tiers via `#[path=...] mod common;`). Compiles clean in BOTH binaries; the 3 shared `#[test]`s (`vectors_load...`, `caveats_binding_kat_pins_all_seven`, `sequence_gap_...`) run once per binary (9 tests each = 6 driver + 3 shared). `#![allow(dead_code)]` legit (each tier uses a subset); driver crate-level `#![allow(clippy::expect_used/...)]` covers common's expects. No lost assertions.
2. **caveats_binding KAT** (`assert_caveats_binding_kat`): recomputes `compute_caveats_binding(vector.ucan_cid, request_id, vector.invoker_did, est, JCS(InvocationCaveats::empty()))`, hex via `{b:02x}` = lowercase/64-char/no-0x. **Proven non-vacuous by MUTATION**: corrupted one `expected_caveats_binding` hex char → `caveats_binding_kat_pins_all_seven` FAILED (real recompute `92888ab...7d`). Restored JSON byte-identical.
3. **`outlet_caveats_binding_conformance.rs`** omit-none rule: asserts `!jcs.contains("null")` + `obj.len()==1` + key `eq_ignore_ascii_case("amountmaxpercall")` (pins camelCase — snake_case would FAIL since eq_ignore_ascii_case does NOT ignore underscores) + value=="100" + hardcoded `EXPECTED_BINDING_HEX` checked. Non-vacuous: a None-as-null would flip len→12 and add "null".
4. **`EXPECTED_OPERATOR_PK`** `[u8;32]` in all 5 signing files == `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` (hand-concatenated, matches). Also runtime-asserted against `operator.verifying_key()` so a transcription error fails loudly anyway.
5. **Bounded drain timeouts** (NAPI/UniFFI live tiers): `tokio::time::timeout(10s, poll_next(...)).await.expect("...fail fast...")` correctly wraps the poll future; `.expect` unwraps outer `Elapsed` (panic=fail-fast, not always-succeed); inner matched `Ok(Some(bytes))=>use`, `Ok(None)|Err(_)=>break` (None=closed handled; Err fail-closed → outer assertion catches). Not always-succeed / always-timeout.

## LOW observations (NOT defects in the fixes; pre-existing/coverage)
- through-open-path sets `ContextParams` timing == `OpenStreamParams` timing, so the test cannot detect a supervisor regression that FAILS to overwrite caller values (masked by equality). Coverage weakness, not a test bug.
- KAT binds vector's declared ucan_cid/invoker_did, but live opens use local values (`cid-outlet-stream-conformance` etc.) — the two bindings are independent; vector's declared invoker_did never exercised by the runtime open. Same gap noted in wave-1 memory.
