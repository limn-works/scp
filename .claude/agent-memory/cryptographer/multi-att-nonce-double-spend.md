---
name: multi-att-nonce-double-spend
description: TS evaluateLayer1 validates each att URI of a token via separate ucanValidate calls; step-9 nonce is recorded on first call, so 2nd+ URIs of a multi-att token spuriously fail NonceReused and poison the persistent context nonce tracker
metadata:
  type: project
---

`bindings/typescript/src/trust.ts::evaluateLayer1` (introduced in PR #1867,
branch `fix/sdk-coverage-fail-closed-and-parity`) loops over EVERY declared
capability URI of a UCAN token (`__extractAllCapabilityUris` → all `att[i].with`)
and calls `scp.ucanValidate(handle, token, capUri)` once per URI, AND-intersecting
the per-URI verdicts via `intersectCapabilityValidation`.

**The bug:** `ucanValidate` runs the full 11-step `validate_ucan` pipeline, and
step 9 (`NonceTracker::check_and_record`) RECORDS the nonce into the *persistent*
per-context tracker — NAPI: `rt.core.nonce_tracker` (napi/src/ucan.rs:263);
WASM: writeback via `WasmContextManager::ucan_record_nonce` (wasm/src/ucan.rs:382).
The nonce is keyed by token, not by (token, capUri). So for a token with ≥2 att
entries, the FIRST capUri call burns the nonce; the SECOND call re-reads
seen_nonces, hits `NonceReused`, classifies as `nonce` → `nonceValid:false`.

**Two consequences:**
1. False negative: a fully-valid multi-att token gets `nonceValid:false` in its
   trust verdict purely from being validated against more than one of its own URIs.
2. Replay-cache poisoning: the legitimate nonce is now permanently in the context's
   persistent tracker, so a later REAL operation presenting that token is rejected
   as a replay.

**Root cause is the design assumption** that ucanValidate is a read-only probe.
It is not — it is write-through on the nonce (by spec, step 9 is check-AND-record).
Trust evaluation calling a state-mutating validation per-URI violates that.

Possible fixes: (a) extract+validate against the union/first URI only and document
multi-att ceiling as bridge-level; (b) add a read-only validation entry point that
does NOT record the nonce (probe vs commit split already exists in the
NonceTracker trait: check_replay vs record); (c) dedupe by validating the token
once and checking capability-match in TS. Option (b) aligns with the H11
split-phase protocol already in validate.rs.

See [[trust-ucan-classification]].
