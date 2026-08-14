---
name: project-sdk-parity-idioms
description: Per-SDK idiom divergences that are intentional (not parity bugs) when reviewing TS/Python SDK wrappers
metadata:
  type: project
---

When reviewing `bindings/typescript` vs `bindings/python` SDK wrappers for parity, these
divergences are INTENTIONAL per-SDK idiom (ADR-048 §7 + the per-sdk-idiom lesson), NOT defects:

- **Discovery helper dispatch shape.** TS routes ALL discovery functions
  (`parseAddress`, `normalizeAddress`, `discoverContexts`, `resolveAddress`) through the
  `SCP` instance as first arg: `discoverContexts(scp, query)`. Python routes the pure
  discovery helpers (`parse_address`, `normalize_address`, `discover_contexts`,
  `create_query`) as **module-level functions** using a lazy module bridge singleton
  (`discovery._bridge()`), no `SCP` instance. Each SDK is internally consistent; a new
  discovery wrapper should follow its own SDK's existing pattern.

- **Identity lifecycle ops.** Live as methods on the `SCP` class in both SDKs
  (`scp.identityRotateKey(identity)` / `scp.identity_rotate_key(identity)`), routed through
  the per-instance bridge (not on the `Identity` handle, which is a pure data type post
  ADR-048 PR-4 #1549). Both take the opaque Identity object.

**Why:** ADR-048 §7 was amended to per-SDK idiom — don't propagate one language's binding
constraints across SDKs. See [[project-sdk-coverage-pr]].
**How to apply:** Don't flag TS-instance-arg vs Python-module-function as a parity bug for
discovery; do flag genuine semantic drift (wire shape, error codes, missing operations).

Receipt-verification wire contract (`scp_runtime::economy::receipt::verification_results_to_json`):
top-level `{all_valid: bool, results: [...]}`; each entry `{receipt_id, ok, valid, result}`
on success or `{ok:false, error}` on failure. `ok` = adapter RESPONDED, `valid`/`all_valid`
= payment validity. The TS `PaymentReceiptVerificationResult`/`Entry` interfaces and the
Python dict shape both match this exactly. There is NO top-level `ok` field.
