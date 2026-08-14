# Optional strings at the FFI boundary: treat `Some("")` as `None`

**Date:** 2026-04-14
**Source:** PR #1637 — governance `reason` field empty-string rejection

## The bug

Governance actions with an `Option<String> reason` field accepted `None` but rejected
`Some("")` with a validation error. `validate_governance_reason("")` correctly rejects the
empty string (the validator's contract is "non-empty human-readable reason"), and the caller
blindly invoked it whenever `reason.is_some()`.

SDKs vary in how they represent "no value":

| SDK        | Idiomatic "no value"           | What reaches Rust                    |
| ---------- | ------------------------------ | ------------------------------------ |
| Rust       | `None`                         | `None`                               |
| Python     | `None`                         | `None` — but `""` is truthy-neighbor |
| TypeScript | `undefined` or `null` or `""`  | any of them                          |
| Swift      | `nil`                          | `nil`                                |
| Kotlin     | `null`                         | `null`                               |

TypeScript in particular treats `""`, `null`, and `undefined` as semantically interchangeable
for "user didn't provide a value." JSON serialization further flattens the distinction —
`{"reason": ""}` and `{"reason": null}` are often produced interchangeably by higher-level
frameworks.

## The rule

**At the FFI validation boundary, normalize `Some("")` to `None` for every optional string
field where empty conveys "absent" rather than "explicitly empty."** Do not loosen the
downstream validator — it has a contract that callers with a required field still depend on.

Fix pattern:

```rust
| GovernanceAction::RemoveMember { reason: Some(r), .. }
| GovernanceAction::CloseContext { reason: Some(r), .. }
| GovernanceAction::RotateContentKeys { reason: Some(r), .. } => {
    if !r.is_empty() {
        validate_governance_reason(r)?;
    }
}
// A required reason (e.g. ResetMember) still calls the validator directly — empty rejected.
GovernanceAction::ResetMember { reason, .. } => {
    validate_governance_reason(reason)?;
}
```

## Why normalize at the validator, not the FFI bridge

- **Consistency across 3 bridges.** Putting the normalization in `scp-ffi/common/src/validate.rs`
  means PyO3, UniFFI, and NAPI all get the same behavior for free. Normalizing per-bridge
  invites drift.
- **Required-field callers unchanged.** The validator itself still rejects `""` for callers
  that pass a non-optional reason. Only the "treat Some('') like None" behavior lives in the
  optional-field call sites.
- **Tests assert both paths.** `governance_reason_empty_string_rejected` covers the direct
  validator contract; `*_empty_string_reason_accepted` covers the optional-field callers.

## How to catch this when reviewing

- Any FFI function with an `Option<String>` parameter: grep for calls to `validate_*` inside
  its `Some(_)` arm. If the validator rejects empty strings, confirm the Some/None check is
  on `!r.is_empty()`, not `.is_some()`.
- Any SDK wrapper that converts `""` to a `String` and passes it across: confirm the receiving
  end treats empty as absent. Better yet, normalize to `None` in the SDK wrapper before
  crossing the boundary — defense in depth.

## Related

- `crates/scp-ffi/common/src/validate.rs::validate_governance_action_strings`
- `crates/scp-protocol/src/context/governance.rs` — the `GovernanceAction` enum definition
- Issue #1604 — the original report
