# bridge-symmetry fixtures

Canned fixture tests for `scripts/check-bridge-symmetry.sh`. Each fixture is
a miniature repo with a `scripts/bridge-aliases.json` and stub `crates/scp-ffi/`
source trees, exercised by pointing the checker at it via `SCP_BRIDGE_ROOT`.

## Scope

This script (and its fixtures) enforce **surface-area symmetry only**: every
canonical operation in `bridge-aliases.json` must have at least one declared
alias present in every required bridge's source tree, or carry a documented
exemption.

**Call-ordering invariants** (e.g. "`ensure_did_resolver_initialized` must
precede `register_identity`") are enforced by Layer B's
`scripts/check-call-invariants.py`, which uses `tree-sitter-rust` for a
proper tokenization of Rust source. That layer has its own fixture suite.
Shell+awk cannot reliably handle raw strings (`r#"..."#`), format strings
containing `{}`, or block comments — which is why the call-ordering logic
was removed from this layer.

## Fixtures

- `good-all-bridges` — single canonical op implemented in all three bridges.
  Expected: exit 0, zero findings.
- `bad-missing-napi` — canonical op missing from the NAPI bridge.
  Expected: exit 1, finding cites `bridge=napi missing operation widget_create`.
- `good-exempt-missing` — canonical op missing from NAPI but explicitly
  exempted in `bridge-aliases.json`. Expected: exit 0, zero findings.

## Running

```sh
bash scripts/tests/bridge-symmetry/run-tests.sh
```
