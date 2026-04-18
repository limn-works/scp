# Bridge parity harness — scope extensions

This file tracks additive enforcement-infra work that extends the
harness with new capabilities (deterministic seed plumbing, Kotlin/
Swift runners, new ops). These are legitimately separable from
Layer C's enforcement scope: the harness enforces what is wired;
wiring more is a next pass. They require the 5-point integration
checklist (CLAUDE.md) before they can land.

Discovered protocol bugs previously tracked in §3–§5 (context-ID
format divergence, SCPID unregistered-DID error-code triple-
divergence, event_log_append starting sequence) have been fixed and
removed. Git history carries the rationale and the PRs that landed
each fix.

## xfail-strict is still the enforcement contract

If a future divergence is caught, follow the same workflow the §3–§5
bugs followed:

The `xfail_bridges` / `xfail_reason` fields on OpSpecs in
`seed_operations.py` translate to `@pytest.mark.xfail(strict=True)` in
`test_bridge_parity.py`. Strict means: a fix that makes a test PASS
will fail CI with XPASS unless the xfail is also removed in the same
PR. This enforces a hard workflow: **fix the bridge, same PR removes
the xfail, same PR updates this document.**

When fixing any newly added divergence, the same PR MUST:

1. Remove the corresponding `xfail_bridges=(...)` and `xfail_reason=...`
   fields from the OpSpec in `seed_operations.py`.
2. Update the op's docstring block to drop the "xfail'd" language.
3. Update the relevant section of THIS file (mark resolved or delete).
4. Run the full parity suite locally — all cases should pass.

`seed_operations.py`'s module docstring repeats this policy for agents
reading the file directly.

---

# Scope extensions

## 1. Wire `seed: Option<[u8; 32]>` through identity creation

The seed parameter is an additive protocol change spanning four bridges
plus `scp-core` that requires 5-point integration-checklist sign-off
(CLAUDE.md). Until it lands, `sign_message` parity is shape-only: the
signature field uses a `regex` comparator matching 128 hex chars rather
than `bytes_from_hex` byte-equality. `identity_create_deterministic` is
similarly shape-only.

**Scope**: `crates/scp-ffi/src/identity.rs`,
`crates/scp-ffi/napi/src/identity.rs`,
`crates/scp-ffi/wasm/src/identity.rs`,
`crates/scp-ffi/uniffi/src/` + a `testing` feature flag plumbed from
`scp-core`. Estimated ~60-100 LoC across all bridges.

**Action**: File a GitHub issue "Wire deterministic seed param through
`identity_create` for bridge parity byte-equality". Link to ADR-046 and
the `identity_create_deterministic` op in `seed_operations.py`. When it
lands, flip the `signature` FieldSpec from `regex` to `bytes_from_hex`
and add an `expected_value` for full byte parity.

---

# Scope extensions (continued)

## 6. Expand the op library

Current 5 ops cover identity, context, error, event log, and signing.
Missing areas that would benefit from parity assertions:

- UCAN mint + validate (capability URI handling differs subtly between
  bridges per ADR-016)
- Transport status (connection state serialization)
- Tool register + invoke (JSON schema validation parity)

Per the ADR: adding a new op is ~20 lines. Incremental coverage
is the whole point of the harness.
