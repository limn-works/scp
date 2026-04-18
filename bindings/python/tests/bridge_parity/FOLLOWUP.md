# Bridge parity harness — scope extensions and discovered bugs

This file has two kinds of entries, and the distinction is load-bearing:

- **§1, §2, §6 — Scope extensions.** Additive enforcement-infra work that
  extends the harness with new capabilities (deterministic seed plumbing,
  Kotlin/Swift runners, new ops). These are legitimately separable from
  Layer C's enforcement scope: the harness enforces what is wired; wiring
  more is a next pass. They require the 5-point integration checklist
  (CLAUDE.md) before they can land.

- **§4, §5 — Discovered protocol bugs.** The harness surfaced real
  cross-bridge divergences while being built. They are NOT enforcement-
  infra work. They ARE prerequisites before Layer C's parity gate can
  assert on NAPI/WASM for the affected ops. Each one is a spec or
  semantic violation in production bridge code, currently held visible
  by `@pytest.mark.xfail(strict=True)` so the divergence cannot
  regress unnoticed.

## xfail-strict is the enforcement contract

The `xfail_bridges` / `xfail_reason` fields on OpSpecs in
`seed_operations.py` translate to `@pytest.mark.xfail(strict=True)` in
`test_bridge_parity.py`. Strict means: a fix that makes a test PASS
will fail CI with XPASS unless the xfail is also removed in the same
PR. This enforces a hard workflow: **fix the bridge, same PR removes
the xfail, same PR updates this document.**

These xfails are real bugs held under a tripwire, not dismissals. The
bugs WILL be fixed, and when each fix lands, the gate upgrades from
"visible divergence" to "byte-equality parity." Layer C's parity gate
will assert on NAPI/WASM for these ops at that point.

When fixing any divergence in §4 / §5, the same PR MUST:

1. Remove the corresponding `xfail_bridges=(...)` and `xfail_reason=...`
   fields from the OpSpec in `seed_operations.py`.
2. Update the op's docstring block to drop the "xfail'd" language.
3. Update the relevant section of THIS file (mark resolved or delete).
4. Run the full parity suite locally — all 10 cases should pass.

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

## 2. Add Kotlin and Swift runners

Currently only PyO3, NAPI, and WASM are covered. UniFFI Swift/Kotlin
bindings ship in production and need the same parity guarantees.

**Scope**: Two additional subprocess-based runners with the same
length-prefixed JSON-RPC wire format. Kotlin needs JVM warmup
considerations (long-lived subprocess amortizes this); Swift needs
macOS runners in CI.

**Action**: Once one new runner lands, refactor `seed_operations.py`'s
`node_call` dict to `runner_call: dict[str, dict]` keyed by mode.

---

# Discovered protocol bugs (xfail-strict tripwires)

## 4. DISCOVERED BUG — blocks full parity coverage on valid-challenge SCPID path

**Issue**: filed alongside this PR (see inline description below). Bug is self-documented here; grep `xfail_reason` in `seed_operations.py` for the test-suite surface.

The `invalid_capability_rejected` op in the MVP uses a malformed
challenge (protocol=`scpid/1`, expected `scpid/1.0`). All three bridges
correctly reject it with `SCP-IDENT-1038` (validation error) BEFORE
the identity lookup. That path is at parity and the op verifies it.

A distinct divergence exists on the valid-challenge path (unregistered
DID): PyO3 returns `SCP-IDENT-1001` (via
`crates/scp-ffi/src/runtime.rs::with_identity`), NAPI returns
`SCP-PERM-3023` (via `crates/scp-ffi/napi/src/runtime.rs::with_identity`),
WASM returns `SCP-IDENT-1010` (via
`crates/scp-ffi/wasm/src/identity.rs::sign_with_identity`). Three
bridges, three codes for the same condition — a real bug.

**Current tripwire**: The MVP op does not yet exercise this path, so
the harness does not surface the divergence via xfail-strict today.
Adding an `unregistered_did_rejected` op that passes a well-formed
challenge with an unregistered DID would expose it immediately; the
op lands at the same time as the bridge alignment fix.

**Fix**: Semantically PyO3's choice (`SCP-IDENT-1001`, a generic
identity error) is correct — the DID is not in the local identity
registry, which is an identity-not-found condition, not a permission
denial (PERM-3023) and not a DID-document-missing condition (IDENT-1010
is used for DID document resolution failures elsewhere in WASM).
Align NAPI and WASM on `SCP-IDENT-1001`, then land the
`unregistered_did_rejected` op without xfail — same PR.

xfail-strict enforces the "fix the bridge, same PR adds the op / removes
xfail" workflow. This bug is real. It will be fixed before Layer C's
parity gate asserts on NAPI/WASM for SCPID sign error codes.

## 5. DISCOVERED BUG — blocks full parity coverage for `event_log_append`

**Issue**: filed alongside this PR (see inline description below). Bug is self-documented here; grep `xfail_reason` in `seed_operations.py` for the test-suite surface.

When a context is freshly created and the event log is immediately
queried, bridges return different event counts and starting sequence
numbers (PyO3 may emit `ContextCreated` at creation, others may not).
The current schema uses `exact` comparators and expects PyO3's observed
values; NAPI/WASM diverge.

**Current tripwire**: `test_parity[napi-event_log_append]` and
`test_parity[wasm-event_log_append]` are marked
`@pytest.mark.xfail(strict=True)`. Divergence remains visible in CI
but does not block the suite.

**Fix**: Align which events are emitted at `context_create` time across
all four bridges. This is cross-bridge protocol work — the ContextCreated
event sequencing is a protocol-level semantic, not an enforcement-infra
concern. It requires protocol-level discussion on what the canonical
initial event sequence is.

xfail-strict enforces the "fix the bridge, same PR removes xfail"
workflow. This bug is real. It will be fixed before Layer C's parity
gate asserts on NAPI/WASM for `event_log_append`.

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
