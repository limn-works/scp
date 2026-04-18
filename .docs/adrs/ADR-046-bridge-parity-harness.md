# ADR-046: Cross-Bridge Runtime Parity Harness

**Status:** Accepted
**Date:** 2026-04-17
**Phase:** Phase 6 (production readiness, enforcement)
**Related:** ADR-022 (language bindings), ADR-034 (WASM constraints), ADR-045 (fuzzing infra), ADR-047 (bridge symmetry enforcement — static surface-area parity; complements this ADR's runtime parity)

## Context

SCP ships four production FFI bridges over the same Rust core:

| Bridge       | Host                 | Mechanism       | Reference       |
|--------------|----------------------|-----------------|-----------------|
| PyO3         | Python (CPython)     | `pyo3 0.24`     | `crates/scp-ffi/src/` |
| NAPI         | Node.js / Bun        | `napi-rs`       | `crates/scp-ffi/napi/` |
| WASM         | Browser JS           | `wasm-bindgen`  | `crates/scp-ffi/wasm/` |
| UniFFI       | Swift / Kotlin       | `uniffi`        | `crates/scp-ffi/uniffi/` |

Layers A and B already enforce **structural parity** — that every operation is
declared in every bridge and in the SDK capability matrix. What they cannot
catch is **runtime behavioral drift**: a bridge that accepts the call, returns
a plausibly-shaped response, but encodes a field differently, swaps a key
casing, returns `null` where another returns the empty string, or quietly
diverges on error shape. These are the bugs that break cross-ecosystem
interop, and they are invisible to per-bridge unit tests.

This ADR introduces **Layer C** of the bridge enforcement stack: a runtime
parity harness that drives each bridge with identical inputs and asserts
identical (normalized) outputs.

## Decision

A **Python-hosted harness** spawns a long-lived **Bun child** over JSON-RPC.
For each operation in a small seed op library, the harness invokes the
operation on the PyO3 bridge (in-process) and on the NAPI + WASM bridges
(via the Bun child), normalizes both outputs to canonical JSON, and asserts
equality.

### MVP bridges

The MVP covers PyO3, NAPI, and WASM only. Each operation runs on PyO3 and
each NAPI/WASM bridge in turn (parametrized product: N_ops × 2 alt bridges).
UniFFI (Kotlin, Swift) is deferred — see "Future work."

### Harness architecture

```
┌─────────────── pytest (Python 3.12) ───────────────┐
│                                                    │
│  conftest.py: spawns Bun child, tears down         │
│  test_bridge_parity.py: parametrized test matrix   │
│  normalizer.py: canonical JSON normalization       │
│  runner_client.py: JSON-RPC client over stdio      │
│                                                    │
│  PyO3 bridge                                       │
│  ──────────── (in-process `import scp_sdk`)        │
│  Seed ops run here                                 │
│                                                    │
└──────────────────┬─────────────────────────────────┘
                   │ length-prefixed JSON-RPC frames
                   │ over stdin/stdout
                   ▼
┌──────── bun node_bridge_runner.ts ─────────────────┐
│                                                    │
│  mode="napi"  → imports @limn-works/scp-ts via     │
│                 NAPI native addon                  │
│  mode="wasm"  → imports @limn-works/scp-ts-wasm    │
│                 via wasm-bindgen Promise API       │
│                                                    │
│  Dispatches on op name to bridge calls, returns    │
│  raw JSON results                                  │
│                                                    │
└────────────────────────────────────────────────────┘
```

### Transport: length-prefixed JSON-RPC

Request frames on the Bun child's stdin and response frames on stdout use
HTTP-style length prefixes to tolerate non-line-safe binary data and partial
reads:

```
Content-Length: N\r\n
\r\n
<N bytes of JSON>
```

Rationale over newline-delimited JSON: base64 and JSON body do not contain
raw newlines, but we want the transport layer to be robust independent of
future payload shapes. HTTP semantics are well-understood and the parser is
~20 lines.

### Bridge selection is explicit

The runner's `mode` field is `"napi"` or `"wasm"` — **never `"auto"`**. A
silent fallback from NAPI → WASM would defeat the purpose of the harness
(we specifically want to compare the two). If a mode cannot be loaded, the
runner returns a structured error; pytest surfaces this as a test failure,
not a skip.

### Normalization pipeline

Raw bridge outputs differ superficially in ways that do not indicate real
behavioral divergence:

- **Case**: PyO3 returns snake_case keys; NAPI returns camelCase; WASM
  varies.
- **Bytes representation**: PyO3 `bytes`, NAPI `Buffer` / `number[]`, WASM
  `Uint8Array`.
- **Timestamps**: created_at is local wall-clock.
- **Nonces / random IDs**: different per call.

The `normalizer.py` module applies a declarative schema (`OpSchema`) with
per-field `FieldSpec` comparators:

| Comparator         | Semantics |
|--------------------|-----------|
| `exact`            | Values must match literally after case/byte canonicalization |
| `base64_bytes`     | Coerce bytes/Buffer/Uint8Array/list[int] to base64 str and compare |
| `ignore`           | Drop the field; it is expected to vary |
| `regex`            | Value must match the supplied pattern (shape-only) |
| `timestamp_window` | Both values must be within `window_secs` of each other |

Normalization order:
1. Recursively snake_case keys (`contextId` → `context_id`).
2. Coerce byte-like types to base64 strings.
3. Apply per-field comparator: `ignore` drops the key, `base64_bytes`
   canonicalizes, etc.
4. Sort dict keys for stable output.

### Determinism and crypto outputs

Crypto outputs (DIDs, verifying keys, signatures) are derived from
non-deterministic key generation across bridges. To compare byte-equality
would require a `seed: Option<[u8; 32]>` parameter on identity creation in
every bridge, routed to a deterministic RNG behind `#[cfg(feature =
"testing")]`. That is a multi-bridge change out of scope for the MVP.

**MVP decision**: use **shape-only comparators** (regex / ignore) for
crypto-generated identifiers on `identity_create_deterministic` and
`sign_message`. The DID must match `did:dht:z[1-9a-km-np-zA-HJ-NP-Z]+`,
the verifying key must be 32-byte base64, the signature must be 64-byte
base64 — but we do not require cross-bridge byte equality.

This trades off a class of findings (bit-exact crypto divergence) for
shipping the harness now. When a bridge-wide `seed` parameter lands, flip
the comparators to `base64_bytes` in `seed_operations.py`; the rest of the
framework is unaffected. A follow-up note is filed in
`bindings/python/tests/bridge_parity/FOLLOWUP.md`.

### Seed operation library

MVP ships exactly five operations:

| ID  | Op                           | What it exercises                        |
|-----|------------------------------|------------------------------------------|
| 1   | `identity_create_deterministic` | Identity creation, DID shape, key shape |
| 2   | `context_create`             | Context ID shape, creator DID routing    |
| 3   | `invalid_capability_rejected` | Error path parity (error code equality)  |
| 4   | `event_log_append`           | Event sequence, payload, Merkle root     |
| 5   | `sign_message`               | SCPID sign — signature shape, algorithm  |

The library is a **list** of `OpSpec` dataclasses, not a class hierarchy:
adding an op is a ~20-line change (one `OpSpec`, one `py_call`, one
`node_call` dispatch in the runner). This is the explicit "expansion is
not completion" contract — the framework ships complete, and the op library
grows monotonically.

### CI: new `bridge-parity` job

A new job in `.github/workflows/ci.yml`:

- Triggers when `python`, `typescript`, or `rust` paths change.
- Sets up Python 3.12, Bun, Rust, wasm-pack.
- Builds PyO3 (`maturin develop --release --features scp-core/testing,allow_in_memory_custody`).
- Builds NAPI (`cargo build -p scp-ffi-napi --release --features scp-ffi-napi/allow_in_memory_custody,scp-core/testing`) and wires the addon into `bindings/typescript/node_modules/` mirroring `typescript-check`.
- Builds WASM with `wasm-pack build --target nodejs --release --out-dir pkg-node`
  and wires the output into `node_modules/@limn-works/scp-ts-wasm`. The
  `nodejs` target (not `bundler`) is required because the parity harness
  runs the WASM bridge under Bun, which uses a Node-style runtime loader.
  `--target bundler` emits ESM with a bare `import * from "./X.wasm"` that
  only works behind a bundler; `--target nodejs` emits a self-loading
  CJS-compatible module Bun can consume directly. See the rationale
  comment in `.github/workflows/ci.yml` (job `bridge-parity`, step "Build
  WASM bridge").
- Runs `pytest bindings/python/tests/bridge_parity/ -v -m parity`.
- Joins the final `ci` aggregator gate.

## Alternatives considered

### TypeScript-hosted harness

Flip the topology: TS harness spawns a Python child. Rejected because it
forces NAPI or WASM to be the reference bridge. PyO3 is the most mature
bridge (it has documented parity targets in multiple places), has the
richest API surface, and running it in-process (no subprocess overhead) is
faster. A PyO3 subprocess adds complexity (double serialization, process
management) for no correctness gain.

### Rust-hosted harness

A Rust test crate that somehow loads PyO3 + NAPI as libraries into the
same process. Rejected because:

- PyO3 requires a Python interpreter in-process (embedding works but
  complicates CI).
- NAPI native addons export N-API symbols, not Rust ABI; loading them as a
  Rust library bypasses the bridge surface entirely.
- You cannot cross-link both runtimes into one Rust binary cleanly.

### Snapshot tests per bridge

Rejected: snapshots catch changes in one bridge, not drift between
bridges. Two bridges can both pass their own snapshots while silently
disagreeing on output shape. The whole point of the harness is to compare
bridges, not a bridge to its historical self.

### Pact / contract testing

Tools like Pact assume network-protocol semantics (provider / consumer,
versioned contracts). Our surface is a function call, not an HTTP
endpoint. Overkill for the problem.

## Consequences

### Positive

- Behavioral drift between bridges becomes a CI failure, not a post-ship
  bug report.
- The op library is the authoritative "spec of behavior that must be
  identical across bridges" — a living artifact that is easier to audit
  than the bridge source files themselves.
- New bridges (future UniFFI Swift/Kotlin) can be added as additional
  `alt_bridge` modes without restructuring the harness.

### Negative

- Requires a Bun child subprocess at test time — one more moving part in
  CI. Mitigated: single long-lived child per test session, not per test.
- MVP does not catch byte-exact crypto divergence. Tracked in FOLLOWUP.md.

### Open questions

- **JVM/Swift runners**: JVM warmup is expensive (~1–2s per process); cold
  Swift (xcrun) even more so on macOS runners. The current design's
  long-lived child approach generalizes — just a different child language.
  Separate CI shape (macOS runners for Swift, JVM warmup strategy for
  Kotlin) is a Phase 6 follow-up, not a blocker for MVP.

## Future work

- Add `"kotlin"` and `"swift"` runners (separate subprocess kinds; same
  JSON-RPC shape).
- Add a `seed: Option<[u8; 32]>` parameter to identity creation in all
  four bridges behind `#[cfg(feature = "testing")]`, then flip
  `identity_create_deterministic` and `sign_message` comparators from
  regex to `base64_bytes` for true crypto parity.
- Expand the op library to cover UCAN mint/validate, transport status,
  tool register/invoke.

## References

- `.docs/adrs/phase-4.md` § ADR-022 — language bindings architecture
- `.docs/adrs/phase-6.md` § ADR-034 — WASM constraint boundary
- `crates/scp-ffi/CLAUDE.md`, `crates/scp-ffi/napi/CLAUDE.md`,
  `crates/scp-ffi/wasm/CLAUDE.md` — bridge-specific design notes
- `bindings/python/tests/bridge_parity/` — harness implementation
