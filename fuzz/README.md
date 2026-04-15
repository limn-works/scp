# SCP Fuzzing Infrastructure

## Overview

SCP's fuzzing infrastructure uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) to find
parser panics, serde edge cases, and exploitable deserialization paths at every protocol trust boundary.

Fuzzing occupies a distinct layer in SCP's testing pyramid:

```
  Integration / E2E tests    ← behavioral correctness across components
  Fuzz targets               ← parser safety + security invariants at trust boundaries
  Property tests (proptest)  ← algebraic properties of individual types
  Unit tests                 ← local function correctness
```

Fuzz targets are highest-value for SCP because relays are **explicitly untrusted** — any TCP connection can
send bytes to `OuterEnvelope::from_bytes`. Post-MLS decryption is a separate trust boundary because MLS
authentication success does not imply that the plaintext is well-formed. Every target asserts at minimum
security invariant **I1** (no panic on any untrusted input).

Calibrated expectations: ~30% chance of finding a panic in the first 24 hours of a new Tier 1 target
(most likely from `rmpv::Value` deep nesting or `#[serde(flatten)]` type confusion). The long-term value
is **regression detection** as the protocol evolves — catching new parsing bugs before they ship.

## Quick Start

### Install prerequisites

```sh
# Nightly Rust (required by cargo-fuzz)
rustup toolchain install nightly

# cargo-fuzz
cargo install cargo-fuzz --locked
```

Or via mise (if configured in the repo):

```sh
mise install
```

### Run a single target for 60 seconds

```sh
cargo +nightly fuzz run fuzz_outer_envelope --fuzz-dir fuzz \
  -- -dict=fuzz/dicts/msgpack_outer_envelope.dict \
     -max_total_time=60 -max_len=1048576
```

When the fuzzer starts, you'll see libFuzzer output like:

```
INFO: Seed: 1234567890
INFO: Loaded 1 modules   (NNN guards): NNN [0x..., 0x...)
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
#2     INITED cov: 42 ft: 42 corpus: 1 exec/s: 0 rss: 29Mb
#5     NEW    cov: 78 ft: 90 corpus: 2 exec/s: 0 rss: 30Mb
```

The `cov:` counter grows as new code paths are discovered. If it plateaus immediately, check that the
`-dict=` flag is present and correct.

If the fuzzer finds a crash:

```
SUMMARY: libFuzzer: deadly signal
...
artifact_prefix='fuzz/artifacts/fuzz_outer_envelope/'; Test unit written to fuzz/artifacts/fuzz_outer_envelope/crash-<hash>
```

See [Crash Workflow](#crash-workflow) below.

### List all targets

```sh
cargo +nightly fuzz list --fuzz-dir fuzz
```

## Target Inventory

All 18 targets, grouped by tier and trust boundary.

**Trust boundaries:**
- **B1** — Relay wire protocol (any unauthenticated TCP connection)
- **B2** — Post-MLS decryption (authenticated but untrusted plaintext)
- **B3** — Resolution / discovery (network adversary, DHT poisoning)

### Tier 1 — Wire Format Parsers (15 min nightly)

Highest priority. Raw bytes + dictionary. Any of these panicking is a P0 security bug.

| Target | Trust Boundary | Strategy | Dict | max\_len |
|--------|---------------|----------|------|---------|
| `fuzz_outer_envelope` | B1 | Raw bytes | `msgpack_outer_envelope.dict` | 1 MiB |
| `fuzz_inner_envelope` | B2 | Raw bytes | `msgpack_inner_envelope.dict` | 1 MiB |
| `fuzz_client_message` | B1 | Raw bytes | `msgpack_client_message.dict` | 512 KiB |
| `fuzz_relay_message` | B1 | Raw bytes | `msgpack_relay_message.dict` | 512 KiB |
| `fuzz_sender_key_dist` | B2 | Raw bytes | `msgpack_sender_key.dict` | 64 KiB |
| `fuzz_scp_credential` | B2 | Raw bytes | `msgpack_credential.dict` | 32 KiB |

### Tier 2 — Parsers & Content Trust Boundaries (5 min nightly)

| Target | Trust Boundary | Strategy | Dict | max\_len |
|--------|---------------|----------|------|---------|
| `fuzz_parse_ucan` | B3 | Raw UTF-8 | `ucan_jwt.dict` | 32 KiB |
| `fuzz_scp_uri` | B3 | Raw UTF-8 | `scp_uri.dict` | 8 KiB |
| `fuzz_capability_uri` | B3 | Raw UTF-8 | `capability_uri.dict` | 4 KiB |
| `fuzz_broadcast_content` | B2 | Raw bytes | `msgpack_broadcast.dict` | 512 KiB |
| `fuzz_deserialize_export` | B2 | Raw bytes | `msgpack_export.dict` | 1 MiB |

### Tier 3 — Invariant & Differential Targets

Test security properties beyond no-panic. Mix of raw bytes and structured `Arbitrary`.

| Target | Trust Boundary | Strategy | Invariants |
|--------|---------------|----------|------------|
| `fuzz_outer_envelope_roundtrip` | B1 | Raw bytes | I1, deser→reser→deser value equality + canonical hash stability |
| `fuzz_sender_header_roundtrip` | B1 | Raw bytes | I1, parse→build→parse identity |
| `fuzz_chunk_envelope` | B2 | Raw bytes | I1, I2 (`total_chunks` allocation bounds) |
| `fuzz_merkle_proof` | B3 | Arbitrary (`ArbMerkleProof`) | I1, I2, single-bit flip in sibling hash changes result |
| `fuzz_canonical_hash_differential` | B2 | Arbitrary (`ArbCanonicalHashInput`) | I1, I10 (different `InnerEnvelopeParams` → different hash) |
| `fuzz_aad_differential` | B2 | Arbitrary (`ArbAadInput`) | I1, I9 (different `(context_id, sender_did)` → different AAD) |

### Tier 4 — Validation Depth & State

Require structured generation to reach code paths that raw bytes cannot.

| Target | Trust Boundary | Strategy | Invariants |
|--------|---------------|----------|------------|
| `fuzz_validate_ucan_deep` | B3 | Arbitrary + real Ed25519 | I1, I3, I6, I7, I8 (expired/revoked/ceiling/depth) |

## Running Locally

### Single target, short run

```sh
cargo +nightly fuzz run fuzz_outer_envelope --fuzz-dir fuzz \
  -- -dict=fuzz/dicts/msgpack_outer_envelope.dict \
     -max_total_time=300 -max_len=1048576 -rss_limit_mb=2048 -timeout=30
```

### Overnight campaign (8+ hours for Tier 1)

```sh
cargo +nightly fuzz run fuzz_outer_envelope --fuzz-dir fuzz \
  fuzz/corpus/fuzz_outer_envelope \
  -- -dict=fuzz/dicts/msgpack_outer_envelope.dict \
     -max_total_time=28800 -max_len=1048576 -rss_limit_mb=2048 -timeout=30 -detect_leaks=0
```

Always pass the corpus directory so the fuzzer can both read seeds and save newly discovered inputs.

### Minimize corpus after a campaign

```sh
cargo +nightly fuzz cmin fuzz_outer_envelope --fuzz-dir fuzz fuzz/corpus/fuzz_outer_envelope
```

Run this periodically — corpus grows unbounded otherwise, slowing future runs.

### Coverage report

```sh
# Build with coverage instrumentation
cargo +nightly fuzz coverage fuzz_outer_envelope --fuzz-dir fuzz fuzz/corpus/fuzz_outer_envelope

# Show coverage (requires llvm-tools)
# The coverage data is in fuzz/coverage/fuzz_outer_envelope/
```

Coverage is the only reliable way to verify that the fuzzer is reaching interesting code. If `cov:` output
in the libFuzzer logs plateaus at a low number, check that:
1. The correct `-dict=` file is specified
2. `-max_len` is large enough to accommodate valid messages
3. The seed corpus has at least one valid input per enum variant

## Adding a New Target

1. **Create the dictionary** in `fuzz/dicts/<name>.dict` with all field names from the target type's serde
   attributes, plus MessagePack structural bytes for msgpack targets (see existing dict files for format).

2. **Add a `[[bin]]` entry** to `fuzz/Cargo.toml`:
   ```toml
   [[bin]]
   name = "fuzz_my_target"
   path = "fuzz_targets/fuzz_my_target.rs"
   test = false
   doc = false
   ```

3. **Write the target** in `fuzz/fuzz_targets/fuzz_my_target.rs`. Use raw bytes + dict for parser targets
   (Tier 1-2). Use `Arbitrary` from `fuzz/src/lib.rs` for invariant targets (Tier 3-4). Always include:
   ```rust
   #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
   ```

4. **Add to the CI matrix** in `.github/workflows/fuzz.yml` under `fuzz-nightly` → `matrix.include`.
   Specify `target`, `dict`, `max_len`, and `time`.

5. **Seed the corpus directory** in `fuzz/corpus/fuzz_my_target/`:
   - At least one valid input per enum variant (valid-per-variant seeds)
   - Known-bad boundary probes: empty input, max-length, truncated, oversized
   - Commit a `.gitkeep` if no seeds exist yet; add seeds before the first nightly run

6. **Verify locally**:
   ```sh
   cargo +nightly fuzz run fuzz_my_target --fuzz-dir fuzz -- -max_total_time=60
   ```

See `fuzz/.claude/CLAUDE.md` for the full agent-facing checklist.

## Crash Workflow

When the fuzzer finds a crash:

### 1. Reproduce

```sh
cargo +nightly fuzz run <target> --fuzz-dir fuzz fuzz/artifacts/<target>/crash-<hash>
```

You should see the same panic/abort. If not, the crash may be non-deterministic (unlikely with libFuzzer).

### 2. Minimize

```sh
cargo +nightly fuzz tmin <target> --fuzz-dir fuzz fuzz/artifacts/<target>/crash-<hash>
```

`tmin` produces a smaller input that still triggers the crash. Copy the minimized file to
`fuzz/corpus/<target>/` for regression coverage.

### 3. File a bug

Open a GitHub issue with:
- Which target crashed
- The stack trace from the reproducer run
- The minimized input (as a hex dump or attached file)
- Severity: DoS (panic = P1), potential memory safety (P0)

### 4. Fix and add regression test

Add a `#[test]` to the relevant production crate that feeds the minimized input directly to the parser.
This prevents regression without requiring the fuzzer to rediscover it:

```rust
#[test]
fn regression_fuzz_outer_envelope_crash_abc123() {
    // Minimized crash input from fuzz/corpus/fuzz_outer_envelope/crash-abc123
    let input = &[0x85, 0x01, ...];
    let _ = OuterEnvelope::from_bytes(input);
}
```

Check the minimized input into `fuzz/corpus/<target>/` (not `fuzz/artifacts/`).

## Corpus Management

Corpus directories live at `fuzz/corpus/<target>/` and are checked into git (seeds only). The nightly CI
job runs `cargo fuzz cmin` after each run to prevent unbounded growth. The corpus key in GitHub Actions
cache accumulates across nightly runs, so the fuzzer builds on prior discoveries automatically.

Best practices:
- Commit one valid input per enum variant to each corpus directory at target creation time
- Add minimized crash inputs after fixing bugs
- Run `cargo fuzz cmin` locally before committing large corpus additions
- Cross-pollinate related targets: `fuzz_outer_envelope` and `fuzz_outer_envelope_roundtrip` share corpus

## Dictionary File Format

libFuzzer dictionary syntax — one token per line:

```
# Comment lines start with #
"field_name"       # string token
"\x81"             # escaped hex byte
"\xc4\x20"         # multi-byte sequence
```

For MessagePack targets: include all field names from `#[serde(rename = "...")]` attributes, fixmap
headers (`\x81`–`\x8f`), fixarray headers (`\x91`–`\x9f`), bin8/16/32 prefixes (`\xc4/\xc5/\xc6`),
str8/16 prefixes (`\xd9/\xda`), nil/true/false (`\xc0/\xc2/\xc3`), and common integer encodings.

For JWT/text targets: include structural punctuation (`.`, `{`, `}`, `"`), algorithm names (`EdDSA`),
JWT fields (`alg`, `typ`, `iss`, `aud`, `exp`, `att`, `prf`), and UCAN-specific keywords.

## Security Invariants

| ID | Invariant | Verified By |
|----|-----------|-------------|
| I1 | No panic on any untrusted input | All targets |
| I2 | No unbounded allocation (bounded by protocol constants) | T1–T6, T10–T11, T14–T15 |
| I3 | Cryptographic signatures unforgeable (no structural bypass) | T16, T18 |
| I4 | Nonce replay prevention: accepted nonce never re-accepted | — (future T20) |
| I5 | Epoch monotonicity: no rollback | — (future T19) |
| I6 | Timestamps outside `[now - max_age, now + skew]` always rejected | T18 |
| I7 | Capabilities outside ceiling always rejected | — (T18 fixes capability + ceiling, not exercised) |
| I8 | Delegation chain verification terminates (depth ≤ 32) | — (T18 uses empty `prf`, no chain walked) |
| I9 | Different `(context_id, sender_did)` → different AAD | T17 |
| I10 | Different `InnerEnvelopeParams` → different canonical hash | T16 |

## CI

### Nightly fuzzing job

`.github/workflows/fuzz.yml` runs at 03:00 UTC every night:

- **Tier 1 targets**: 15 minutes each (900s)
- **Tier 2 targets**: 5 minutes each (300s)
- Parallel matrix — all targets run simultaneously
- Corpus cached per-target with `actions/cache`; `cargo fuzz cmin` runs after each campaign to keep it trim
- Crash artifacts uploaded on failure, retained 90 days
- `fail-fast: false` — one target's crash does not stop others

### Weekly deep-fuzz job

Runs at 00:00 UTC every Saturday (or on `workflow_dispatch`):

- **Tier 1 targets only**, 2 hours each (7200s)
- AddressSanitizer enabled (cargo-fuzz default)
- Same corpus cache as nightly — accumulates week-over-week

### PR compilation check

`.github/workflows/ci.yml` includes a `fuzz-build` job on every PR:

```sh
cargo +nightly check --manifest-path fuzz/Cargo.toml
```

This catches compilation breakage without running the fuzzer. If a production type's public API changes
and breaks a fuzz target, this check will fail on the PR that broke it.

### Manual trigger

To trigger a nightly run manually with custom timing:

1. Go to **Actions** → **Fuzz** → **Run workflow**
2. Set "Seconds per target" (default 900)
3. Click **Run workflow**

Crash artifacts are under **Actions** → the workflow run → **Artifacts** → `fuzz-crash-<target>-<run_id>`.

## Sanitizers

| Mode | Sanitizers | When | Notes |
|------|-----------|------|-------|
| Default | AddressSanitizer | Every run (nightly + local) | Cargo-fuzz enables ASan automatically. Catches buffer overflows in dependency `unsafe` (rmp-serde, OpenMLS, aws-lc-sys). |
| Weekly | ASan + UBSan | Saturday deep-fuzz | Catches undefined behavior in dependency C code. |
| Not used | MSan | Never | Requires full instrumented recompilation of aws-lc-sys C — impractical. |
| Future | TSan | Stateful targets | For concurrency bugs in `NonceTracker`/`BudgetTracker`. Not yet implemented. |

To run with UBSan locally (nightly only):

```sh
RUSTFLAGS="-Zsanitizer=undefined" \
  cargo +nightly fuzz run fuzz_outer_envelope --fuzz-dir fuzz \
  -- -dict=fuzz/dicts/msgpack_outer_envelope.dict -max_total_time=300 -max_len=1048576
```

Note: combining `address` and `undefined` sanitizers (`-Zsanitizer=address,undefined`) may not work
cleanly with all dependency C code. If you see spurious sanitizer errors, fall back to ASan alone.
