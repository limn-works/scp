# Fuzz Crate — Agent Instructions

## Critical: Standalone Crate

The `fuzz/` directory is a **standalone cargo-fuzz crate, NOT a workspace member**. It has its own `[workspace]` block in `fuzz/Cargo.toml`. Never add `fuzz` to the root `Cargo.toml` members list. Never run `cargo clippy --workspace` from the repo root and expect it to cover fuzz targets — workspace lints do not apply here.

## Nightly Rust Required

All `cargo fuzz` commands require the nightly compiler. Always use `+nightly`:

```sh
cargo +nightly fuzz run <target> --fuzz-dir fuzz -- -dict=fuzz/dicts/<dict> -max_total_time=60
cargo +nightly fuzz list --fuzz-dir fuzz
cargo +nightly fuzz coverage <target> --fuzz-dir fuzz
```

Running with stable Rust will fail with a linker or feature error. This is not a configuration bug — it is a libFuzzer requirement.

## Target Conventions

### Tier 1-2: Raw Bytes + Dictionary

Targets that parse untrusted wire-format bytes use raw byte slices:

```rust
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SomeType::from_bytes(data);
});
```

Run with the corresponding dictionary:

```sh
cargo +nightly fuzz run fuzz_outer_envelope --fuzz-dir fuzz \
  -- -dict=fuzz/dicts/msgpack_outer_envelope.dict \
     -max_total_time=900 -max_len=1048576
```

Do NOT wrap raw bytes in `Arbitrary` types for parser targets. This breaks libFuzzer's mutation-coverage feedback loop — the fuzzer mutates the `Arbitrary` binary encoding, not the parser input, and coverage guidance stops working.

### Tier 3-4: Structured Arbitrary

Targets that test security invariants or require semantically valid inputs use `Arbitrary` types from `fuzz/src/lib.rs`:

```rust
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use libfuzzer_sys::fuzz_target;
use scp_fuzz::ArbMerkleProof;

fuzz_target!(|input: ArbMerkleProof| {
    // invariant assertions here
});
```

Arbitrary is appropriate when raw bytes cannot reach the code path (e.g., the target requires a cryptographically valid structure, or exercises a differential property between two structurally different inputs).

### Allow Attributes Are Mandatory

Every target file must have these at the top:

```rust
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
```

The libFuzzer harness (`fuzz_target!` macro) uses panics for crash detection. Clippy denials on these lints would prevent the crate from building.

### No Unsafe in Target Code

Targets call production `pub` functions only. No `unsafe` in `fuzz_targets/`. If a production function requires unsafe, it must be wrapped in the production crate — not in the fuzz target.

## Dictionary Files

Location: `fuzz/dicts/` (one file per target family).

Format: libFuzzer dictionary syntax — one token per line, strings in double quotes:

```
# Comment
"field_name"
"\x81"
"\xc4\x20"
```

Include:
- All field names from the target type's `#[serde(rename = "...")]` attributes
- MessagePack structural bytes (fixmap headers `\x8N`, fixarray `\x9N`, bin8/16/32 `\xc4/c5/c6`, str8/16 `\xd9/da`)
- Common length prefixes and integer encodings used in valid messages

When to update a dictionary:
- A new field is added to the target type's serde attributes
- A new enum variant is added to a type the target parses
- A new structural token is introduced (e.g., a new extension key)

Forgetting the `-dict=` flag is the single most common cause of poor fuzzer coverage on MessagePack targets. Without the dictionary, the fuzzer spends most of its time on random bytes that are rejected before reaching any interesting code.

## Adding a New Fuzz Target

1. **Identify the trust boundary:**
   - B1: Relay wire protocol (unauthenticated TCP input)
   - B2: Post-MLS decryption (authenticated but untrusted plaintext)
   - B3: Resolution/discovery (network adversary, DHT poisoning)

2. **Determine strategy:**
   - Raw bytes + dict: parser targets (Tier 1-2)
   - `Arbitrary`: semantic invariant targets (Tier 3-4)

3. **Set `-max_len`** based on protocol constants. Check `serde_util.rs` for `MAX_*` bounds. Default 4096 is too small for envelope targets (Tier 1 needs 1 MiB).

4. **Create the dictionary** in `fuzz/dicts/` with all field names from the target type's serde attributes, plus MessagePack structural bytes.

5. **Create a seed corpus** in `fuzz/corpus/<target>/` (see `fuzz/README.md` §Adding a New Target for the full seed file workflow):
   - At least one valid input per enum variant
   - Known-bad boundary probes: empty input, max-length, truncated, oversized
   - Commit a `.gitkeep` if no seeds exist yet; add seeds before the first nightly run

6. **Map to security invariants** (I1-I10) — document in the target file which invariants the target asserts.

7. **Add `[[bin]]` entry** to `fuzz/Cargo.toml`.

8. **Add to CI matrix** in `.github/workflows/fuzz.yml` under the appropriate tier.

9. **Verify locally:**
   ```sh
   cargo +nightly fuzz run <target> --fuzz-dir fuzz -- -max_total_time=60
   ```

## Modifying Existing Targets

- If a production type's serde attributes change (field added/removed/renamed), update the corresponding dictionary file immediately. The `fuzz-build` CI check will catch compilation breakage but not dictionary staleness.
- If a new enum variant is added to a parsed type, add a seed to `fuzz/corpus/<target>/`.
- Never weaken an invariant assertion (e.g., remove an `assert!` or change `panic!` to a `return`). Weakening invariants requires human approval.

## Corpus Directories

- `fuzz/corpus/<target>/` — checked in (seeds). These are the starting inputs the fuzzer uses.
- `fuzz/artifacts/<target>/` — gitignored (crash outputs). Never check in crash artifacts without minimization.

To minimize a crash artifact before checking it in:

```sh
cargo +nightly fuzz tmin <target> --fuzz-dir fuzz fuzz/artifacts/<target>/crash-<hash>
```

Then move the minimized file to `fuzz/corpus/<target>/`.

## Corpus Growth and Minimization

The nightly CI job runs `cargo fuzz cmin` after each run to prevent unbounded corpus growth. When running locally for extended campaigns, do the same:

```sh
cargo +nightly fuzz cmin <target> --fuzz-dir fuzz fuzz/corpus/<target>
```

## Fuzz Crate Dependencies

The fuzz crate depends on production crates via path dependencies:

```toml
scp-protocol = { path = "../crates/scp-protocol", features = ["testing"] }
scp-transport = { path = "../crates/scp-transport" }
scp-runtime = { path = "../crates/scp-runtime", features = ["testing"] }
scp-event-log = { path = "../crates/scp-event-log" }
```

If a production crate's public API changes and breaks a fuzz target, fix the fuzz target. Do not skip it. The `fuzz-build` CI check runs `cargo +nightly check --manifest-path fuzz/Cargo.toml` on every PR and will catch this.

## Security Invariants

Every target asserts at minimum **I1** (no panic on any untrusted input). Additional invariants:

| ID | Invariant | Verified By |
|----|-----------|-------------|
| I1 | No panic on any untrusted input | All targets |
| I2 | No unbounded allocation (bounded by protocol constants) | T1-T6, T10-T11, T14-T15 |
| I3 | Cryptographic signatures unforgeable (no structural bypass) | T16, T18 |
| I4 | Nonce replay prevention: accepted nonce never re-accepted | — (future T20) |
| I5 | Epoch monotonicity: no rollback | — (future T19) |
| I6 | Timestamps outside `[now - max_age, now + skew]` always rejected | T18 |
| I7 | Capabilities outside ceiling always rejected | — (T18 fixes capability + ceiling, not exercised) |
| I8 | Delegation chain verification terminates (depth ≤ 32) | — (T18 uses empty `prf`, no chain walked) |
| I9 | Different `(context_id, sender_did)` → different AAD | T17 |
| I10 | Different `InnerEnvelopeParams` → different canonical hash | T16 |

## Common Pitfalls

- **Forgetting `-dict=` flag** — MessagePack targets waste 99% of fuzzer time without dictionaries. Coverage will not reach past the first fixmap byte.
- **Wrong `-max_len`** — The default is 4096 bytes. Tier 1 envelope targets need 1 MiB (`-max_len=1048576`). Without this, the fuzzer never generates valid-length blobs.
- **`Arbitrary` for parser targets** — Breaks mutation-coverage feedback. Use raw bytes + dict for anything that calls `from_bytes` or a string parser.
- **Running with stable Rust** — Will fail. Must use `+nightly`.
- **Checking in crash artifacts** — Always minimize with `fuzz tmin` first, then move to corpus.
- **Adding the fuzz crate to root workspace** — Never do this. It breaks normal CI.
