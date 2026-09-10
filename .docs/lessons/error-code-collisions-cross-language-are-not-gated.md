# A New Error Code Must Be Checked Against the Registry Table by Hand, Because the Gate Cannot See Across Languages

**Rule**: Before allocating a `SCP-<PREFIX>-<NUMBER>`, read
`.docs/standards/sdk-common.md` and confirm no other owner holds that number.
`scripts/check-error-codes.sh` will not catch a collision with a code that only
an SDK wrapper defines, and it says so in its own source.

**Context**: pull request #2364 added a code for "the selected durable storage
backend failed to open" and numbered it `SCP-STORAGE-8001`. All three Rust
bridges raised it, four SDK suites asserted it, and every gate passed.

`SCP-STORAGE-8001` was already taken twice over. The registry at
`.docs/standards/sdk-common.md:297` assigns it to `scp-kt-android`
`AndroidStorage` for "storage key not found", and
`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/AndroidStorage.kt:329`
defines `ERROR_KEY_NOT_FOUND` as that literal. An Android app links
`AndroidStorage` and the `UniFFI` bridge into one process, so that app would have
received one code string meaning two conditions, with no way to tell them apart.

**Why the gate passed**: `scripts/check-error-codes.sh` runs four phases, and
none of them covers this case.

- Phase 1 checks that the number sits inside its prefix's band. `8001` sits
  inside `8000`--`8999`, so it passed.
- Phase 2 detects one number used for two purposes by fingerprinting the error
  *message* on each line that constructs an error. Its own comment names the
  limitation: "SDK-wrapper literals in Python/TS/Swift/Kotlin that construct
  typed errors with ad-hoc `SCP-...` strings ... are NOT inspected by this
  Phase-2 detector ... SDK literals must be reviewed manually against
  `error_codes.rs`". `AndroidStorage.ERROR_KEY_NOT_FOUND` is a bare `const`
  assignment in Kotlin, so no fingerprint was ever recorded for it.
- Phase 3 requires each quoted code literal to appear exactly once inside
  `crates/scp-ffi/common/src/error_codes.rs`. The Kotlin constant is not in that
  file, so nothing was duplicated there.
- Phase 4 covers only the outlet `6100`--`6199` sub-block.

**Fix**: the code became `SCP-STORAGE-8004` — the next number free of the
Android sub-block (`8001`--`8003`) and the `scp-client-wasm` sub-block
(`8010`--`8013`) — with a row in the registry table naming its owner, and
`crates/scp-ffi/common/tests/storage_code_allocation.rs` asserting that neither
selection-layer code takes a number another backend owns.

That test lives outside `src/error_codes.rs` on purpose. Phase 3 requires one
quoted code literal per registry constant in that file, so a test module holding
`"SCP-STORAGE-8001"` there reads as a second constant claiming that number, and
the gate rejects it.

**Lesson**: three takeaways.

1. **A green gate is evidence about what the gate checks, not about what you
   asked.** This gate documents its own blind spot in a comment eleven lines
   long. Read a gate's stated scope before treating its pass as an answer.
2. **The cross-language owner map is prose, and prose does not run.** The
   `SCP-STORAGE-` table in `.docs/standards/sdk-common.md` is the only artifact
   that records which backend owns which number across Rust, Kotlin and wasm.
   Consult it when allocating, and add a row when you allocate.
3. **A per-owner test can pin what the gate cannot.** Mapping a source file to
   an owner mechanically would mean inventing a path-to-owner rule nobody
   decided, which is the extrapolation-as-contract failure `CLAUDE.md` forbids.
   A test that names the numbers one owner holds, and asserts your constants
   avoid them, states the same guarantee without inventing that rule.
