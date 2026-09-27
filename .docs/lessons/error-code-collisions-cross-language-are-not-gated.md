# Error Codes: the Gate Cannot See Across Languages, and It Scans Test Fixtures

## Check a new code against the registry table by hand

Before allocating a `SCP-<PREFIX>-<NUMBER>`, read the registry tables in
`.docs/standards/sdk-common.md` and confirm no other owner holds the number, then add a row
naming the owner. `scripts/check-error-codes.sh` cannot catch a collision with a code that
only an SDK wrapper defines, and its own comments say so:

- Phase 1 checks only that the number sits inside its prefix's band.
- Phase 2 fingerprints error messages on lines that construct errors and does not inspect
  SDK-wrapper literals; a bare Kotlin `const` never gets a fingerprint.
- Phase 3 requires each quoted code to appear once in
  `crates/scp-ffi/common/src/error_codes.rs`, and a Kotlin constant is not in that file.

Pull request #2364 allocated `SCP-STORAGE-8001` for "storage backend failed to open" and
every gate passed, while `AndroidStorage.ERROR_KEY_NOT_FOUND` already held that number. An
Android app links both into one process and would have received one code meaning two
conditions. The code became `SCP-STORAGE-8004`, and
`crates/scp-ffi/common/tests/storage_code_allocation.rs` asserts that the selection-layer
codes avoid every number another backend owns. That test lives outside `src/error_codes.rs`
because Phase 3 would read a second quoted literal there as a second constant.

## Test fixtures pass the same gate

`scripts/check-error-codes.sh` scans every `.ts`, `.py`, and `.rs` file, tests included. A
placeholder such as `SCP-GOV-6001` (the governance band is 11000–11999) or an unknown prefix
such as `SCP-WEIRD-9999` turns CI red. In a fixture, use a real in-range code for the category
under test, or the `SCP-UNKNOWN-*` or `SCP-TEST-*` sentinel the script allowlists.
