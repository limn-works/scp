# Review the Class, Not the Instance

**Problem**: A reviewer finds one defect, writes one finding, and a fix agent fixes one site. The next round rediscovers the same defect at a sibling site, after a full verification cycle has run. Changing one error code in `crates/scp-ffi/uniffi/src/bridge.rs` left the same stale assertion in that file's own `tests` module and in the Kotlin and Swift custody test suites, and it took three rounds to fix — where one `git grep` for the old code, run at the first fix, would have found all three sites.

**Root cause**: A reviewer understands the defect the moment it reads the first site, and it writes the finding without carrying that understanding to the siblings. Green checks do not carry it either. In `.github/workflows/ci.yml`, `rust-test-napi-production` ran `cargo test` while `rust-build-pyo3-production` and `rust-build-uniffi-production` ran `cargo build`, so those two lanes compiled none of their own production-configuration assertions and stayed green anyway. Fixing the PyO3 lane and leaving the UniFFI one cost another three hours.

**Rule**: `CLAUDE.md` states this rule in the Agents section, below "Take every finding seriously", quoting Alec verbatim. Search every sibling site before writing the finding, and report the class as one finding naming each site.

**Related**: the same incident produced the push cadence in the Change protocol of `CLAUDE.md`, below "Run CI locally before pushing" — one full gate run on the tree you are about to push, not one per commit.
