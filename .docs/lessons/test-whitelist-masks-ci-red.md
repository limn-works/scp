# A Local Test Whitelist Masks CI-Red Regressions

**Problem**: During the actor-per-context refactor, a local "22-test whitelist" (running only a curated subset of `scp-runtime` tests while the migration was in flight) made the worktree look green when the full suite was actually CI-red. CI does not honor the local whitelist — it runs the whole suite with the full feature set — so regressions outside the whitelisted subset were invisible locally and only surfaced after push.

**Root cause**: A whitelist is a convenience for iterating on a known-broken tree, not a verification gate. Treating "the whitelist passes" as "tests pass" conflates a deliberately narrowed local view with the authoritative CI view. The two diverge precisely on the tests the whitelist was added to skip.

**Rule**:
- Before declaring a change done (and always before pushing), run the **full** suite with CI features, not the in-flight whitelist:
  `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") cargo nextest run --workspace` with the CI feature flags (`scp-core/testing,scp-runtime/testing` plus the `allow_in_memory_custody` features per the clippy command in CLAUDE.md).
- A whitelist is allowed only as a temporary iteration aid on a known-broken tree. It is never a stand-in for the verification gate, and "the whitelist is green" is never grounds to report a change complete.
- If a green local run and a red CI run disagree, trust CI: reproduce the full run locally before pushing again.
