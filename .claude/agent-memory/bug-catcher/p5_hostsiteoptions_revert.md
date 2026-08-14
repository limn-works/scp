# P5 HostSiteConfig→HostSiteOptions revert (feat/p5-downstream-updates)

ADR-052 Phase B-P5 reverted the construction-pattern enum API (`HostSiteConfig`
with `Reach`/`TlsMode` enums + `defaults(reach)` factory) back to the flat bool
`HostSiteOptions` (`plaintext`/`skip_nat`/`dht_mode`, with whole-struct
`Default`). Compiles clean (`-p scp-node --features upnp,allow_unencrypted_storage
-- -D warnings`), all unit + integration tests pass.

## Findings

- **MEDIUM — self_host_banner lies in memory mode (main.rs):** The P5 commit
  dropped the `publishes_dht` parameter from `self_host_banner(port, plaintext)`
  and deleted the `self_host_banner_memory_mode_states_no_publish` test. The
  banner now UNCONDITIONALLY prints "Your host's PUBLIC IP will be published to
  the global Mainline DHT ... IP<->identity disclosure" even when
  `SCP_NODE_DHT_MODE=memory` (still a supported, help-documented self-host mode
  → `DhtMode::Memory` → `InMemoryDhtClient`, publishes nothing). Banner is the
  operator's only pre-socket disclosure. This is a privacy-disclosure-accuracy
  regression: prior code branched the line on `publishes_dht`. NOT a crash/compile
  bug. Fix: restore the `publishes_dht` arg + conditional `dht_line` (parse
  `dht_mode` before the banner as the pre-P5 code did) and restore the deleted
  test.

- **LOW — orphaned re-added doc:** `.docs/guides/deploying-an-scp-website.md` is
  deleted on HEAD but re-added (staged `A`) in the working tree with corrected
  `HostSiteOptions` content. BUT both prior inbound links were removed on HEAD
  (examples/README.md line + self-hosting guide line 2) and NOT restored. The
  re-added guide is now unreferenced/undiscoverable. Either restore a link or the
  deletion was intended. Discoverability, not a code bug.

## Non-issues verified (don't re-flag)
- Builder migration in `run_node_with`: `.domain()` + no tls_provider correctly
  defaults to headless ACME w/ no email (resolve_tls → AcmeProvider::new, email
  None) — matches old `TlsMode::Acme { email: None }` default.
- `dht_mode` now independent of `skip_nat` (old code forced Memory when
  skip_nat); intended by new flat API, wired correctly via `match dht_mode` in
  host_site_until. Not a bug.
- `integration.rs` build_for_testing/dev "method not found" only when clippy run
  WITHOUT `allow_unencrypted_storage` (gate: cfg(any(test,
  feature="allow_unencrypted_storage"))). False alarm — always add that feature.
