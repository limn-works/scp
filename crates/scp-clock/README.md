# scp-clock

The **clock port** for SCP (Shared Context Protocol): the `Clock` trait plus its
production (`SystemClock`) and deterministic-test (`TestClock`) implementations.

This is a wasm-safe capability leaf — `std`-only, no async, no other SCP crate —
so it compiles to `wasm32-unknown-unknown` for the in-browser SCP client
(ADR-057). Every consumer that needs wall-clock time (UCAN expiry, nonce
freshness, checkpoint timestamps, `KeyPackage` lifetimes) injects a `&dyn Clock`
rather than reading the system clock directly, which keeps time controllable in
tests and hardenable in the browser.

A system clock before the Unix epoch is treated as an unrecoverable environment
failure (it would otherwise bypass expiry/freshness checks), so `SystemClock`
panics rather than silently returning `0`.

Part of the `scp-clock` / `scp-crypto` / `scp-did` split that dissolved the old
`scp-primitives` junk-drawer crate (ADR-057 Amendment, 2026-06-30).
