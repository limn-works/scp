---
name: ffi-dedup-must-carry-error-codes
description: When a shared scp-ffi/common module dedupes logic across the three bridges, check that it also owns the error-CODE mapping, not just the message text — that is where the three bridges keep drifting.
metadata:
  type: project
---

A shared module in `crates/scp-ffi/common/src/` that returns a typed error enum
must also expose the canonical `SCP-XXXX-NNNN` code for each variant. Deduping
only the message string leaves each bridge to pick its own code, and the three
bridges then diverge silently while every surrounding comment still claims
parity.

**Why:** `key_file.rs` (PR #2415, branch `spec/custody-vocabulary-names-the-backend`)
extracted `open_default_key_file` so the three bridges "cannot drift on the path,
the environment variable, or the message text" — a claim scoped to exactly the
part that was shared. The code mapping stayed per-bridge and had already drifted
three ways on one `KeyFileError`: `MissingPassphrase` → `SCP-VALID-7001` on PyO3
and `SCP-VALID-7005` on NAPI/UniFFI; `Open` → `SCP-IDENT-1001` on PyO3/NAPI and
`SCP-IDENT-1002` ("Identity not found") on UniFFI. The Python and TypeScript SDK
docstrings then documented different codes for the same failure.

**How to apply:** reviewing any new or grown `scp-ffi/common` module, ask which
`error_codes.rs` constant each variant maps to and whether that mapping lives in
the shared module. If each bridge does its own `match e { ... code: codes::X }`,
that is the finding — the fix is `impl Error { fn code(&self) -> &'static str }`
in the shared module, with the bridge only choosing its own error *type*.
Also check the surrounding parity comment: a comment that enumerates what cannot
drift (path, env var, message) is a signal that something outside that list did.

Related: [[commit12-helpers-logic-split]] — same instinct, one layer up.
