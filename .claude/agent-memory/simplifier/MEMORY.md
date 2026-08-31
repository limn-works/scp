# Simplifier Memory

- [Commit 12 helpers/logic split rule](project_commit12_helpers_logic_split.md) — `*_helpers.rs` takes `&Supervisor`; `*_logic.rs` is pure value-shape free functions.
- [FFI dedup must carry error codes](project_ffi_dedup_must_carry_error_codes.md) — a shared `scp-ffi/common` module owns the code mapping too, not just the message; that is where the three bridges drift.
