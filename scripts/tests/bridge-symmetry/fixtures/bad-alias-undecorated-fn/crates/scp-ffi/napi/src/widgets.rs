// Adversarial fixture: the canonical alias `widget_create` is declared in
// bridge-aliases.json as an exported NAPI symbol, and a `pub fn widget_create`
// definition exists at module scope — but it is NOT decorated with `#[napi]`,
// so napi-rs never registers it as a Node-callable export. A naive scanner
// that matches `fn widget_create(` (or even `pub fn widget_create(`) would
// report the alias as resolved; the strict scanner refuses because the
// binding tooling never sees the fn. This is the phantom-alias hole the
// PR-E (#26) hardening closes.
//
// A `pub(crate) fn ghost_op` is included to cover the secondary phantom
// shape the plan calls out: a non-pub fn that compiles fine but never
// crosses the FFI boundary regardless of any decoration the macro might
// or might not be applied to.
//
// The PyO3 / UniFFI siblings DO carry their bridge-specific macro
// so the script's finding pinpoints napi exclusively.

pub fn widget_create() {}

pub(crate) fn ghost_op() {}
