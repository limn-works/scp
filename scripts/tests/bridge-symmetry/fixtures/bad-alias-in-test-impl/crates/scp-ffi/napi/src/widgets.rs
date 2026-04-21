// Adversarial fixture: the canonical alias `widget_create` is declared in
// bridge-aliases.json as an exported NAPI symbol, but the only `fn
// widget_create(...)` definition in this file is a method inside a
// `#[cfg(test)] impl Context { ... }` block. A naive scanner that descends
// into every impl block regardless of its cfg attributes would report the
// alias as present; the correct behavior is to treat the entire test-gated
// impl block as invisible and REPORT the alias as missing.
//
// Mirrors the `bad-alias-in-test-module-only` fixture (which gates `mod`
// rather than `impl`). Both scanners — awk in check-bridge-symmetry.sh and
// `syn` in ffi_conformance.rs — must reject this pattern.

pub struct Context;

pub fn widget_create_not_real() {}

#[cfg(test)]
impl Context {
    pub fn widget_create() {
        // This must NOT satisfy the alias scanner.
    }
}
