// Adversarial fixture: the canonical alias `widget_create` is declared in
// bridge-aliases.json as an exported NAPI symbol, but the only `fn
// widget_create(...)` definition in this file is hidden inside a
// `#[cfg(test)] mod tests { ... }` block. A naive substring scanner (e.g.
// grep 'fn widget_create(') would report the alias as present; the correct
// behavior is to treat the test-module definition as invisible and REPORT
// the alias as missing.

pub fn widget_create_not_real() {}

#[cfg(test)]
mod tests {
    pub fn widget_create() {
        // This must NOT satisfy the alias scanner.
    }
}
