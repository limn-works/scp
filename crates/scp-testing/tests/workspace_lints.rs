//! Structural test: the workspace lint table allows no lint that only a per-site
//! ruling may allow.
//!
//! `clippy::unused_async_trait_impl` (clippy 1.98.0) reports an `async fn` whose
//! body never awaits, inside an impl block. Allowing it in
//! `[workspace.lints.clippy]` turns it off at every impl block in the
//! repository, including impl blocks written after the allow. That lint reported
//! `LocalHandleQuerier`'s two empty-vector lookups, a capability that answers "no
//! match" where it cannot perform the lookup at all, and no other check reported
//! them.
//!
//! `.docs/standards/rust.md`, section `clippy::unused_async_trait_impl`, states
//! the criterion for allowing the lint at one site and forbids allowing it at the
//! workspace level. This test enforces the second half.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Reads the workspace root `Cargo.toml`.
///
/// `CARGO_MANIFEST_DIR` points at `crates/scp-testing`, so the workspace root is
/// two levels up.
fn workspace_manifest() -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/scp-testing has a grandparent directory");
    let path = root.join("Cargo.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Returns the body of the `[workspace.lints.clippy]` table: every line after
/// that header, up to the next line that opens a table.
fn workspace_lints_clippy_table(manifest: &str) -> String {
    let mut lines = manifest.lines();
    let found = lines.any(|line| line.trim() == "[workspace.lints.clippy]");
    assert!(
        found,
        "the workspace manifest declares no [workspace.lints.clippy] table"
    );
    lines
        .take_while(|line| !line.trim_start().starts_with('['))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns the lint names the table sets to `allow`, in the two spellings the
/// table uses: `name = "allow"` and `name = { level = "allow", .. }`.
fn allowed_lints(table: &str) -> Vec<String> {
    table
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let (name, value) = line.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let value = value.trim();
            let allows = value == "\"allow\""
                || (value.starts_with('{') && value.contains("level = \"allow\""));
            allows.then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn workspace_lint_table_does_not_allow_unused_async_trait_impl() {
    let manifest = workspace_manifest();
    let table = workspace_lints_clippy_table(&manifest);
    let allowed = allowed_lints(&table);

    assert!(
        !allowed.iter().any(|name| name == "unused_async_trait_impl"),
        "[workspace.lints.clippy] allows `unused_async_trait_impl`, which turns the \
         lint off at every impl block in the repository. Allow it at the one site \
         instead, under the criterion in `.docs/standards/rust.md`, section \
         `clippy::unused_async_trait_impl`. Allowed lints found: {allowed:?}"
    );
}

#[test]
fn the_table_parser_reads_the_allows_the_table_carries() {
    // A gate that reports OK because it parsed nothing is the failure mode this
    // test rules out: the parser must find the allows the table is known to
    // carry.
    let manifest = workspace_manifest();
    let table = workspace_lints_clippy_table(&manifest);
    let allowed = allowed_lints(&table);

    for expected in ["multiple_crate_versions", "cargo_common_metadata"] {
        assert!(
            allowed.iter().any(|name| name == expected),
            "the parser did not find `{expected}`, which [workspace.lints.clippy] \
             sets to allow. Allowed lints found: {allowed:?}"
        );
    }

    // The `{ level = "warn", priority = -1 }` group entries are not allows.
    for group in ["all", "pedantic", "nursery", "cargo"] {
        assert!(
            !allowed.iter().any(|name| name == group),
            "the parser read the `{group}` group entry as an allow; it sets `warn`"
        );
    }
}

#[test]
fn the_table_parser_would_catch_a_reintroduced_workspace_allow() {
    // Both spellings a re-introduction could use, checked against the parser
    // rather than against the manifest, so this assertion holds whatever the
    // manifest says.
    let bare = "unused_async_trait_impl = \"allow\"\n";
    assert!(
        allowed_lints(bare)
            .iter()
            .any(|name| name == "unused_async_trait_impl"),
        "the parser missed the bare `= \"allow\"` spelling"
    );

    let table_valued = "unused_async_trait_impl = { level = \"allow\", priority = -1 }\n";
    assert!(
        allowed_lints(table_valued)
            .iter()
            .any(|name| name == "unused_async_trait_impl"),
        "the parser missed the `{{ level = \"allow\" }}` spelling"
    );
}
