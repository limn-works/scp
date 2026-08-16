#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Four lists name governance outcomes, and this test holds them equal.
//!
//! `scp_ffi_common::governance_result::governance_action_result_name` matches
//! every variant of `scp_core::context::state::GovernanceActionResult` with no
//! wildcard arm, so a new variant stops that crate from compiling until someone
//! names it. No compiler sees three SDK lists that mirror those names:
//!
//! - `bindings/python/scp_sdk/governance.py` — `GovernanceActionResult` values,
//! - `bindings/swift/Sources/SCP/Governance.swift` — enum raw values,
//! - `bindings/typescript/src/types.ts` — `GOVERNANCE_ACTION_RESULTS` entries.
//!
//! Each SDK rejects a name its list lacks (`SCP-GOV-11040`), which is right for
//! a caller running an SDK older than its bridge and wrong for a maintainer who
//! added a variant and stopped at Rust. This test tells those two apart by
//! reading all four lists and comparing them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Resolves a path relative to this workspace's root.
fn workspace_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/scp-testing sits two levels below a workspace root")
        .join(relative)
}

/// Reads a file this workspace holds, or panics naming that file.
fn read(relative: &str) -> String {
    let path = workspace_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Collects every double-quoted name on a line, which is how all four lists
/// spell an outcome: `=> "MemberAdded",` in Rust, `= "MemberAdded"` in Python
/// and Swift, `"MemberAdded",` in TypeScript.
fn quoted_names(source: &str, keep_line: impl Fn(&str) -> bool) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in source.lines().filter(|line| keep_line(line)) {
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            let candidate = &after[..close];
            // Every outcome name starts uppercase and carries only letters, so
            // this skips a doc-comment phrase or a code identifier caught by
            // the same line filter.
            if candidate
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase())
                && candidate.chars().all(|c| c.is_ascii_alphanumeric())
            {
                names.insert(candidate.to_owned());
            }
            rest = &after[close + 1..];
        }
    }
    names
}

/// Names every arm of `governance_action_result_name` reports.
fn rust_names() -> BTreeSet<String> {
    let source = read("crates/scp-ffi/common/src/governance_result.rs");
    let body_start = source
        .find("pub const fn governance_action_result_name")
        .expect("governance_action_result_name must exist");
    let body_end = source[body_start..]
        .find("\n}\n")
        .map(|offset| body_start + offset)
        .expect("that function must end");
    quoted_names(&source[body_start..body_end], |line| {
        line.contains("GovernanceActionResult::")
    })
}

/// Names Python's `GovernanceActionResult` enum carries.
fn python_names() -> BTreeSet<String> {
    let source = read("bindings/python/scp_sdk/governance.py");
    let class_start = source
        .find("class GovernanceActionResult(enum.Enum):")
        .expect("Python must declare GovernanceActionResult");
    let class_end = source[class_start..]
        .find("    @classmethod")
        .map(|offset| class_start + offset)
        .expect("that enum must end at its first classmethod");
    quoted_names(&source[class_start..class_end], |line| {
        line.contains(" = \"")
    })
}

/// Names Swift's `GovernanceActionResult` enum carries.
fn swift_names() -> BTreeSet<String> {
    let source = read("bindings/swift/Sources/SCP/Governance.swift");
    let enum_start = source
        .find("public enum GovernanceActionResult: String, Sendable {")
        .expect("Swift must declare GovernanceActionResult");
    let enum_end = source[enum_start..]
        .find("\n}\n")
        .map(|offset| enum_start + offset)
        .expect("that enum must end");
    quoted_names(&source[enum_start..enum_end], |line| {
        line.trim_start().starts_with("case ")
    })
}

/// Names TypeScript's `GOVERNANCE_ACTION_RESULTS` array carries.
fn typescript_names() -> BTreeSet<String> {
    let source = read("bindings/typescript/src/types.ts");
    let array_start = source
        .find("export const GOVERNANCE_ACTION_RESULTS = [")
        .expect("TypeScript must declare GOVERNANCE_ACTION_RESULTS");
    let array_end = source[array_start..]
        .find("] as const;")
        .map(|offset| array_start + offset)
        .expect("that array must end");
    quoted_names(&source[array_start..array_end], |line| line.contains('"'))
}

/// Adding a variant to `GovernanceActionResult` and naming it in one shared
/// bridge mapping leaves three SDKs unable to name it, and each then rejects a
/// legitimate outcome with `SCP-GOV-11040`. This comparison catches that
/// omission where a maintainer can still fix it.
#[test]
fn every_sdk_names_every_governance_outcome() {
    let rust = rust_names();
    assert_eq!(
        rust.len(),
        29,
        "governance_action_result_name must name every variant; found {rust:?}"
    );

    for (sdk, names) in [
        ("Python", python_names()),
        ("Swift", swift_names()),
        ("TypeScript", typescript_names()),
    ] {
        let missing: Vec<_> = rust.difference(&names).collect();
        assert!(
            missing.is_empty(),
            "{sdk} names no outcome for: {missing:?} — add each to its enum, \
             or callers on that SDK read SCP-GOV-11040 for a legitimate outcome"
        );
        let extra: Vec<_> = names.difference(&rust).collect();
        assert!(
            extra.is_empty(),
            "{sdk} names outcomes no bridge reports: {extra:?} — remove each, \
             or name it in governance_action_result_name"
        );
    }
}
