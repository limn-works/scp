//! Governance name parity between the Rust bridges and the four SDKs.
//!
//! The same closed extraction holds each SDK's built-in member roles equal to
//! `RESERVED_ROLE_NAMES` in `crates/scp-protocol/src/context/roles.rs`: every
//! bridge reports `RoleAssignment.role_name`, and an SDK that lacks a reserved
//! name reports a protocol-defined role as a governance-defined one or rejects
//! it. Kotlin returns the bridge's role name as a `String` and declares no
//! role type, so it has no role set to compare.
//!
//! Every bridge names a governance outcome, a proposal status, and a rejection
//! reason through the exhaustive name functions in
//! `crates/scp-ffi/common/src/governance_result.rs`. Each SDK parses those
//! names into a typed enum and raises `SCP-GOV-11040` for a name its enum
//! lacks, so an SDK enum that misses a Rust name turns a successful governance
//! call into an error, and an SDK enum that carries a name Rust never emits is
//! dead surface. This test holds each SDK's name set equal to the Rust set.
//!
//! Both sides are read with closed extraction, never a free-text search:
//!
//! - The Rust set comes from parsing `governance_result.rs` with `syn` and
//!   collecting the string literal each arm of each name function's `match`
//!   returns. A wildcard arm, an arm whose body is not one string literal, or
//!   a missing function fails the test.
//! - Each SDK set comes from the enum's declaration block. Every line from the
//!   exact declaration line to the exact terminator line must be blank, a
//!   comment the language allows there, or an entry that matches the
//!   language's entry shape. Any other line fails the test, so a reformatted
//!   or restructured enum cannot drop names silently.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| "scp-testing sits less than two levels below a root".to_owned())
}

fn read(relative: &str) -> Result<String, String> {
    let path = repo_root()?.join(relative);
    std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Returns the error message of `result`, or an error naming `what` when it
/// succeeded.
fn expect_err<T: std::fmt::Debug>(result: Result<T, String>, what: &str) -> Result<String, String> {
    match result {
        Ok(v) => Err(format!("{what} succeeded with {v:?}")),
        Err(e) => Ok(e),
    }
}

/// One governance name enum: its Rust name function and each SDK's
/// declaration.
struct NameEnum {
    rust_fn: &'static str,
    python_class: &'static str,
    swift_enum: &'static str,
    kotlin_enum: &'static str,
    ts_const: &'static str,
}

const ENUMS: [NameEnum; 3] = [
    NameEnum {
        rust_fn: "governance_action_result_name",
        python_class: "GovernanceActionResult",
        swift_enum: "GovernanceActionResult",
        kotlin_enum: "GovernanceActionResult",
        ts_const: "GOVERNANCE_ACTION_RESULTS",
    },
    NameEnum {
        rust_fn: "proposal_status_name",
        python_class: "ProposalStatus",
        swift_enum: "ProposalStatus",
        kotlin_enum: "ProposalStatus",
        ts_const: "PROPOSAL_STATUSES",
    },
    NameEnum {
        rust_fn: "rejection_reason_name",
        python_class: "RejectionReason",
        swift_enum: "RejectionReason",
        kotlin_enum: "RejectionReason",
        ts_const: "REJECTION_REASONS",
    },
];

const RUST_FILE: &str = "crates/scp-ffi/common/src/governance_result.rs";
const PYTHON_FILE: &str = "bindings/python/scp_sdk/governance.py";
const SWIFT_FILE: &str = "bindings/swift/Sources/SCP/Governance.swift";
const KOTLIN_FILE: &str = "bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Types.kt";
const TS_FILE: &str = "bindings/typescript/src/types.ts";
const ROLES_FILE: &str = "crates/scp-protocol/src/context/roles.rs";
const PYTHON_ROLE_FILE: &str = "bindings/python/scp_sdk/types.py";

// ---------------------------------------------------------------------------
// Rust side: syn
// ---------------------------------------------------------------------------

/// Returns the string literal each arm of `fn_name`'s top-level `match`
/// returns, in source order.
fn rust_names(source: &str, fn_name: &str) -> Result<Vec<String>, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse {RUST_FILE}: {e}"))?;
    let func = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(f) if f.sig.ident == fn_name => Some(f),
            _ => None,
        })
        .ok_or_else(|| format!("{RUST_FILE} defines no fn `{fn_name}`"))?;
    let [syn::Stmt::Expr(syn::Expr::Match(m), None)] = func.block.stmts.as_slice() else {
        return Err(format!("`{fn_name}`'s body is not one `match` expression"));
    };
    let mut names = Vec::with_capacity(m.arms.len());
    for arm in &m.arms {
        if matches!(arm.pat, syn::Pat::Wild(_)) || arm.guard.is_some() {
            return Err(format!("`{fn_name}` has a wildcard or guarded arm"));
        }
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = arm.body.as_ref()
        else {
            return Err(format!(
                "an arm of `{fn_name}` returns something other than a string literal"
            ));
        };
        names.push(s.value());
    }
    if names.is_empty() {
        return Err(format!("`{fn_name}`'s match has no arms"));
    }
    Ok(names)
}

/// Returns the string literals of the `&[&str]` constant `const_name`, in
/// source order.
fn rust_const_names(source: &str, const_name: &str) -> Result<Vec<String>, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse {ROLES_FILE}: {e}"))?;
    let item = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Const(c) if c.ident == const_name => Some(c),
            _ => None,
        })
        .ok_or_else(|| format!("{ROLES_FILE} defines no const `{const_name}`"))?;
    let syn::Expr::Reference(syn::ExprReference { expr, .. }) = item.expr.as_ref() else {
        return Err(format!(
            "`{const_name}` is not a reference to an array literal"
        ));
    };
    let syn::Expr::Array(array) = expr.as_ref() else {
        return Err(format!(
            "`{const_name}` is not a reference to an array literal"
        ));
    };
    let mut names = Vec::with_capacity(array.elems.len());
    for elem in &array.elems {
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = elem
        else {
            return Err(format!(
                "an element of `{const_name}` is something other than a string literal"
            ));
        };
        names.push(s.value());
    }
    if names.is_empty() {
        return Err(format!("`{const_name}` is empty"));
    }
    Ok(names)
}

// ---------------------------------------------------------------------------
// SDK side: closed extraction
// ---------------------------------------------------------------------------

/// How one language declares an enum's names.
struct Shape {
    /// The exact declaration line, with `{}` standing for the enum name.
    declaration: &'static str,
    /// The exact line that ends the entry block.
    terminator: &'static str,
    /// Line prefixes, after the declaration, that the block may carry besides
    /// entries (comments, docstring lines).
    allowed_prefixes: &'static [&'static str],
    /// Parses one entry line into its name, or `None` when the line is not an
    /// entry.
    entry: fn(&str) -> Option<String>,
}

/// Returns the quoted value when `rest` is exactly `"value"` followed by
/// `suffix`, with no quote, backslash, or space inside the value.
fn quoted_then(rest: &str, suffix: &str) -> Option<String> {
    let inner = rest
        .strip_prefix('"')?
        .strip_suffix(suffix)?
        .strip_suffix('"')?;
    let valid = !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric());
    valid.then(|| inner.to_owned())
}

fn is_ident(s: &str, first: fn(char) -> bool, rest: fn(char) -> bool) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(first) && chars.all(rest)
}

/// `    NAME = "Value"`
fn python_entry(line: &str) -> Option<String> {
    let (ident, rest) = line.strip_prefix("    ")?.split_once(" = ")?;
    is_ident(
        ident,
        |c| c.is_ascii_uppercase(),
        |c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_',
    )
    .then_some(())?;
    quoted_then(rest, "")
}

/// `    case name = "Value"`
fn swift_entry(line: &str) -> Option<String> {
    let (ident, rest) = line.strip_prefix("    case ")?.split_once(" = ")?;
    is_ident(
        ident,
        |c| c.is_ascii_lowercase(),
        |c| c.is_ascii_alphanumeric(),
    )
    .then_some(())?;
    quoted_then(rest, "")
}

/// `    NAME("Value"),`
fn kotlin_entry(line: &str) -> Option<String> {
    let (ident, rest) = line.strip_prefix("    ")?.split_once('(')?;
    is_ident(
        ident,
        |c| c.is_ascii_uppercase(),
        |c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_',
    )
    .then_some(())?;
    quoted_then(rest, "),")
}

/// `  "Value",`
fn ts_entry(line: &str) -> Option<String> {
    quoted_then(line.strip_prefix("  ")?, ",")
}

/// `    case name`, a case with no raw value, whose identifier is the name.
fn swift_bare_case_entry(line: &str) -> Option<String> {
    let ident = line.strip_prefix("    case ")?;
    is_ident(
        ident,
        |c| c.is_ascii_lowercase(),
        |c| c.is_ascii_lowercase(),
    )
    .then(|| ident.to_owned())
}

const PYTHON: Shape = Shape {
    declaration: "class {}(enum.Enum):",
    terminator: "    @classmethod",
    allowed_prefixes: &["    #"],
    entry: python_entry,
};
const SWIFT: Shape = Shape {
    declaration: "public enum {}: String, Sendable {",
    terminator: "}",
    allowed_prefixes: &["    //"],
    entry: swift_entry,
};
const KOTLIN: Shape = Shape {
    declaration: "enum class {}(val rawValue: String) {",
    terminator: "    ;",
    allowed_prefixes: &["    //"],
    entry: kotlin_entry,
};
const TS: Shape = Shape {
    declaration: "export const {} = [",
    terminator: "] as const;",
    allowed_prefixes: &["  //"],
    entry: ts_entry,
};
/// Swift's `MemberRole`: one bare case per built-in role, then the
/// `custom(name:)` case that carries a governance-defined role's name.
const SWIFT_ROLE: Shape = Shape {
    declaration: "public enum {}: Sendable, Hashable {",
    terminator: "}",
    allowed_prefixes: &["    //", "    case custom(name: String)"],
    entry: swift_bare_case_entry,
};

/// Returns the names in `name`'s entry block, in source order.
///
/// A Python block may open with a docstring; its lines are skipped up to the
/// line that closes it.
fn sdk_names(source: &str, shape: &Shape, name: &str) -> Result<Vec<String>, String> {
    let declaration = shape.declaration.replace("{}", name);
    let mut lines = source.lines();
    // `any` stops at the declaration, so `lines` resumes on the line after it.
    if !lines.by_ref().any(|l| l == declaration) {
        return Err(format!("no line equals `{declaration}`"));
    }
    let mut names = Vec::new();
    let mut in_docstring = false;
    let mut first = true;
    for line in lines {
        if line == shape.terminator {
            if names.is_empty() {
                return Err(format!("`{name}` declares no entries"));
            }
            return Ok(names);
        }
        if in_docstring {
            in_docstring = !line.trim_end().ends_with(r#"""""#);
            continue;
        }
        if first && line.starts_with(r#"    """"#) {
            first = false;
            let opened_and_closed =
                line.trim_end().len() > 7 && line.trim_end().ends_with(r#"""""#);
            in_docstring = !opened_and_closed;
            continue;
        }
        first = false;
        if line.trim().is_empty() || shape.allowed_prefixes.iter().any(|p| line.starts_with(p)) {
            continue;
        }
        match (shape.entry)(line) {
            Some(value) => names.push(value),
            None => {
                return Err(format!(
                    "`{name}` block holds a line that is not an entry: {line:?}"
                ));
            }
        }
    }
    Err(format!(
        "`{name}` block never reaches `{}`",
        shape.terminator
    ))
}

fn as_set(names: &[String], label: &str) -> BTreeSet<String> {
    let set: BTreeSet<String> = names.iter().cloned().collect();
    assert_eq!(
        set.len(),
        names.len(),
        "{label} lists a name twice: {names:?}"
    );
    set
}

/// One SDK: its label, its source, its shape, and the field of [`NameEnum`]
/// that names its declaration.
type Sdk<'a> = (&'a str, String, &'a Shape, fn(&NameEnum) -> &'static str);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_sdk_names_exactly_the_rust_governance_names() -> Result<(), String> {
    let rust_src = read(RUST_FILE)?;
    let sdks: [Sdk<'_>; 4] = [
        ("Python", read(PYTHON_FILE)?, &PYTHON, |e| e.python_class),
        ("Swift", read(SWIFT_FILE)?, &SWIFT, |e| e.swift_enum),
        ("Kotlin", read(KOTLIN_FILE)?, &KOTLIN, |e| e.kotlin_enum),
        ("TypeScript", read(TS_FILE)?, &TS, |e| e.ts_const),
    ];
    for e in &ENUMS {
        let rust = as_set(&rust_names(&rust_src, e.rust_fn)?, e.rust_fn);
        for (sdk, src, shape, decl) in &sdks {
            let label = format!("{sdk} `{}`", decl(e));
            let names = sdk_names(src, shape, decl(e)).map_err(|err| format!("{label}: {err}"))?;
            let sdk_set = as_set(&names, &label);
            let missing: Vec<_> = rust.difference(&sdk_set).collect();
            let extra: Vec<_> = sdk_set.difference(&rust).collect();
            assert!(
                missing.is_empty() && extra.is_empty(),
                "{label} differs from Rust `{}`: missing {missing:?}, extra {extra:?}",
                e.rust_fn
            );
        }
    }
    Ok(())
}

#[test]
fn every_sdk_member_role_names_exactly_the_reserved_role_names() -> Result<(), String> {
    let rust = rust_const_names(&read(ROLES_FILE)?, "RESERVED_ROLE_NAMES")?;
    let rust = as_set(&rust, "RESERVED_ROLE_NAMES");
    // Each SDK spells a built-in role in its own case; its parser matches the
    // lowercase form, which is the form `RESERVED_ROLE_NAMES` holds.
    let sdks: [(&str, String, &Shape, &str); 3] = [
        ("Python", read(PYTHON_ROLE_FILE)?, &PYTHON, "MemberRole"),
        ("Swift", read(SWIFT_FILE)?, &SWIFT_ROLE, "MemberRole"),
        ("TypeScript", read(TS_FILE)?, &TS, "BUILT_IN_ROLES"),
    ];
    for (sdk, src, shape, decl) in &sdks {
        let label = format!("{sdk} `{decl}`");
        let names: Vec<String> = sdk_names(src, shape, decl)
            .map_err(|err| format!("{label}: {err}"))?
            .iter()
            .map(|n| n.to_ascii_lowercase())
            .collect();
        let sdk_set = as_set(&names, &label);
        let missing: Vec<_> = rust.difference(&sdk_set).collect();
        let extra: Vec<_> = sdk_set.difference(&rust).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{label} differs from `RESERVED_ROLE_NAMES`: missing {missing:?}, extra {extra:?}"
        );
    }
    Ok(())
}

#[test]
fn rust_extraction_reads_the_reserved_role_names() -> Result<(), String> {
    // A positive control for the const extraction.
    let names = rust_const_names(&read(ROLES_FILE)?, "RESERVED_ROLE_NAMES")?;
    assert_eq!(
        names,
        [
            "admin",
            "moderator",
            "member",
            "observer",
            "author",
            "subscriber"
        ]
    );
    let cases = [
        (r#"const R: &[&str] = &["a", B];"#, "R", "string literal"),
        (
            r#"const R: [&str; 1] = ["a"];"#,
            "R",
            "reference to an array",
        ),
        (r#"const R: &[&str] = &["a"];"#, "S", "defines no const"),
    ];
    for (source, name, expected) in cases {
        let err = expect_err(rust_const_names(source, name), source)?;
        assert!(err.contains(expected), "{source}: {err}");
    }
    Ok(())
}

#[test]
fn rust_extraction_reads_the_shipped_names() -> Result<(), String> {
    // The shipped function list; a positive control for the syn extraction.
    let names = rust_names(&read(RUST_FILE)?, "proposal_status_name")?;
    assert_eq!(
        names,
        [
            "Pending",
            "Approved",
            "Rejected",
            "Expired",
            "Cancelled",
            "Invalidated"
        ]
    );
    Ok(())
}

#[test]
fn rust_extraction_rejects_a_wildcard_arm_and_a_non_literal_arm() -> Result<(), String> {
    let wildcard = r#"pub const fn n(s: &S) -> &'static str { match s { S::A => "A", _ => "B" } }"#;
    let computed = r#"pub fn n(s: &S) -> &'static str { match s { S::A => "A", S::B => name() } }"#;
    let cases = [
        (wildcard, "n", "wildcard"),
        (computed, "n", "string literal"),
        (wildcard, "missing", "defines no fn"),
    ];
    for (source, fn_name, expected) in cases {
        let err = expect_err(rust_names(source, fn_name), source)?;
        assert!(err.contains(expected), "{source}: {err}");
    }
    Ok(())
}

#[test]
fn sdk_extraction_reads_each_shape() -> Result<(), String> {
    let py = "class X(enum.Enum):\n    \"\"\"Doc.\n\n    More.\n    \"\"\"\n\n    A = \"A\"\n    # note\n    B_C = \"BC\"\n\n    @classmethod\n";
    let swift = "public enum X: String, Sendable {\n    /// doc\n    case a = \"A\"\n    case bC = \"BC\"\n}\n";
    let kt = "enum class X(val rawValue: String) {\n    A(\"A\"),\n    B_C(\"BC\"),\n    ;\n";
    let ts = "export const X = [\n  \"A\",\n  \"BC\",\n] as const;\n";
    for (source, shape) in [(py, &PYTHON), (swift, &SWIFT), (kt, &KOTLIN), (ts, &TS)] {
        assert_eq!(sdk_names(source, shape, "X")?, ["A", "BC"], "{source}");
    }
    let role = "public enum X: Sendable, Hashable {\n    /// doc\n    case admin\n    case author\n    case custom(name: String)\n}\n";
    assert_eq!(sdk_names(role, &SWIFT_ROLE, "X")?, ["admin", "author"]);
    Ok(())
}

#[test]
fn sdk_extraction_rejects_a_line_it_cannot_classify() -> Result<(), String> {
    // A name hidden behind any construct the shape does not name must fail,
    // never vanish from the set.
    let py = "class X(enum.Enum):\n    A = \"A\"\n    B = auto()\n    @classmethod\n";
    let swift = "public enum X: String, Sendable {\n    case a = \"A\", b = \"B\"\n}\n";
    let kt = "enum class X(val rawValue: String) {\n    A(\"A\"), B(\"B\"),\n    ;\n";
    let ts = "export const X = [\n  \"A\", \"B\",\n] as const;\n";
    let unterminated = "export const X = [\n  \"A\",\n";
    let role = "public enum X: Sendable, Hashable {\n    case admin, author\n}\n";
    let cases = [
        (py, &PYTHON, "X", "not an entry"),
        (swift, &SWIFT, "X", "not an entry"),
        (kt, &KOTLIN, "X", "not an entry"),
        (ts, &TS, "X", "not an entry"),
        (role, &SWIFT_ROLE, "X", "not an entry"),
        (unterminated, &TS, "X", "never reaches"),
        (ts, &TS, "Y", "no line equals"),
    ];
    for (source, shape, name, expected) in cases {
        let err = expect_err(sdk_names(source, shape, name), source)?;
        assert!(err.contains(expected), "{source}: {err}");
    }
    Ok(())
}
