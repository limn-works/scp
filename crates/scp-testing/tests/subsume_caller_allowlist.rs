//! ADR-049 §9 tripwire: the `ClassSCommitToken::subsume` call sites across the
//! runtime crates equal a closed allowlist.
//!
//! `subsume` discards the fail-closed persist a Class-S token owes, which is
//! sound only where a sibling token commits the same whole-state persist. The
//! two sanctioned sites and their siblings are listed in the doc comment on
//! `ClassSCommitToken::subsume` in `scp-runtime-core`. A new caller fails this
//! test and must be reviewed for its sibling commit before it ships.
//!
//! The scan lives here, not in `scp-runtime-core`, because it reads the sibling
//! domain crates' sources, which a packaged `scp-runtime-core` does not have
//! (ADR-070). `scp-testing` sits in the workspace by construction, and the test
//! fails when any allowlisted file is missing or holds no call, so a scan that
//! reaches no source cannot pass.
//!
//! Each file is tokenized with `proc_macro2`, so a `.subsume(` in a comment or a
//! string literal does not count, and one inside a macro invocation does. This
//! is a speed bump for an honest contributor, not an adversarial gate: the
//! durability guarantee is the token's `Drop` guard plus each site's proven
//! sibling commit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};

/// Each sanctioned production file and the exact number of `.subsume(` calls
/// it may contain. Adding a site means adding it here with a §9 sibling-commit
/// argument on the new call.
const KNOWN_SUBSUME_SITES: [(&str, usize); 2] = [
    ("crates/scp-runtime-messaging/src/helpers.rs", 1),
    ("crates/scp-runtime-governance/src/helpers.rs", 1),
];

/// The definition and its in-module unit tests, neither a production caller.
const DEFINING_FILE: &str = "crates/scp-runtime-core/src/context/actor/class_s.rs";

fn workspace_root() -> Result<PathBuf, String> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("scp-testing sits two levels below the repository root")?
        .to_path_buf())
}

fn read_dir(dir: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .map(|entry| {
            entry
                .map(|e| e.path())
                .map_err(|e| format!("read an entry of {}: {e}", dir.display()))
        })
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for path in read_dir(dir)? {
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Counts `.` `subsume` `( … )` token sequences, descending into every group,
/// including macro arguments.
fn count_subsume_calls(stream: TokenStream) -> usize {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut count = 0;
    for (idx, token) in tokens.iter().enumerate() {
        if let TokenTree::Group(group) = token {
            count += count_subsume_calls(group.stream());
        }
        let is_call = matches!(token, TokenTree::Punct(p) if p.as_char() == '.')
            && matches!(tokens.get(idx + 1), Some(TokenTree::Ident(i)) if i == "subsume")
            && matches!(
                tokens.get(idx + 2),
                Some(TokenTree::Group(g)) if g.delimiter() == proc_macro2::Delimiter::Parenthesis
            );
        if is_call {
            count += 1;
        }
    }
    count
}

#[test]
fn subsume_callers_equal_the_allowlist() -> Result<(), String> {
    let mut files = Vec::new();
    for dir in read_dir(&workspace_root()?.join("crates"))? {
        let is_runtime = dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("scp-runtime"));
        if is_runtime && dir.join("src").is_dir() {
            rust_files(&dir.join("src"), &mut files)?;
        }
    }

    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for file in &files {
        let rel = file
            .strip_prefix(workspace_root()?)
            .map_err(|e| format!("{} is outside the repository root: {e}", file.display()))?
            .to_string_lossy()
            .into_owned();
        if rel == DEFINING_FILE {
            continue;
        }
        let src = std::fs::read_to_string(file).map_err(|e| format!("read {rel}: {e}"))?;
        let stream = TokenStream::from_str(&src).map_err(|e| format!("tokenize {rel}: {e}"))?;
        let count = count_subsume_calls(stream);
        if count > 0 {
            found.insert(rel, count);
        }
    }

    for (file, _) in KNOWN_SUBSUME_SITES {
        assert!(
            found.contains_key(file),
            "allowlisted subsume caller {file} is missing or holds no `.subsume(` call; \
             remove it from KNOWN_SUBSUME_SITES only with the site it covered"
        );
    }
    let expected: BTreeMap<String, usize> = KNOWN_SUBSUME_SITES
        .iter()
        .map(|(f, n)| ((*f).to_owned(), *n))
        .collect();
    assert_eq!(
        found, expected,
        "ADR-049 §9: the `ClassSCommitToken::subsume()` call sites in the runtime \
         crates differ from KNOWN_SUBSUME_SITES. subsume DISCARDS the owed \
         fail-closed persist — prove a sibling token commits the same whole-state \
         persist, then add the site to KNOWN_SUBSUME_SITES with a §9 safety argument."
    );
    Ok(())
}

/// The counter must see a call inside a macro and ignore comments and strings,
/// or the allowlist check could pass on a scan that misses a real caller.
#[test]
fn counter_sees_macro_calls_and_skips_comments_and_strings() -> Result<(), String> {
    let src = r#"
        fn a(t: Token) { t.subsume("ctx"); }
        // t.subsume("in a comment");
        /* t.subsume("in a block comment"); */
        const S: &str = "t.subsume(\"in a string\")";
        fn b(t: Token) { some_macro!(t.subsume("ctx")); }
        fn c(t: Token) { let _ = t.subsume; }
    "#;
    let stream = TokenStream::from_str(src).map_err(|e| format!("tokenize the fixture: {e}"))?;
    assert_eq!(count_subsume_calls(stream), 2);
    Ok(())
}
