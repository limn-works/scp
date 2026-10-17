//! One code, one meaning: the codes `scp-ffi-common` defines and the codes an
//! SDK owns take distinct numbers.
//!
//! `.docs/standards/sdk-common.md` registers each code in a table row naming
//! its owner. A bridge and an SDK wrapper run in one process, so a code that
//! the native registry (`src/error_codes.rs`) defines and that a row also
//! gives to one SDK names two conditions in that process. These assertions
//! read the registry, the native constants and the source trees of the four
//! SDKs, and fail on:
//!
//! - a code registered in two rows;
//! - an SDK-owned code that the native registry also defines;
//! - an SDK-owned code that another SDK's source names;
//! - a native constant in the capability-challenge band
//!   (`SCP-VALID-7140` to `SCP-VALID-7159`) with no row naming the native
//!   registry as its owner.
//!
//! The file sits outside `src/error_codes.rs` for the reason
//! `storage_code_allocation.rs` gives: `scripts/check-error-codes.sh` Phase 3
//! counts every quoted code literal in that file as a constant.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The first and last number of the capability-challenge band.
const CHALLENGE_BAND: (u32, u32) = (7140, 7159);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Every `SCP-<PREFIX>-<digits>` token in `text` with four or more digits, in
/// order.
fn code_tokens(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = text[i..].find("SCP-") {
        let start = i + off;
        let mut j = start + 4;
        while j < bytes.len() && bytes[j].is_ascii_uppercase() {
            j += 1;
        }
        let digits = j + 1;
        let mut end = digits;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if j > start + 4 && bytes.get(j) == Some(&b'-') && end - digits >= 4 {
            out.push(text[start..end].to_owned());
        }
        i = start + 4;
    }
    out
}

/// The literal of every `pub const NAME: &str = "SCP-...";` in the native
/// registry, with how many constants carry it.
fn native_codes() -> Result<BTreeMap<String, usize>, String> {
    let text = read(&repo_root().join("crates/scp-ffi/common/src/error_codes.rs"))?;
    let mut codes = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("pub const ") && line.contains(": &str = \"SCP-") {
            let tokens = code_tokens(line);
            assert_eq!(tokens.len(), 1, "one code per constant: {line}");
            *codes.entry(tokens[0].clone()).or_insert(0) += 1;
        }
    }
    assert!(codes.len() > 100, "the parser found the native constants");
    Ok(codes)
}

/// A registry row: its code and its owner cell.
struct Row {
    code: String,
    owner: String,
}

fn registry_rows() -> Result<Vec<Row>, String> {
    let text = read(&repo_root().join(".docs/standards/sdk-common.md"))?;
    let rows: Vec<Row> = text
        .lines()
        .filter(|l| l.starts_with("| `SCP-"))
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let code = cells[1].trim_matches('`').to_owned();
            // A row naming a prefix and a number range allocates a band, not a code.
            (code_tokens(&code) == [code.clone()]).then(|| Row {
                code,
                owner: cells[2].to_owned(),
            })
        })
        .collect();
    assert!(rows.len() > 50, "the parser found the registry rows");
    Ok(rows)
}

/// The SDK source trees, keyed by the name a registry owner cell gives the SDK.
const SDK_TREES: [(&str, &[&str]); 4] = [
    ("Swift", &["bindings/swift/Sources"]),
    (
        "Kotlin",
        &[
            "bindings/kotlin/scp-kt/src/main",
            "bindings/kotlin/scp-kt-android/src/main",
        ],
    ),
    ("Python", &["bindings/python/scp_sdk"]),
    ("TypeScript", &["bindings/typescript/src"]),
];

/// The SDK a row gives sole ownership to, when its owner cell names exactly one
/// SDK and not the native registry.
fn sole_sdk_owner(owner: &str) -> Option<&'static str> {
    if owner.contains("native") || owner.contains("all bridges") {
        return None;
    }
    let named: Vec<&'static str> = [
        ("Swift", "Swift SDK"),
        ("Kotlin", "Kotlin SDK"),
        ("Kotlin", "scp-kt-android"),
        ("Python", "Python SDK"),
        ("TypeScript", "ts-native"),
    ]
    .iter()
    .filter(|(_, marker)| owner.contains(marker))
    .map(|(sdk, _)| *sdk)
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    (named.len() == 1).then(|| named[0])
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let path = entry
            .map_err(|e| format!("read {}: {e}", dir.display()))?
            .path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("swift" | "kt" | "py" | "ts")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

/// Every code token in each SDK's source tree.
fn sdk_codes() -> Result<BTreeMap<&'static str, BTreeSet<String>>, String> {
    let mut by_sdk = BTreeMap::new();
    for (sdk, dirs) in SDK_TREES {
        let mut files = Vec::new();
        for dir in dirs {
            collect_files(&repo_root().join(dir), &mut files)?;
        }
        let mut codes = BTreeSet::new();
        for file in &files {
            codes.extend(code_tokens(&read(file)?));
        }
        assert!(!codes.is_empty(), "{sdk}: the scan found SDK codes");
        by_sdk.insert(sdk, codes);
    }
    Ok(by_sdk)
}

#[test]
fn code_tokens_parses_only_whole_codes() {
    assert_eq!(
        code_tokens(
            "x \"SCP-VALID-7150\" `SCP-CTX-2003`, SCP-GOV-11040 SCP--1234 SCP-A-12 SCP-IDENT-"
        ),
        vec!["SCP-VALID-7150", "SCP-CTX-2003", "SCP-GOV-11040"]
    );
}

#[test]
fn no_code_is_registered_twice() -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for row in registry_rows()? {
        assert!(
            seen.insert(row.code.clone()),
            "{} has two registry rows",
            row.code
        );
    }
    Ok(())
}

#[test]
fn no_native_code_is_defined_twice() -> Result<(), String> {
    for (code, count) in native_codes()? {
        assert_eq!(count, 1, "{code} is defined by {count} native constants");
    }
    Ok(())
}

#[test]
fn an_sdk_owned_code_has_no_second_meaning() -> Result<(), String> {
    let native = native_codes()?;
    let sdks = sdk_codes()?;
    let mut sdk_owned = 0;
    for row in registry_rows()? {
        let Some(owner) = sole_sdk_owner(&row.owner) else {
            continue;
        };
        sdk_owned += 1;
        assert!(
            !native.contains_key(&row.code),
            "{} is registered to the {owner} SDK and also defined by the native registry",
            row.code
        );
        for (sdk, codes) in &sdks {
            if *sdk != owner {
                assert!(
                    !codes.contains(&row.code),
                    "{} is registered to the {owner} SDK and also named in the {sdk} SDK",
                    row.code
                );
            }
        }
    }
    assert!(sdk_owned >= 6, "the registry has SDK-owned rows to check");
    Ok(())
}

#[test]
fn every_native_challenge_band_code_is_registered_to_the_native_registry() -> Result<(), String> {
    let rows = registry_rows()?;
    let in_band: Vec<String> = native_codes()?
        .into_keys()
        .filter(|code| {
            code.strip_prefix("SCP-VALID-")
                .and_then(|n| n.parse::<u32>().ok())
                .is_some_and(|n| (CHALLENGE_BAND.0..=CHALLENGE_BAND.1).contains(&n))
        })
        .collect();
    assert!(in_band.len() >= 10, "the band holds the challenge codes");
    for code in in_band {
        let row = rows
            .iter()
            .find(|r| r.code == code)
            .ok_or_else(|| format!("{code} has no registry row"))?;
        assert!(
            row.owner.contains("native FFI-common registry"),
            "{code} is defined natively but registered to {}",
            row.owner
        );
    }
    Ok(())
}
