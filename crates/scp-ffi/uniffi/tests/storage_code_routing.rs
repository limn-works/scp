//! Every `SCP-STORAGE-` code reaches a `UniFFI` caller as `ScpError::Storage`
//! because one function, `ScpError::coded`, picks the variant from the code's
//! prefix (sdk-common.md §Registered SCP-STORAGE- codes). A call site that
//! writes an `ScpError` variant literal with a storage code skips that
//! routing and can name the wrong variant. This scan parses every source file
//! under `src/` with `syn` and fails on any such literal outside `coded` whose
//! `code:` expression names a storage code directly. A code assigned through
//! a local binding or returned from a function is not covered.
//!
//! What it matches: a struct expression whose path is `ScpError::<Variant>`,
//! or `Self::<Variant>` inside `impl ScpError`, whose `code` field expression
//! names a path segment starting `STORAGE_` or a string literal starting
//! `SCP-STORAGE-`. Macro bodies that parse as comma-separated expressions are
//! scanned too, so a literal inside `vec![...]` or `Err(...)` in a macro is
//! not hidden.

use std::path::{Path, PathBuf};

use syn::visit::Visit;

const STORAGE_CODE_PREFIX: &str = "SCP-STORAGE-";

/// One `ScpError` literal carrying a storage code outside `coded`.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    file: String,
    function: String,
    variant: String,
}

/// True when `expr` names a `STORAGE_*` constant or a `SCP-STORAGE-` literal.
struct MentionsStorageCode(bool);

impl<'ast> Visit<'ast> for MentionsStorageCode {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .iter()
            .any(|s| s.ident.to_string().starts_with("STORAGE_"))
        {
            self.0 = true;
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        if lit.value().starts_with(STORAGE_CODE_PREFIX) {
            self.0 = true;
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(exprs) = macro_exprs(mac) {
            for expr in &exprs {
                self.visit_expr(expr);
            }
        }
    }
}

/// A macro body parsed as comma-separated expressions, or `None` when the
/// body is not that shape.
fn macro_exprs(mac: &syn::Macro) -> Option<Vec<syn::Expr>> {
    let exprs = mac
        .parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        .ok()?;
    Some(exprs.into_iter().collect())
}

struct Scan<'f> {
    file: &'f str,
    /// The self type of each enclosing `impl` block, innermost last.
    impls: Vec<bool>,
    /// The name of each enclosing function, innermost last.
    fns: Vec<String>,
    found: Vec<Violation>,
}

impl Scan<'_> {
    fn in_scp_error_impl(&self) -> bool {
        self.impls.last().copied().unwrap_or(false)
    }

    /// `ScpError::coded`, the one function allowed to build a variant from a
    /// storage code.
    fn in_coded(&self) -> bool {
        self.in_scp_error_impl() && self.fns.last().is_some_and(|f| f == "coded")
    }

    fn variant_of(&self, path: &syn::Path) -> Option<String> {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let [.., owner, variant] = segs.as_slice() else {
            return None;
        };
        let is_scp_error =
            owner == "ScpError" || (owner == "Self" && segs.len() == 2 && self.in_scp_error_impl());
        is_scp_error.then(|| variant.clone())
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let is_scp_error = matches!(
            &*item.self_ty,
            syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "ScpError")
        );
        self.impls.push(is_scp_error);
        syn::visit::visit_item_impl(self, item);
        self.impls.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.fns.push(item.sig.ident.to_string());
        // A free function is never inside `impl ScpError`.
        self.impls.push(false);
        syn::visit::visit_item_fn(self, item);
        self.impls.pop();
        self.fns.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.fns.push(item.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, item);
        self.fns.pop();
    }

    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        if let Some(variant) = self.variant_of(&expr.path) {
            let code_field = expr
                .fields
                .iter()
                .find(|f| matches!(&f.member, syn::Member::Named(name) if name == "code"));
            if let Some(field) = code_field {
                let mut mentions = MentionsStorageCode(false);
                mentions.visit_expr(&field.expr);
                if mentions.0 && !self.in_coded() {
                    self.found.push(Violation {
                        file: self.file.to_owned(),
                        function: self.fns.last().cloned().unwrap_or_default(),
                        variant,
                    });
                }
            }
        }
        syn::visit::visit_expr_struct(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(exprs) = macro_exprs(mac) {
            for expr in &exprs {
                self.visit_expr(expr);
            }
        }
    }
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn scan_source(file: &str, src: &str) -> TestResult<Vec<Violation>> {
    let ast = syn::parse_file(src).map_err(|e| format!("{file} must parse: {e}"))?;
    let mut scan = Scan {
        file,
        impls: Vec::new(),
        fns: Vec::new(),
        found: Vec::new(),
    };
    scan.visit_file(&ast);
    Ok(scan.found)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> TestResult {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn no_scp_error_literal_outside_coded_carries_a_storage_code() -> TestResult {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files)?;
    assert!(
        files.iter().any(|f| f.ends_with("bridge.rs")),
        "the scan must reach bridge.rs, which defines `coded`"
    );
    let mut violations = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path)?;
        violations.extend(scan_source(&path.display().to_string(), &text)?);
    }
    assert!(
        violations.is_empty(),
        "build these through `ScpError::coded` or `ScpError::storage`: {violations:#?}"
    );
    Ok(())
}

/// The scan flags each planted shape, and passes the same literal inside
/// `ScpError::coded`, so the clean result above is not a scan that matches
/// nothing.
#[test]
fn the_scan_catches_planted_storage_code_literals() -> TestResult {
    let planted = r#"
        use scp_ffi_common::error_codes as codes;
        fn open() -> Result<(), ScpError> {
            Err(ScpError::Validation { msg: String::new(), code: codes::STORAGE_8004.to_owned() })
        }
        fn open_in_macro() -> Vec<ScpError> {
            vec![crate::bridge::ScpError::Storage {
                msg: String::new(),
                code: "SCP-STORAGE-8005".into(),
            }]
        }
        impl ScpError {
            fn lock(msg: String) -> Self {
                Self::Context { msg, code: STORAGE_8005.to_owned() }
            }
            pub(crate) fn coded(class: ErrorClass, code: &str, msg: String) -> Self {
                Self::Storage { msg, code: codes::STORAGE_8000.to_owned() }
            }
        }
        impl Other {
            fn not_scp_error() -> Self {
                Self::Context { msg: String::new(), code: STORAGE_8005.to_owned() }
            }
            fn coded() -> ScpError {
                ScpError::Storage { msg: String::new(), code: STORAGE_8000.to_owned() }
            }
        }
        fn not_storage() -> ScpError {
            ScpError::Validation { msg: String::new(), code: codes::VALID_7004.to_owned() }
        }
    "#;
    let variants: Vec<(String, String)> = scan_source("planted.rs", planted)?
        .into_iter()
        .map(|v| (v.function, v.variant))
        .collect();
    assert_eq!(
        variants,
        vec![
            ("open".to_owned(), "Validation".to_owned()),
            ("open_in_macro".to_owned(), "Storage".to_owned()),
            ("lock".to_owned(), "Context".to_owned()),
            ("coded".to_owned(), "Storage".to_owned()),
        ],
        "a planted violation escaped the scan, or a clean shape was flagged"
    );
    Ok(())
}
