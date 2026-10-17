//! Every `UniFFI` export takes at most eight by-value buffer arguments.
//!
//! `UniFFI` lowers a `String`, `Vec`, `Option`, `HashMap`, record, or enum
//! argument to a 24-byte `RustBuffer` passed by value. JNA 5.18.1 on
//! darwin-aarch64 corrupts the first word (`capacity`) of the last such
//! argument in some calls that pass nine or more of them (a pointer followed
//! by nine or ten buffers, for example). The Rust side then frees that buffer
//! with a wrong capacity, and the wiping global allocator zeroes that many
//! bytes of the host's heap. Every call shape with eight or fewer buffers was
//! delivered intact, so this test holds each export, and each method of an
//! exported trait, to eight. Group further inputs in a `uniffi::Record`, which
//! travels as one buffer.
//!
//! An object (`Arc<T>`, `&T`), a callback (`Box<dyn T>`, `Arc<dyn T>`), and a
//! primitive number or `bool` travel in a register or as a handle and are not
//! counted.

use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// The most by-value `RustBuffer` arguments one export may take.
const MAX_BUFFER_ARGS: usize = 8;

/// Whether `attrs` holds `#[uniffi::export]` in any form, including inside a
/// `#[cfg_attr(..)]`.
fn is_exported(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let path = attr.path();
        let is_export = path.segments.len() == 2
            && path.segments[0].ident == "uniffi"
            && path.segments[1].ident == "export";
        let in_cfg_attr = path.is_ident("cfg_attr")
            && attr.meta.require_list().is_ok_and(|list| {
                let tokens = list.tokens.to_string().replace(' ', "");
                tokens.contains("uniffi::export")
            });
        is_export || in_cfg_attr
    })
}

/// Whether an argument of type `ty` is lowered to a by-value `RustBuffer`.
fn is_buffer(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(r) => {
            // `&str` and `&[T]` are buffers; `&T` of an object is a pointer.
            matches!(&*r.elem, syn::Type::Slice(_))
                || matches!(&*r.elem, syn::Type::Path(p) if p.path.is_ident("str"))
        }
        syn::Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return true;
            };
            let name = last.ident.to_string();
            let register = [
                "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "bool",
            ];
            !(register.contains(&name.as_str()) || name == "Arc" || name == "Box")
        }
        syn::Type::Paren(p) => is_buffer(&p.elem),
        syn::Type::Group(g) => is_buffer(&g.elem),
        _ => true,
    }
}

/// The number of by-value buffer arguments in `sig`, receiver excluded.
fn buffer_args(sig: &syn::Signature) -> usize {
    sig.inputs
        .iter()
        .filter(|arg| matches!(arg, syn::FnArg::Typed(t) if is_buffer(&t.ty)))
        .count()
}

/// Collects `(function, buffer argument count)` for every export over the
/// bound.
#[derive(Debug, Default)]
struct OverBound {
    found: Vec<(String, usize)>,
    exports_seen: usize,
}

impl OverBound {
    fn check(&mut self, owner: &str, sig: &syn::Signature) {
        self.exports_seen += 1;
        let count = buffer_args(sig);
        if count > MAX_BUFFER_ARGS {
            self.found.push((format!("{owner}{}", sig.ident), count));
        }
    }
}

impl<'ast> Visit<'ast> for OverBound {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if is_exported(&item.attrs) {
            self.check("", &item.sig);
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if is_exported(&item.attrs) {
            let owner = match &*item.self_ty {
                syn::Type::Path(p) => p
                    .path
                    .segments
                    .last()
                    .map_or_else(String::new, |s| format!("{}::", s.ident)),
                _ => String::new(),
            };
            // Every method of an exported impl counts, whatever its
            // visibility.
            for impl_item in &item.items {
                if let syn::ImplItem::Fn(f) = impl_item {
                    self.check(&owner, &f.sig);
                }
            }
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if is_exported(&item.attrs) {
            let owner = format!("{}::", item.ident);
            for trait_item in &item.items {
                if let syn::TraitItem::Fn(f) = trait_item {
                    self.check(&owner, &f.sig);
                }
            }
        }
        syn::visit::visit_item_trait(self, item);
    }
}

/// Scans one Rust source text.
fn scan_source(source: &str) -> Result<OverBound, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut visitor = OverBound::default();
    visitor.visit_file(&file);
    Ok(visitor)
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_sources(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Scans every source file of this crate: the exports seen, and one line per
/// export over the bound.
fn scan_crate() -> Result<(usize, Vec<String>), String> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files).map_err(|e| format!("list {}: {e}", src.display()))?;
    let mut over = Vec::new();
    let mut exports_seen = 0;
    for path in &files {
        let source =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let result = scan_source(&source).map_err(|e| format!("parse {}: {e}", path.display()))?;
        exports_seen += result.exports_seen;
        for (name, count) in result.found {
            over.push(format!("{}: {name} takes {count}", path.display()));
        }
    }
    Ok((exports_seen, over))
}

#[test]
fn every_uniffi_export_takes_at_most_eight_buffer_arguments() {
    let scanned = scan_crate();
    assert!(scanned.is_ok(), "{scanned:?}");
    let (exports_seen, over) = scanned.unwrap_or_default();
    // The scan must reach the bridge's exports, or an empty result proves
    // nothing.
    assert!(exports_seen > 100, "scanned only {exports_seen} exports");
    assert!(
        over.is_empty(),
        "exports over {MAX_BUFFER_ARGS} by-value buffer arguments; group inputs in a \
         uniffi::Record:\n{}",
        over.join("\n")
    );
}

#[test]
fn the_scan_flags_nine_buffers_and_passes_eight() {
    let source = r"
        #[uniffi::export(async_runtime = tokio)]
        impl Scp {
            pub async fn nine(&self, a: String, b: String, c: String, d: String, e: String,
                f: String, g: String, h: Vec<u8>, i: Option<String>) {}
            pub fn eight(&self, a: String, b: String, c: String, d: String, e: String,
                f: String, g: String, h: String, n: u64, o: Arc<ContextHandle>) {}
            fn private_nine(&self, a: String, b: String, c: String, d: String, e: String,
                f: String, g: String, h: String, i: String) {}
        }
        #[uniffi::export]
        pub fn free_nine(a: &str, b: String, c: String, d: String, e: String, f: String,
            g: String, h: String, i: SomeRecord) {}
        #[uniffi::export(with_foreign)]
        pub trait Host: Send + Sync {
            fn nine(&self, a: String, b: String, c: String, d: String, e: String,
                f: String, g: String, h: String, i: String);
        }
        pub fn unexported_nine(a: String, b: String, c: String, d: String, e: String,
            f: String, g: String, h: String, i: String) {}
    ";
    let scanned = scan_source(source);
    assert!(scanned.is_ok(), "{scanned:?}");
    let found = scanned.map(|r| r.found).unwrap_or_default();
    let mut names: Vec<_> = found.iter().map(|(n, c)| format!("{n}={c}")).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "Host::nine=9",
            "Scp::nine=9",
            "Scp::private_nine=9",
            "free_nine=9"
        ]
    );
}
