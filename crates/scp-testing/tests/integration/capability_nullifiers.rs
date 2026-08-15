// A test binary asserts by panicking, and a scanner that cannot parse a source
// file has no honest verdict to report, so `expect`/`panic` are the right
// failure mode here. This mirrors the header on `ffi_conformance.rs`.
#![allow(clippy::expect_used, clippy::panic, clippy::doc_markdown)]

//! Workspace-wide security-nullifier detector for the seven provider
//! capabilities of `.docs/specs/17-persistence-and-storage.md` §17.17.2.
//!
//! # Why this file exists separately from `ffi_conformance.rs`
//!
//! `ffi_conformance.rs` carries the ADR-048 §1 pure-helper scanner, whose scope
//! is the three FFI bridge roots and whose subject is inherent, export-decorated
//! methods. This detector's scope is every Rust source file the workspace's
//! crates compile in a production build, and its subject is trait impls of the
//! seven provider capabilities. Those two scopes share nothing but the parser.
//! A workspace-wide capability scanner living in a file named for FFI
//! conformance would be a name that lies about what it gates, so it lives here.
//!
//! # What this detector decides
//!
//! Spec §17.17.2 SCP-CAPSEL-8010 splits a capability's development arm into a
//! durability-only affordance (it forgets state, and fails closed) and a
//! security nullifier (it keeps answering, and its answer no longer carries the
//! guarantee the caller believes it does). SCP-CAPSEL-8012 forbids a nullifier
//! arm from being present in a shipped production artifact.
//!
//! **The criterion.** A method of a production-capability trait impl is a
//! security nullifier when all three of the following hold:
//!
//! 1. the method takes `self` in some form and reads neither `self` nor `Self`
//!    anywhere outside the receiver, so it consults no backing resource; AND
//! 2. the method reads none of its non-receiver parameters, and consults no
//!    ambient source in their place, so nothing the caller supplied and nothing
//!    outside the method reaches the value it produces; AND
//! 3. every value the method can produce asserts that the operation succeeded —
//!    the return type is fallible, every value-producing expression constructs
//!    `Ok(..)`, no expression constructs `Err(..)`, the body contains no `?`
//!    escape, and no `Ok` payload is the honest-absence value `None`.
//!
//! Conjuncts 1 and 2 together say the method is a constant function: nothing it
//! reads can change what it returns. Conjunct 3 says that constant is a claim of
//! success. A method satisfying 1 and 2 but returning `Err(..)` fails closed and
//! is honest; a method satisfying 1 and 2 but returning `Ok(None)` reports the
//! protocol-supported absent state and is also honest — ADR-062, capability
//! injection and prove-absent dev backends, §Decision 5 classifies exactly this
//! shape (`NoOpRelayQuerier::query`) as not a nullifier for that reason. Only a
//! method that reads nothing and still claims the operation succeeded lies to
//! its caller.
//!
//! **Why conjunct 2 covers ambient sources as well as parameters.** Five real
//! methods in this workspace take `&self` and no parameters at all, read neither
//! `self` nor a parameter, and return `Ok(seed)`:
//! `KeyCustody::generate_ephemeral_ed25519_seed` on `FileKeyCustody`,
//! `SqliteKeyCustody`, and the three callback custody bridges. Each one draws 32
//! bytes from `OsRng`. Each produces exactly the outcome its caller asked for,
//! so none is a nullifier — and a predicate that reads "ignores its bound
//! inputs" without also asking "and manufactures its answer from nothing" flags
//! all five. Conjunct 2 therefore requires the body to be **inert**: every
//! statement and every expression it holds must come from the closed set
//! `expr_is_inert` whitelists (literals, paths, aggregates of those, and the
//! argument-transparent constructors `Ok`, `Err`, `Some`, `default`, `new`,
//! and `pin`). Drawing
//! from `OsRng`, awaiting a future, invoking a macro, or calling anything
//! outside that set is an operation, so the method consulted something and the
//! predicate does not flag it.
//!
//! **The whitelist is positive and closed, not a denylist.** It enumerates the
//! expression forms that can produce a value without consulting anything, and
//! rejects every other form by construction. Growing it means naming another
//! way to manufacture a constant, never another way to spell an evasion.
//!
//! **The boundary this predicate does not cross.** It reasons about one method
//! body at a time. A capability method that delegates its fabrication to a
//! helper — `Ok(fabricate_token())` — performs a call, so the body is not
//! inert and the predicate does not flag it. Catching that shape needs
//! interprocedural analysis, which this detector does not attempt.
//!
//! **Identifier names decide nothing here.** `NoOp`, `Noop`, `InMemory`,
//! `Stub`, `Fake`, and `Dummy` are search heuristics for a human auditor, never
//! the criterion, and none of them appears in this detector's predicate. The
//! census behind ADR-062 is why: `NoOp` spans fail-closed placeholders, one
//! deliberate production not-applicable decision, and genuine nullifiers, while
//! `InMemory` spans honest durability-only arms and one fabricator. A name-keyed
//! check is defeated by a rename, which is the camouflage this gate guards
//! against.
//!
//! **Return-value spellings decide nothing here either.** The detector never
//! matches on the text `Ok(())`, which is the correct return for every
//! successful void operation in this tree. It matches on the structure of the
//! value path: a constructor named `Ok` applied to a payload, reached from the
//! method body through async blocks, `Box::pin`, `if`/`match` arms, and
//! `return`. `Ok(Default::default())`, a value bound to a local first, and
//! `Ok(SomeType::new())` all reduce to the same structure and are all flagged.
//!
//! # Scope: which files, and which items inside them
//!
//! The detector walks the module tree of every crate under `crates/`, starting
//! at each crate's `src/lib.rs`, `src/main.rs`, and `src/bin/*.rs`, and follows
//! `mod` declarations (including `#[path = "…"]`). A file no crate root reaches
//! is not compiled and is not scanned.
//!
//! An item is out of scope when its `cfg` predicate cannot hold in any build
//! that leaves `test` off and the `testing` feature off. That is decided by
//! evaluating the predicate with `test` bound to false, `feature = "testing"`
//! bound to false, and every other atom bound to true, which is the optimistic
//! assignment: an item survives unless no production build can contain it.
//! Gating propagates from a `mod` declaration to the file it names, so
//! `#[cfg(feature = "testing")] pub mod testing;` takes the whole subtree out of
//! scope. That exclusion is the ADR-062 mechanism working as designed: the
//! shipped-feature-graph gate, `scripts/check-shipped-feature-graph.sh`, proves
//! the gated nullifiers absent from shipped artifacts, and this detector covers
//! the ungated remainder.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// The seven provider capabilities and the traits that express them
// ---------------------------------------------------------------------------

/// One provider capability from spec §17.17.2, and the trait names that express
/// it in this workspace.
struct CapabilityTraits {
    /// The capability as §17.17.2 enumerates it.
    capability: &'static str,
    /// Trait names whose impls carry this capability's contract. Matched on the
    /// last path segment of the trait in `impl Trait for Type`.
    traits: &'static [&'static str],
}

/// The seven provider capabilities of spec §17.17.2, resolved to trait names.
///
/// This registry is the detector's scope selector, not its verdict: it decides
/// which impls the three-conjunct predicate runs against. Adding a capability
/// trait widens the gate; the `registry_scope_still_resolves` test below fails
/// if any registered name stops resolving, so a rename cannot silently narrow
/// the scope back.
const CAPABILITY_TRAITS: &[CapabilityTraits] = &[
    CapabilityTraits {
        // §17.6 — the platform key/value store, the browser participant
        // driver's store, and the UniFFI foreign-implemented provider.
        capability: "client storage (§17.6)",
        traits: &["Storage", "EncryptedStorage", "StorageProvider"],
    },
    CapabilityTraits {
        // §17.7 — relay-side blob custody.
        capability: "relay blob storage (§17.7)",
        traits: &["BlobStorage"],
    },
    CapabilityTraits {
        // §3.10 — the DHT leaf, the resolver composed over it, the sequence
        // store that supplies BEP44 monotonicity, and the publish half that
        // §3.10.6 makes a MUST alongside resolution. §17.17.3 reasons about
        // both directions of this capability, so both belong in its row.
        capability: "DID/DHT resolution (§3.10)",
        traits: &[
            "DhtClient",
            "DidResolver",
            "SequenceStore",
            "RelayPublisher",
        ],
    },
    CapabilityTraits {
        // §12.11 — bridge credential custody and its durable backend.
        capability: "credential storage",
        traits: &[
            "BridgeCredentialStore",
            "DurableCredentialBackend",
            "AdapterCredentialStore",
        ],
    },
    CapabilityTraits {
        // §17.8 / ADR-006 — private key custody, including the pre-rotation
        // recovery backstop of §9.7.4.1 item 3a.
        capability: "key custody (§17.8)",
        traits: &["KeyCustody", "PreRotationCustody", "KeyCustodyProvider"],
    },
    CapabilityTraits {
        // ADR-025 — device attestation, native trait and UniFFI provider.
        capability: "device attestation",
        traits: &["DeviceAttestation", "DeviceAttestationProvider"],
    },
    CapabilityTraits {
        // §3.10.2 / §3.10.4 — single-relay and multi-relay DID document query.
        capability: "relay querier",
        traits: &["RelayQuerier", "MultiRelayQuerier"],
    },
];

/// Every registered trait name, flattened.
fn registered_trait_names() -> HashSet<String> {
    CAPABILITY_TRAITS
        .iter()
        .flat_map(|c| c.traits.iter().map(|t| (*t).to_owned()))
        .collect()
}

/// The capability a trait name belongs to, for the failure message.
fn capability_of(trait_name: &str) -> &'static str {
    CAPABILITY_TRAITS
        .iter()
        .find(|c| c.traits.contains(&trait_name))
        .map_or("unregistered", |c| c.capability)
}

// ---------------------------------------------------------------------------
// Conjunct 1 and 2: does the method read anything?
// ---------------------------------------------------------------------------

/// Walks an AST looking for a reference to any identifier in a target set,
/// including inside macro token streams.
///
/// `syn::visit` does not descend into macro tokens, because a macro's body was
/// never parsed as expressions. A method whose only read of `self` sits inside
/// `format!("{}", self.field)` would look constant to a visitor that stops at
/// the macro boundary, so this walker inspects the raw `TokenStream` too.
///
/// **Known limitation — identifier-splitting macros.** A macro that constructs
/// the identifier from sub-tokens (`paste::paste!([<se lf>])`,
/// `concat_idents!`, a proc-macro emitting `Ident::new("self", …)`) evades the
/// token walk. No SCP capability impl uses one; prefer restructuring the method
/// over reaching for such a macro inside a capability impl.
struct IdentUseScanner<'a> {
    targets: &'a HashSet<String>,
    found: bool,
}

impl syn::visit::Visit<'_> for IdentUseScanner<'_> {
    fn visit_ident(&mut self, ident: &syn::Ident) {
        if self.targets.contains(&ident.to_string()) {
            self.found = true;
        }
    }

    fn visit_macro(&mut self, m: &syn::Macro) {
        if tokens_use_ident(m.tokens.clone(), self.targets) {
            self.found = true;
        }
        syn::visit::visit_macro(self, m);
    }
}

/// Recursively searches a `proc_macro2::TokenStream` for any identifier in
/// `targets`. `proc-macro2` is already a `syn` dependency.
fn tokens_use_ident(stream: proc_macro2::TokenStream, targets: &HashSet<String>) -> bool {
    for tree in stream {
        match tree {
            proc_macro2::TokenTree::Ident(ident) if targets.contains(&ident.to_string()) => {
                return true;
            }
            proc_macro2::TokenTree::Group(group) if tokens_use_ident(group.stream(), targets) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Reports whether the method references any identifier in `targets` in its
/// body, in the non-receiver parts of its signature, or in its generics.
fn method_reads_any(method: &syn::ImplItemFn, targets: &HashSet<String>) -> bool {
    if targets.is_empty() {
        return false;
    }
    let mut scanner = IdentUseScanner {
        targets,
        found: false,
    };
    syn::visit::Visit::visit_block(&mut scanner, &method.block);
    if scanner.found {
        return true;
    }
    syn::visit::Visit::visit_generics(&mut scanner, &method.sig.generics);
    if scanner.found {
        return true;
    }
    syn::visit::Visit::visit_return_type(&mut scanner, &method.sig.output);
    if scanner.found {
        return true;
    }
    for input in &method.sig.inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            syn::visit::Visit::visit_type(&mut scanner, &pat_type.ty);
            if scanner.found {
                return true;
            }
        }
    }
    false
}

/// Reports whether the method declares a `self` receiver in any form: `self`,
/// `&self`, `&mut self`, or `self: Arc<Self>`.
fn method_has_self_receiver(method: &syn::ImplItemFn) -> bool {
    method
        .sig
        .inputs
        .first()
        .is_some_and(|arg| matches!(arg, syn::FnArg::Receiver(_)))
}

/// Conjunct 1: the method takes `self` but never reads `self` or `Self`.
fn conjunct_ignores_self(method: &syn::ImplItemFn) -> bool {
    if !method_has_self_receiver(method) {
        return false;
    }
    let targets: HashSet<String> = ["self", "Self"].iter().map(|s| (*s).to_owned()).collect();
    !method_reads_any(method, &targets)
}

/// Collects every identifier a pattern binds, so a parameter destructured as
/// `(a, b)` or `Config { host, .. }` is tracked by each of its bindings.
fn pattern_bindings(pat: &syn::Pat, out: &mut HashSet<String>) {
    struct BindingScanner<'a>(&'a mut HashSet<String>);
    impl syn::visit::Visit<'_> for BindingScanner<'_> {
        fn visit_pat_ident(&mut self, pat_ident: &syn::PatIdent) {
            self.0.insert(pat_ident.ident.to_string());
            syn::visit::visit_pat_ident(self, pat_ident);
        }
    }
    syn::visit::Visit::visit_pat(&mut BindingScanner(out), pat);
}

/// Conjunct 2: the method reads none of its non-receiver parameters, and
/// consults no ambient source in their place.
///
/// A parameter bound to a wildcard (`_`) or to an underscore-prefixed name is
/// unreadable by construction and contributes no binding, so a method whose
/// every parameter is `_`-prefixed satisfies the parameter half of this
/// conjunct — which is the point, since that is how an unused parameter is
/// spelled to silence the compiler.
fn conjunct_ignores_parameters(method: &syn::ImplItemFn) -> bool {
    let mut bindings = HashSet::new();
    for input in &method.sig.inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            pattern_bindings(&pat_type.pat, &mut bindings);
        }
    }
    // Underscore-prefixed bindings are the compiler-sanctioned spelling of "I
    // do not read this". Searching the body for them would be searching for a
    // name the author already declared unused, so they contribute nothing.
    bindings.retain(|b| !b.starts_with('_'));
    if !bindings.is_empty() {
        let mut scanner = IdentUseScanner {
            targets: &bindings,
            found: false,
        };
        syn::visit::Visit::visit_block(&mut scanner, &method.block);
        if scanner.found {
            return false;
        }
    }
    block_is_inert(&method.block)
}

/// Reports whether a block manufactures its value without consulting anything.
///
/// See `expr_is_inert` for the whitelist and for why the check exists.
fn block_is_inert(block: &syn::Block) -> bool {
    block.stmts.iter().all(|stmt| match stmt {
        // `let x = <inert>;` binds a manufactured constant. `let … else { … }`
        // is a fallible destructure, so it is an operation.
        syn::Stmt::Local(local) => local
            .init
            .as_ref()
            .is_some_and(|init| init.diverge.is_none() && expr_is_inert(&init.expr)),
        syn::Stmt::Expr(expr, _) => expr_is_inert(expr),
        // A nested `fn`, `use`, or `macro_rules!` inside a method body is not a
        // value-manufacturing form, and a `;`-only statement carries nothing.
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => false,
    })
}

/// Reports whether an expression can produce a value without consulting `self`,
/// a parameter, or any ambient source such as a random-number generator, a
/// clock, the filesystem, or an awaited future.
///
/// **This is a positive whitelist, closed by construction.** It enumerates the
/// expression forms that manufacture a constant and rejects every other form,
/// including every method call, every `.await`, every macro with a non-empty
/// token stream, and every call whose callee is not one of the five
/// argument-transparent constructors below. Adding an entry means naming
/// another way to manufacture a constant; no entry is a bypass spelling.
///
/// The six permitted callee names — `Ok`, `Err`, `Some`, `default`, `new`,
/// `pin` — are the standard-library forms that carry their arguments through unchanged
/// or take none at all, so a call to one of them adds no information the
/// arguments did not already hold. Their arguments must themselves be inert, so
/// `Zeroizing::new(OsRng.gen())` is not inert even though `new` is permitted.
fn expr_is_inert(expr: &syn::Expr) -> bool {
    /// Callee names that carry their arguments through unchanged or take none.
    const TRANSPARENT_CONSTRUCTORS: &[&str] = &["Ok", "Err", "Some", "default", "new", "pin"];

    match expr {
        // A literal, a local, a unit variant, or an associated constant.
        syn::Expr::Lit(_) | syn::Expr::Path(_) => true,

        // Aggregates of manufactured constants.
        syn::Expr::Tuple(t) => t.elems.iter().all(expr_is_inert),
        syn::Expr::Array(a) => a.elems.iter().all(expr_is_inert),
        syn::Expr::Repeat(r) => expr_is_inert(&r.expr) && expr_is_inert(&r.len),
        syn::Expr::Struct(s) => {
            s.fields.iter().all(|f| expr_is_inert(&f.expr))
                && s.rest.as_deref().is_none_or(expr_is_inert)
        }

        // Forms that pass a value through unchanged.
        syn::Expr::Reference(r) => expr_is_inert(&r.expr),
        syn::Expr::Cast(c) => expr_is_inert(&c.expr),
        syn::Expr::Paren(p) => expr_is_inert(&p.expr),
        syn::Expr::Group(g) => expr_is_inert(&g.expr),
        syn::Expr::Block(b) => block_is_inert(&b.block),
        syn::Expr::Async(a) => block_is_inert(&a.block),
        syn::Expr::Unsafe(u) => block_is_inert(&u.block),
        syn::Expr::Return(r) => r.expr.as_deref().is_none_or(expr_is_inert),

        // Arithmetic and selection over manufactured constants stay constant.
        syn::Expr::Unary(u) => expr_is_inert(&u.expr),
        syn::Expr::Binary(b) => expr_is_inert(&b.left) && expr_is_inert(&b.right),
        syn::Expr::Field(f) => expr_is_inert(&f.base),
        syn::Expr::Index(i) => expr_is_inert(&i.expr) && expr_is_inert(&i.index),
        syn::Expr::If(if_expr) => {
            expr_is_inert(&if_expr.cond)
                && block_is_inert(&if_expr.then_branch)
                && if_expr
                    .else_branch
                    .as_ref()
                    .is_none_or(|(_, e)| expr_is_inert(e))
        }
        syn::Expr::Match(m) => {
            expr_is_inert(&m.expr) && m.arms.iter().all(|arm| expr_is_inert(&arm.body))
        }

        // A call to one of the argument-transparent constructors, with inert
        // arguments. Every other call performs work.
        syn::Expr::Call(call) => {
            let syn::Expr::Path(path_expr) = call.func.as_ref() else {
                return false;
            };
            let Some(last) = path_expr.path.segments.last() else {
                return false;
            };
            TRANSPARENT_CONSTRUCTORS.contains(&last.ident.to_string().as_str())
                && call.args.iter().all(expr_is_inert)
        }

        // A macro with an empty token stream — `vec![]`, `HashMap::new()`'s
        // macro cousins — expands to an empty container and reads nothing. A
        // macro carrying tokens can expand to anything, so it is not inert.
        syn::Expr::Macro(m) => m.mac.tokens.is_empty(),

        // Every remaining form — a method call, `.await`, `?`, an assignment, a
        // loop, a closure, a `let` guard, a range, `break`/`continue`/`yield` —
        // either performs work or reads something.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Conjunct 3: does every value the method produces assert success?
// ---------------------------------------------------------------------------

/// Reports whether a type mentions `Result` anywhere inside it, after looking
/// through `impl Future<Output = …>`, `dyn Future<Output = …>`,
/// `Pin<Box<…>>`, `BoxFuture<'_, …>`, references, and parentheses.
///
/// A capability method is fallible when its caller can observe a failure. Every
/// such shape in this workspace spells that failure as a `Result` somewhere in
/// the return type, whether directly (`-> Result<T, E>`), behind an async
/// signature, or behind a boxed future.
fn type_mentions_result(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) => {
            let Some(last) = type_path.path.segments.last() else {
                return false;
            };
            if last.ident == "Result" {
                return true;
            }
            generic_arguments_mention_result(&last.arguments)
        }
        syn::Type::ImplTrait(it) => it.bounds.iter().any(bound_mentions_result),
        syn::Type::TraitObject(to) => to.bounds.iter().any(bound_mentions_result),
        syn::Type::Reference(r) => type_mentions_result(&r.elem),
        syn::Type::Paren(p) => type_mentions_result(&p.elem),
        syn::Type::Group(g) => type_mentions_result(&g.elem),
        _ => false,
    }
}

fn bound_mentions_result(bound: &syn::TypeParamBound) -> bool {
    match bound {
        syn::TypeParamBound::Trait(t) => t
            .path
            .segments
            .last()
            .is_some_and(|seg| generic_arguments_mention_result(&seg.arguments)),
        _ => false,
    }
}

fn generic_arguments_mention_result(args: &syn::PathArguments) -> bool {
    let syn::PathArguments::AngleBracketed(angled) = args else {
        return false;
    };
    angled.args.iter().any(|arg| match arg {
        syn::GenericArgument::Type(t) => type_mentions_result(t),
        // `Future<Output = Result<…>>` binds the result through an associated
        // type, not through a positional generic argument.
        syn::GenericArgument::AssocType(assoc) => type_mentions_result(&assoc.ty),
        _ => false,
    })
}

/// Reports whether the method's declared return type is fallible.
fn method_return_is_fallible(method: &syn::ImplItemFn) -> bool {
    match &method.sig.output {
        syn::ReturnType::Default => false,
        syn::ReturnType::Type(_, ty) => type_mentions_result(ty),
    }
}

/// Collects every expression whose value becomes the method's output, following
/// the value path through the wrappers a fallible capability method uses.
///
/// The walk descends through: the tail expression of a block, an `async` block,
/// an `unsafe` block, `Box::pin(…)` / `Box::new(…)` / `Arc::new(…)`, both arms
/// of an `if`, every arm of a `match`, and a labelled block. It does **not**
/// descend into a closure, whose body is a separate function.
fn collect_value_expressions<'a>(expr: &'a syn::Expr, out: &mut Vec<&'a syn::Expr>) {
    match expr {
        syn::Expr::Block(b) => collect_block_value_expressions(&b.block, out),
        syn::Expr::Async(a) => collect_block_value_expressions(&a.block, out),
        syn::Expr::Unsafe(u) => collect_block_value_expressions(&u.block, out),
        syn::Expr::Group(g) => collect_value_expressions(&g.expr, out),
        syn::Expr::Paren(p) => collect_value_expressions(&p.expr, out),
        syn::Expr::If(if_expr) => {
            collect_block_value_expressions(&if_expr.then_branch, out);
            if let Some((_, else_expr)) = &if_expr.else_branch {
                collect_value_expressions(else_expr, out);
            } else {
                // An `if` with no `else` yields `()` on the false path, which is
                // not an `Ok(..)` construction, so record the `if` itself and let
                // the caller reject it.
                out.push(expr);
            }
        }
        syn::Expr::Match(m) => {
            for arm in &m.arms {
                collect_value_expressions(&arm.body, out);
            }
        }
        syn::Expr::Call(call) => {
            if call_is_transparent_wrapper(call) {
                for arg in &call.args {
                    collect_value_expressions(arg, out);
                }
            } else {
                out.push(expr);
            }
        }
        other => out.push(other),
    }
}

/// Reports whether a call merely wraps its argument in a container that carries
/// the value through unchanged, so the value path continues into the argument.
fn call_is_transparent_wrapper(call: &syn::ExprCall) -> bool {
    let syn::Expr::Path(path_expr) = call.func.as_ref() else {
        return false;
    };
    let segments: Vec<String> = path_expr
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    if call.args.len() != 1 {
        return false;
    }
    matches!(
        segments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["Box", "pin" | "new"] | ["Arc" | "Rc", "new"]
    )
}

/// Collects the value expressions of a block: its tail expression, plus every
/// `return` the block reaches without crossing a closure boundary.
fn collect_block_value_expressions<'a>(block: &'a syn::Block, out: &mut Vec<&'a syn::Expr>) {
    collect_returns_in_block(block, out);
    // A block ending in a statement (or in nothing) yields `()`, which is not
    // an `Ok(..)` construction. Record nothing for that case; the caller
    // rejects an empty set unless a `return` supplied the value.
    if let Some(syn::Stmt::Expr(expr, None)) = block.stmts.last() {
        collect_value_expressions(expr, out);
    }
}

/// Finds every `return` expression reachable from a block without descending
/// into a closure. A `return` inside an `async` block is the future's output,
/// so the walk does descend into `async`.
fn collect_returns_in_block<'a>(block: &'a syn::Block, out: &mut Vec<&'a syn::Expr>) {
    struct ReturnCollector<'a> {
        out: Vec<&'a syn::Expr>,
    }
    impl<'a> syn::visit::Visit<'a> for ReturnCollector<'a> {
        fn visit_expr_closure(&mut self, _: &'a syn::ExprClosure) {
            // A closure's `return` leaves the closure, not the method.
        }
        fn visit_expr_return(&mut self, node: &'a syn::ExprReturn) {
            // A bare `return;` yields `()`, which is not an `Ok(..)`
            // construction, so it contributes no value expression.
            if let Some(expr) = node.expr.as_deref() {
                self.out.push(expr);
            }
            syn::visit::visit_expr_return(self, node);
        }
    }
    let mut collector = ReturnCollector { out: Vec::new() };
    syn::visit::Visit::visit_block(&mut collector, block);
    out.extend(collector.out);
}

/// Reports whether an expression constructs `Ok(payload)` and yields the
/// payload.
fn as_ok_construction(expr: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::Call(call) = expr else {
        return None;
    };
    let syn::Expr::Path(path_expr) = call.func.as_ref() else {
        return None;
    };
    let last = path_expr.path.segments.last()?;
    if last.ident != "Ok" || call.args.len() != 1 {
        return None;
    }
    call.args.first()
}

/// Reports whether an expression is the path `None`, the honest-absence value.
fn is_none_path(expr: &syn::Expr) -> bool {
    let inner = match expr {
        syn::Expr::Paren(p) => p.expr.as_ref(),
        syn::Expr::Group(g) => g.expr.as_ref(),
        other => other,
    };
    let syn::Expr::Path(path_expr) = inner else {
        return false;
    };
    path_expr
        .path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "None")
        && path_expr.path.segments.last().is_some_and(|seg| {
            matches!(seg.arguments, syn::PathArguments::None)
                || matches!(seg.arguments, syn::PathArguments::AngleBracketed(_))
        })
}

/// Reports whether the body contains a `?` escape or an `Err(..)` construction
/// anywhere, either of which means the method can report failure.
fn body_can_report_failure(block: &syn::Block) -> bool {
    struct FailureScanner {
        found: bool,
    }
    impl syn::visit::Visit<'_> for FailureScanner {
        fn visit_expr_try(&mut self, node: &syn::ExprTry) {
            self.found = true;
            syn::visit::visit_expr_try(self, node);
        }
        fn visit_expr_call(&mut self, node: &syn::ExprCall) {
            if let syn::Expr::Path(path_expr) = node.func.as_ref()
                && path_expr
                    .path
                    .segments
                    .last()
                    .is_some_and(|seg| seg.ident == "Err")
            {
                self.found = true;
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut scanner = FailureScanner { found: false };
    syn::visit::Visit::visit_block(&mut scanner, block);
    scanner.found
}

/// Conjunct 3: every value the method can produce asserts that the operation
/// succeeded.
fn conjunct_asserts_success(method: &syn::ImplItemFn) -> bool {
    if !method_return_is_fallible(method) {
        return false;
    }
    if body_can_report_failure(&method.block) {
        return false;
    }
    let mut values = Vec::new();
    collect_block_value_expressions(&method.block, &mut values);
    if values.is_empty() {
        return false;
    }
    // `Ok(None)` reports the protocol-supported absent state: the caller learns
    // that the capability has no answer, which is what a real backend holding
    // nothing would also report. ADR-062 §Decision 5 classifies this shape as
    // fail-closed and not a nullifier.
    values
        .iter()
        .all(|expr| as_ok_construction(expr).is_some_and(|payload| !is_none_path(payload)))
}

/// The full three-conjunct predicate. This function, and nothing else, decides
/// whether a capability method is a security nullifier.
fn method_is_security_nullifier(method: &syn::ImplItemFn) -> bool {
    conjunct_ignores_self(method)
        && conjunct_ignores_parameters(method)
        && conjunct_asserts_success(method)
}

// ---------------------------------------------------------------------------
// cfg evaluation: can this item exist in a production build?
// ---------------------------------------------------------------------------

/// Evaluates a `cfg` predicate under the assignment that binds `test` to false,
/// `feature = "testing"` to false, and every other atom to true.
///
/// The assignment is optimistic on unknown atoms, so the answer means "some
/// build with `test` off and the `testing` feature off can contain this item".
/// An item for which this returns false cannot appear in any production build
/// and is out of scope, which is how `#[cfg(feature = "testing")]` takes a
/// gated nullifier out of this gate and hands it to
/// `scripts/check-shipped-feature-graph.sh` instead.
fn cfg_predicate_holds_in_production(tokens: proc_macro2::TokenStream) -> bool {
    let Ok(meta) = syn::parse2::<syn::Meta>(tokens) else {
        // An unparseable predicate is treated as possibly-production, the
        // in-scope direction.
        return true;
    };
    eval_cfg_meta(&meta)
}

fn eval_cfg_meta(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => {
            // A bare atom such as `test`, `unix`, or `target_arch`.
            !path.is_ident("test")
        }
        syn::Meta::NameValue(nv) => {
            // `feature = "testing"` and friends.
            if !nv.path.is_ident("feature") {
                return true;
            }
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &nv.value
            else {
                return true;
            };
            s.value() != "testing"
        }
        syn::Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return true;
            };
            if list.path.is_ident("not") {
                return nested.first().is_none_or(|m| !eval_cfg_meta(m));
            }
            if list.path.is_ident("all") {
                return nested.iter().all(eval_cfg_meta);
            }
            if list.path.is_ident("any") {
                return nested.iter().any(eval_cfg_meta);
            }
            // `feature = "x"` written as a list, or an unrecognised combinator.
            true
        }
    }
}

/// Reports whether any `#[cfg(…)]` on the item excludes it from every
/// production build.
fn attrs_exclude_from_production(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        !cfg_predicate_holds_in_production(list.tokens.clone())
    })
}

// ---------------------------------------------------------------------------
// Module-tree walk: which files does a production build compile?
// ---------------------------------------------------------------------------

/// The workspace root, derived from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("scp-testing manifest dir has a crates/ parent and a workspace root")
        .to_path_buf()
}

/// Every crate root file a production build compiles: each crate's
/// `src/lib.rs`, `src/main.rs`, and `src/bin/*.rs`.
fn crate_root_files(workspace: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let crates_dir = workspace.join("crates");
    let mut crate_dirs = Vec::new();
    collect_crate_dirs(&crates_dir, &mut crate_dirs);
    for crate_dir in crate_dirs {
        let src = crate_dir.join("src");
        for name in ["lib.rs", "main.rs"] {
            let candidate = src.join(name);
            if candidate.is_file() {
                roots.push(candidate);
            }
        }
        let bin_dir = src.join("bin");
        if let Ok(entries) = std::fs::read_dir(&bin_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "rs") {
                    roots.push(path);
                }
            }
        }
    }
    roots.sort();
    roots
}

/// Collects every directory under `dir` that holds a `Cargo.toml`, so a crate
/// nested inside another crate's directory (`scp-ffi/uniffi`, `scp-ffi/napi`,
/// `scp-ffi/common`) is found.
fn collect_crate_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("Cargo.toml").is_file() {
        out.push(dir.to_path_buf());
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == "src" || name.starts_with('.') {
            continue;
        }
        collect_crate_dirs(&path, out);
    }
}

/// One impl method the detector examined, with the source location that names
/// it in a failure message.
#[derive(Debug)]
struct NullifierFinding {
    file_rel: String,
    trait_name: String,
    type_name: String,
    method_name: String,
}

/// Accumulates what a single scan learned, so the scope-integrity test can
/// assert that every registered trait still resolves.
#[derive(Default)]
struct ScanReport {
    findings: Vec<NullifierFinding>,
    /// Trait names for which a `trait` definition was found.
    traits_defined: HashSet<String>,
    /// Trait names for which at least one production-reachable
    /// `impl … for …` was found.
    traits_implemented: HashSet<String>,
    /// How many capability-trait impl methods the predicate ran against.
    methods_examined: usize,
    files_scanned: usize,
}

/// Walks the production module tree of every workspace crate and applies the
/// three-conjunct predicate to every capability-trait impl method it reaches.
fn scan_workspace() -> ScanReport {
    let workspace = workspace_root();
    let registered = registered_trait_names();
    let mut report = ScanReport::default();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    for root in crate_root_files(&workspace) {
        scan_module_file(&root, &workspace, &registered, &mut visited, &mut report);
    }
    report
}

/// Parses one module file, records what it finds, and follows its `mod`
/// declarations.
fn scan_module_file(
    path: &Path,
    workspace: &Path,
    registered: &HashSet<String>,
    visited: &mut HashSet<PathBuf>,
    report: &mut ScanReport,
) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical) {
        return;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    let parsed = match syn::parse_file(&src) {
        Ok(f) => f,
        Err(err) => panic!(
            "capability-nullifier scanner: syn parse failed for {} — {err}",
            path.display()
        ),
    };
    report.files_scanned += 1;
    let rel = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    scan_items(
        &parsed.items,
        path,
        &rel,
        workspace,
        registered,
        visited,
        report,
    );
}

/// Recursive worker over a module's items.
#[allow(clippy::too_many_arguments)]
fn scan_items(
    items: &[syn::Item],
    owner_file: &Path,
    rel: &str,
    workspace: &Path,
    registered: &HashSet<String>,
    visited: &mut HashSet<PathBuf>,
    report: &mut ScanReport,
) {
    for item in items {
        match item {
            syn::Item::Trait(item_trait) => {
                let name = item_trait.ident.to_string();
                if registered.contains(&name) {
                    report.traits_defined.insert(name);
                }
            }
            syn::Item::Mod(item_mod) => {
                if attrs_exclude_from_production(&item_mod.attrs) {
                    continue;
                }
                match &item_mod.content {
                    Some((_, inner)) => scan_items(
                        inner, owner_file, rel, workspace, registered, visited, report,
                    ),
                    None => {
                        if let Some(child) = resolve_module_file(owner_file, item_mod) {
                            scan_module_file(&child, workspace, registered, visited, report);
                        }
                    }
                }
            }
            syn::Item::Impl(item_impl) => {
                let Some((_, trait_path, _)) = &item_impl.trait_ else {
                    continue;
                };
                let Some(trait_name) = trait_path.segments.last().map(|s| s.ident.to_string())
                else {
                    continue;
                };
                if !registered.contains(&trait_name) {
                    continue;
                }
                if attrs_exclude_from_production(&item_impl.attrs) {
                    continue;
                }
                report.traits_implemented.insert(trait_name.clone());
                let type_name = self_type_name(&item_impl.self_ty);
                for impl_item in &item_impl.items {
                    let syn::ImplItem::Fn(method) = impl_item else {
                        continue;
                    };
                    if attrs_exclude_from_production(&method.attrs) {
                        continue;
                    }
                    report.methods_examined += 1;
                    if method_is_security_nullifier(method) {
                        report.findings.push(NullifierFinding {
                            file_rel: rel.to_owned(),
                            trait_name: trait_name.clone(),
                            type_name: type_name.clone(),
                            method_name: method.sig.ident.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Renders the implementing type's name for a failure message.
fn self_type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map_or_else(|| "<type>".to_owned(), |s| s.ident.to_string()),
        syn::Type::Reference(r) => self_type_name(&r.elem),
        _ => "<type>".to_owned(),
    }
}

/// Resolves a `mod name;` declaration to the file that holds it, honouring
/// `#[path = "…"]`.
fn resolve_module_file(owner_file: &Path, item_mod: &syn::ItemMod) -> Option<PathBuf> {
    let dir = module_directory(owner_file);
    for attr in &item_mod.attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = &nv.value
        else {
            continue;
        };
        let candidate = dir.join(s.value());
        return candidate.is_file().then_some(candidate);
    }
    let name = item_mod.ident.to_string();
    let flat = dir.join(format!("{name}.rs"));
    if flat.is_file() {
        return Some(flat);
    }
    let nested = dir.join(&name).join("mod.rs");
    nested.is_file().then_some(nested)
}

/// The directory a module's `mod` declarations resolve against: the file's own
/// directory for a crate root or a `mod.rs`, and a sibling directory named for
/// the file otherwise.
fn module_directory(owner_file: &Path) -> PathBuf {
    let parent = owner_file.parent().unwrap_or_else(|| Path::new("."));
    let stem = owner_file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if matches!(stem.as_str(), "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Spec §17.17.2 SCP-CAPSEL-8012 — no security-nullifier arm of any of the
/// seven provider capabilities may sit on a production path.
#[test]
fn no_capability_trait_impl_is_a_security_nullifier() {
    let report = scan_workspace();
    assert!(
        report.files_scanned > 400,
        "capability-nullifier scanner reached only {} files, which means the \
         module-tree walk broke rather than that the workspace shrank (the \
         clean tree reaches 552)",
        report.files_scanned
    );
    assert!(
        report.findings.is_empty(),
        "spec §17.17.2 SCP-CAPSEL-8012 violation: {} capability-trait method(s) \
         read neither `self` nor any parameter and still report success, so each \
         one asserts an outcome it never produced. Make the method fail closed \
         (a typed error, or the protocol's absent state), or gate the whole arm \
         behind `#[cfg(feature = \"testing\")]` so \
         scripts/check-shipped-feature-graph.sh can prove it absent:\n{}",
        report.findings.len(),
        report
            .findings
            .iter()
            .map(|f| format!(
                "  {} — capability: {}\n    impl {} for {} :: {}",
                f.file_rel,
                capability_of(&f.trait_name),
                f.trait_name,
                f.type_name,
                f.method_name
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Capabilities whose only implementations are `testing`-gated, so the
/// production module tree holds no impl for them.
///
/// `DeviceAttestation`'s sole arm is `InMemoryDeviceAttestation`, which ADR-062
/// classifies a nullifier and Slice 6 gated behind `feature = "testing"`; spec
/// §9 line 187 declines the capability outright, so no production arm exists to
/// find. `PreRotationCustody`'s sole arm is `InMemoryPreRotationCustody`, gated
/// the same way, with its real backend still unbuilt (RFC #2130).
/// `RelayPublisher`'s sole arm is `InMemoryRelayPublisher`, which ADR-062
/// Slice 11 gated behind `cfg(any(test, feature = "testing"))`; issue #482,
/// relay resolution, builds the production publisher. The two UniFFI provider
/// traits, `KeyCustodyProvider` and `DeviceAttestationProvider`, are
/// foreign-implemented callback interfaces: the SDK consumer writes the
/// implementation in Swift or Kotlin, so no Rust impl exists on either side of
/// the gate. Their absence from the scan is the expected state, not a scope
/// regression — the definition assertion below still catches a rename, and the
/// third assertion below fails if any of them gains a production arm.
const TRAITS_WITHOUT_PRODUCTION_IMPLS: &[&str] = &[
    "DeviceAttestation",
    "PreRotationCustody",
    "RelayPublisher",
    "KeyCustodyProvider",
    "DeviceAttestationProvider",
];

/// Scope integrity: every trait name in `CAPABILITY_TRAITS` still names a trait
/// the production module tree defines, and the scan still reaches the impls it
/// reached before.
///
/// Without these assertions the gate could be defanged silently by renaming a
/// capability trait or by breaking the module-tree walk: the registry entry
/// would match nothing, the scan would examine nothing, and the gate would pass
/// while covering less.
#[test]
fn registry_scope_still_resolves() {
    let report = scan_workspace();
    let registered = registered_trait_names();

    let missing_definition: Vec<&String> = registered
        .iter()
        .filter(|t| !report.traits_defined.contains(*t))
        .collect();
    assert!(
        missing_definition.is_empty(),
        "these capability traits are registered in CAPABILITY_TRAITS but no \
         `trait` definition was found in the production module tree — a rename \
         or a move would silently narrow this gate's scope: {missing_definition:?}"
    );

    let unexpectedly_unimplemented: Vec<&String> = registered
        .iter()
        .filter(|t| {
            !report.traits_implemented.contains(*t)
                && !TRAITS_WITHOUT_PRODUCTION_IMPLS.contains(&t.as_str())
        })
        .collect();
    assert!(
        unexpectedly_unimplemented.is_empty(),
        "these capability traits had a production implementation and no longer \
         do, so the predicate now runs against nothing for them: \
         {unexpectedly_unimplemented:?}"
    );

    let newly_implemented: Vec<&&str> = TRAITS_WITHOUT_PRODUCTION_IMPLS
        .iter()
        .filter(|t| report.traits_implemented.contains(**t))
        .collect();
    assert!(
        newly_implemented.is_empty(),
        "these capability traits gained a production implementation. Remove \
         them from TRAITS_WITHOUT_PRODUCTION_IMPLS and record the capability \
         decision that put a production arm behind them: {newly_implemented:?}"
    );

    assert!(
        // The clean tree examines 303 methods across 552 files. The floor sits
        // well below that, because a broken module walk collapses the count
        // toward zero rather than trimming it, while a legitimate deletion
        // trims it by a few.
        report.methods_examined >= 200,
        "the predicate ran against only {} capability-trait methods. The scan \
         reached {} files. A drop here means the module-tree walk or the trait \
         registry stopped reaching impls it used to reach.",
        report.methods_examined,
        report.files_scanned
    );
}

// ---------------------------------------------------------------------------
// Pinned fixtures — the detector's own true positive and false positive
// ---------------------------------------------------------------------------

/// Parses one inline impl and returns its single method.
fn single_method(src: &str) -> syn::ImplItemFn {
    let parsed = syn::parse_file(src).expect("fixture parses");
    let item_impl = parsed
        .items
        .iter()
        .find_map(|it| match it {
            syn::Item::Impl(ii) => Some(ii),
            _ => None,
        })
        .expect("fixture holds an impl");
    item_impl
        .items
        .iter()
        .find_map(|ii| match ii {
            syn::ImplItem::Fn(f) => Some(f.clone()),
            _ => None,
        })
        .expect("fixture holds a method")
}

/// Pinned true positive. This is the shape of `NoOpStorage::store`, deleted in
/// commit 49717fc1d: a `Storage::store` that consults no backing store, reads
/// neither the key nor the value, and tells its caller the write succeeded.
/// The detector MUST flag it.
///
/// Deleting or weakening this assertion is the visible cost of defanging the
/// detector.
#[test]
fn detector_flags_pinned_nullifier_fixture() {
    let method = single_method(
        "
        struct Fixture;
        impl Storage for Fixture {
            async fn store(&self, key: &str, value: &[u8]) -> Result<(), PlatformError> {
                Ok(())
            }
        }
        ",
    );
    assert!(
        conjunct_ignores_self(&method),
        "conjunct 1 failed: the fixture reads no `self`"
    );
    assert!(
        conjunct_ignores_parameters(&method),
        "conjunct 2 failed: the fixture reads neither `key` nor `value`"
    );
    assert!(
        conjunct_asserts_success(&method),
        "conjunct 3 failed: the fixture returns `Ok(())`, a success assertion"
    );
    assert!(
        method_is_security_nullifier(&method),
        "the detector must flag a capability method that reads nothing and \
         still reports success"
    );
}

/// Pinned false positive. A method that ignores `self` but reads a parameter is
/// bound to its caller's input, so it is a stateless helper and not a nullifier.
/// The detector MUST NOT flag it.
///
/// Deleting or weakening this assertion is the visible cost of turning the
/// detector into a false-positive generator, which is how a gate gets disabled.
#[test]
fn detector_ignores_pinned_stateless_but_bound_fixture() {
    let method = single_method(
        "
        struct Fixture;
        impl Storage for Fixture {
            async fn store(&self, key: &str, value: &[u8]) -> Result<(), PlatformError> {
                write_through(key, value)?;
                Ok(())
            }
        }
        ",
    );
    assert!(
        conjunct_ignores_self(&method),
        "conjunct 1 holds: the fixture reads no `self`"
    );
    assert!(
        !conjunct_ignores_parameters(&method),
        "conjunct 2 must fail: the fixture reads both `key` and `value`"
    );
    assert!(
        !method_is_security_nullifier(&method),
        "the detector must not flag a method whose output depends on its \
         caller's arguments"
    );
}

/// Conjunct 3, isolated: a method that reads nothing and returns the
/// protocol's absent state fails closed, so the detector must not flag it.
/// This is `NoOpRelayQuerier::query` (ADR-062 §Decision 5).
#[test]
fn detector_ignores_honest_absent_state() {
    let method = single_method(
        "
        struct Fixture;
        impl MultiRelayQuerier for Fixture {
            fn query(
                &self,
                _did: &str,
                _relay_urls: &[String],
            ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send {
                async { Ok(None) }
            }
        }
        ",
    );
    assert!(conjunct_ignores_self(&method));
    assert!(conjunct_ignores_parameters(&method));
    assert!(
        !conjunct_asserts_success(&method),
        "`Ok(None)` reports the absent state, not a produced outcome"
    );
    assert!(!method_is_security_nullifier(&method));
}

/// Conjunct 3, isolated: a method that reads nothing and returns a typed error
/// fails closed, so the detector must not flag it.
#[test]
fn detector_ignores_fail_closed_method() {
    let method = single_method(
        "
        struct Fixture;
        impl KeyCustody for Fixture {
            async fn sign(&self, _key: &KeyHandle, _data: &[u8]) -> Result<Signature, PlatformError> {
                Err(PlatformError::CustodyUnavailable)
            }
        }
        ",
    );
    assert!(conjunct_ignores_self(&method));
    assert!(
        conjunct_ignores_parameters(&method),
        "conjunct 2 holds: constructing an error reads nothing"
    );
    assert!(
        !conjunct_asserts_success(&method),
        "conjunct 3 must fail: a method that constructs `Err(..)` reports \
         failure, which is the fail-closed shape the tenet permits"
    );
    assert!(!method_is_security_nullifier(&method));
}

/// The evasions the predicate must survive: a payload built by
/// `Default::default()`, a payload bound to a local before it is returned, and a
/// payload returned through `Box::pin(async move { … })`. Each reduces to the
/// same value-path structure as `Ok(())`, so each is flagged.
#[test]
fn detector_flags_success_assertions_written_other_ways() {
    let default_payload = single_method(
        "
        struct Fixture;
        impl DeviceAttestation for Fixture {
            async fn attest(&self) -> Result<DeviceAttestationToken, PlatformError> {
                Ok(Default::default())
            }
        }
        ",
    );
    assert!(
        method_is_security_nullifier(&default_payload),
        "`Ok(Default::default())` asserts success exactly as `Ok(())` does"
    );

    let local_binding = single_method(
        "
        struct Fixture;
        impl DeviceAttestation for Fixture {
            async fn verify(&self, _token: &DeviceAttestationToken) -> Result<bool, PlatformError> {
                let verdict = true;
                Ok(verdict)
            }
        }
        ",
    );
    assert!(
        method_is_security_nullifier(&local_binding),
        "binding the payload to a local before returning it changes nothing"
    );

    let boxed_future = single_method(
        "
        struct Fixture;
        impl DhtClient for Fixture {
            fn put(
                &self,
                _record: DhtRecord,
            ) -> Pin<Box<dyn Future<Output = Result<u64, DhtError>> + Send + '_>> {
                Box::pin(async move { Ok(0) })
            }
        }
        ",
    );
    assert!(
        method_is_security_nullifier(&boxed_future),
        "a success assertion wrapped in `Box::pin` of an async block is still \
         a success assertion"
    );
}

/// Pinned false positive, second shape. `KeyCustody::generate_ephemeral_ed25519_seed`
/// on `FileKeyCustody` takes `&self` and no parameters, reads neither, and
/// returns `Ok(seed)` — yet it fills that seed from the operating system's
/// random-number generator, so it produces exactly the outcome its caller asked
/// for. Five methods of this shape ship in this workspace
/// (`crates/scp-platform/src/file.rs`, `crates/scp-platform/src/sqlite/key_custody.rs`,
/// and the three callback custody bridges under `crates/scp-ffi/`). The detector
/// MUST NOT flag them.
///
/// Deleting or weakening this assertion is the visible cost of turning the
/// detector loose on every stateless producer in the tree, which is how a gate
/// earns enough false positives to get disabled.
#[test]
fn detector_ignores_pinned_ambient_source_fixture() {
    let method = single_method(
        "
        struct Fixture;
        impl KeyCustody for Fixture {
            fn generate_ephemeral_ed25519_seed(
                &self,
            ) -> impl Future<Output = Result<Zeroizing<[u8; 32]>, PlatformError>> + Send {
                async move {
                    let mut seed = Zeroizing::new([0u8; 32]);
                    rand::rngs::OsRng.fill_bytes(seed.as_mut());
                    Ok(seed)
                }
            }
        }
        ",
    );
    assert!(
        conjunct_ignores_self(&method),
        "conjunct 1 holds: the method reads no `self`"
    );
    assert!(
        !conjunct_ignores_parameters(&method),
        "conjunct 2 must fail: filling the seed from `OsRng` consults an \
         ambient source, so the method manufactures nothing"
    );
    assert!(
        !method_is_security_nullifier(&method),
        "the detector must not flag a method that produces its answer from the \
         operating system's random-number generator"
    );
}

/// A method that awaits a real backend consults that backend, so the detector
/// must not flag it even when it discards every argument and returns `Ok(())`.
#[test]
fn detector_ignores_method_that_awaits_a_backend() {
    let method = single_method(
        "
        struct Fixture;
        impl BlobStorage for Fixture {
            async fn purge_expired(&self) -> Result<usize, StorageError> {
                let purged = backend_purge().await;
                Ok(purged)
            }
        }
        ",
    );
    assert!(conjunct_ignores_self(&method));
    assert!(
        !conjunct_ignores_parameters(&method),
        "awaiting `backend_purge()` is an operation, so the body is not inert"
    );
    assert!(!method_is_security_nullifier(&method));
}

/// A method that reads `self` consults its backing resource, so it is bound
/// however trivial its body looks. This pins conjunct 1 against a detector that
/// stops looking inside macro token streams.
#[test]
fn detector_ignores_method_that_reads_self_inside_a_macro() {
    let method = single_method(
        "
        struct Fixture;
        impl Storage for Fixture {
            async fn store(&self, _key: &str, _value: &[u8]) -> Result<(), PlatformError> {
                tracing::debug!(\"backend {}\", self.backend_name);
                Ok(())
            }
        }
        ",
    );
    assert!(
        !conjunct_ignores_self(&method),
        "the detector must see `self` inside a macro's token stream"
    );
    assert!(!method_is_security_nullifier(&method));
}

/// The `cfg` evaluator: `#[cfg(not(feature = \"testing\"))]` marks the
/// production-only arm, which must stay in scope, while
/// `#[cfg(any(test, feature = \"testing\"))]` marks the gated arm, which the
/// shipped-feature-graph gate owns instead.
#[test]
fn cfg_evaluator_keeps_production_arms_and_drops_gated_arms() {
    let cases: &[(&str, bool)] = &[
        ("test", false),
        ("feature = \"testing\"", false),
        ("any(test, feature = \"testing\")", false),
        ("all(test, unix)", false),
        ("not(test)", true),
        ("not(feature = \"testing\")", true),
        ("unix", true),
        ("feature = \"sqlite\"", true),
        ("any(feature = \"testing\", feature = \"sqlite\")", true),
        ("all(feature = \"testing\", feature = \"sqlite\")", false),
    ];
    for (predicate, expected) in cases {
        let tokens: proc_macro2::TokenStream = predicate.parse().expect("predicate parses");
        assert_eq!(
            cfg_predicate_holds_in_production(tokens),
            *expected,
            "cfg({predicate}) evaluated wrongly"
        );
    }
}
