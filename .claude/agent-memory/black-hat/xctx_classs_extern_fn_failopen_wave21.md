# Class-S gate wave-21 (commit 1004bb6a5) — ATTR-PEEL CONVERGED, residual CLASS-A: `extern "C" fn`

Gate: `scripts/check-class-s-fail-closed.sh`, scan tree `crates/scp-runtime/src/context`.
Harness: `head -n 3695 <gate> > gatelib.sh; source; FC_FUNCS="" scan_file "<ABSOLUTE path>"`.
GOTCHA: awk inherits the sourcing shell CWD — ALWAYS pass scan_file an ABSOLUTE path
or every file silently fails to open (FNDEF=0 across the whole tree = vacuous scan, not "clean").

## Wave-21 attr-peel = FULLY CONVERGED (the dimension the task was about)
`peel_leading_attrs` (loops `strip_leading_attr`) before the mutation-site fn anchor.
Real scan_file PROVED caught (HIT/GOVHIT): `#[rustfmt::skip]`, stacked `#[a] #[b]`,
attr-macro path `#[tracing::instrument]`, nested-bracket `#[cfg(all(..))]`,
string-with-`]` `#[doc="..]"]`, multi-line attr head (fn caught on later line; head
not misread), `pub(in path) fn`, governance `execute_*` (GOVHIT). FP check: real-tree
1097 recognized fns IDENTICAL parent(cd20e4846) vs HEAD — no new FP, no dropped fn.
Stacked-attr 2nd-test-module → no NTTEST (no FP). CLASS-B one-liner
`#[rustfmt::skip] mod w{ pub fn evil(){} }` genuinely contrived: rustfmt SPLITS it
(verified), so fmt-impossible without skip; once split the inner fn IS detected.

## RESIDUAL CLASS-A-LIVE FAIL-OPEN (pre-existing in base regex, EXPOSED not introduced)
Mutation-site fn anchor: `^(pub..)?(async )?fn NAME` — allows only pub/async. MISSES
`const fn`, `unsafe fn`, `extern "C" fn` at BOTH column-0 AND indented impl-method.
Under `#![forbid(unsafe_code)]` (scp-runtime/src/lib.rs:21 + scp-protocol) the carrier grid:
- `extern "C" fn` / `pub extern "C" fn` / `extern fn` = MISS + COMPILES-clean + FMT-CLEAN
  (no #[rustfmt::skip]) → **CLASS-A-LIVE FAIL-OPEN, viable carrier**.
- `const fn` / `pub const fn` = MISS but rustc E0015 (non-const &mut mutator) → non-carrier.
- `unsafe fn` & all unsafe combos = MISS but forbid(unsafe_code) rejects the DEFINITION → non-carrier.
- `async fn` = already RECOG.
PROVEN against the REAL two-pass gate: planted
`pub extern "C" fn blackhat_extern_evil(){ state.role_state.suspend_all(..); persist_state_best_effort(..); }`
in the live scan tree → gate PASSED (fail-open). Same body as plain `pub fn` → gate FAILED (caught). The `extern` qualifier is the exact hole.
Live tree currently has 0 extern fn / 0 unsafe fn (latent, no live occurrence) but 94 const fn (all non-carriers).
FIX (closed/bounded, not a denylist): widen anchor to also accept `(const |unsafe |extern( "[^"]*")? )*`
before `fn` — recognising the fn means its body is scanned; const stays a non-carrier
by rustc, unsafe by forbid, so widening adds zero FP and closes extern. Convergent.
