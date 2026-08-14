# Class-S gate mutation-site fn-detector — wave-22 (commit dcf9b14c1) CONVERGED

Gate: `scripts/check-class-s-fail-closed.sh`. Real `scan_file` run in isolated worktree
xctx-blackhat (detached @ dcf9b14c1) via funcs-only source + ABSOLUTE paths (awk inherits CWD).

## VERDICT: CONVERGED. fn-detector anchor now accepts the COMPLETE bounded Rust
fn-qualifier grammar. Only documented CLASS-B-contrived (nightly-only) residual remains.

### Anchor (line ~1439): `^(pub..(\(..\))?..)?((const|unsafe|async)..|extern(..".."?)?..)*fn..[A-Za-z0-9_]+`
Closed the prior `pub extern "C" fn` CLASS-A fail-open (was `pub`/`async` only).

### Carriers ALL CAUGHT (real scan_file HIT), col-0 AND indented impl-method:
pub extern "C" fn, extern "C" fn (no pub), bare `extern fn`, const fn, unsafe fn,
async unsafe fn, pub(in crate::x) extern "C" fn, pub(crate) extern, stacked
(pub const unsafe extern "C"), unsafe extern, const extern, C-unwind ABI, tab-separated
qualifiers. Attr-string shapes via #[rustfmt::skip]: lone `]`, raw-string r"..]", raw-hash
r#".."#, escaped-quote — all HIT (string-aware strip_leading_attr w/ in_str + \" escape).

### NO false positives (widened anchor): extern block `extern "C" {`, type alias
`pub type X = extern "C" fn(i32)->i32;`, fn-ptr let binding, comment, string literal —
all SCANNED|0 (regex requires `fn[[:space:]]+IDENT`, so `fn(` is rejected). Correct.

### Real-tree invariance (parent 1004bb6a5 vs head dcf9b14c1, scan dir crates/scp-runtime/src/context):
HIT 2==2 (execute_governance_action, send_message — IDENTICAL content; delegate-persist),
GOVHIT 0==0, GOVFN 30==30 IDENTICAL, FC 28==28 IDENTICAL. FNDEF 1065->1152 (+87, ~66 unique)
= newly-recognised `pub const fn` accessors (allowed_capabilities/created_at/generation/
tag_byte/is_terminal..). Recognising const/unsafe/extern adds SCANNED but ZERO HIT/GOVHIT/
GOVFN/FC. Exactly as the wave-22 comment claims.

### Residual classification:
- raw-identifier fn name `fn r#match` / `r#execute_add_member`: regex captures `r` (truncated
  at `#`). FAILS CLOSED — carrier still HITs; truncated name can't match GOVFN allowlist or a
  delegate, so it can only make the gate STRICTER, never suppress. NOT a fail-open.
- `default fn`, `gen fn`, `async gen fn`: NIGHTLY-ONLY unstable (specialization / gen_blocks).
  Scan dir has zero `#![feature(...)]`; CI is stable -> won't compile. CLASS-B-contrived.

No CLASS-A-live fail-open remains. Mutation-site fn-detector is converged.
