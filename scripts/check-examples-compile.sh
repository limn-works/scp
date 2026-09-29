#!/usr/bin/env bash
# Two assertions about example targets:
#
#   1. Every example target in the workspace compiles, lint-clean, and its example
#      sources hold none of the constructs the source scan below rejects.
#   2. Every published `examples/*.rs` file IS the source of an example target.
#
# Assertion 2 joins on PATH, never on target name. A `[[example]] path = …` key can
# bind the target name `website` to `examples/decoy/website.rs` while
# `examples/website.rs` still ships with no target of its own. A join on name then
# matches `website` against `website` and finds no orphan. The check compiles the
# decoy and prints `── scp-node::website` for a file it never opened. Measured: exit
# 0 with `DhtMode::Memory` sitting in the published file.
#
# WHAT THIS PROVES AND THE WHOLE OF IT. Assertion 1 compiles each example under
# the feature closure cargo gives a dev target, which is NOT the crate's default
# feature set and is NOT what a consumer of the published crate gets. Measured:
# `cargo clippy -p scp-runtime --example identity` builds with
# `--cfg feature="testing"` and `--cfg feature="allow_unencrypted_storage"`, while
# `scp-runtime` declares no `default` key at all. Cargo unifies a crate's
# dev-dependency features into its dev targets and no invocation switches that
# off, so per-package scope narrows the closure without emptying it. Cargo also
# strips path-only DEV-dependencies from a published manifest, and with them the
# feature activations they carried, so an example relying on one compiles here and
# not for a consumer. `crates/scp-runtime/examples/identity.rs` is the measured case.
# It names `InMemoryDhtClient`, which `scp-dht` compiles only under `scp-dht/testing`,
# and for one round `scp-runtime` reached that feature through the stripped
# dev-dependency edge alone, so the file compiled here and failed for a consumer.
# `scp-runtime/testing` now carries `scp-dht/testing` alongside `scp-platform/testing`,
# and `scp-dht` and `scp-platform` are normal dependencies that survive publication, so
# all four of that crate's examples compile for a consumer under `--features testing`.
# A probe crate outside the workspace measured that, not this check, and the limitation
# stated above holds whatever any one crate's manifest says.
#
# Therefore this check CANNOT prove that an example compiles for someone who
# installs the crate, and CANNOT prove that an example avoids a test-only
# construct. Do not write a comment, a commit message, or a CI step description
# claiming either. Four earlier versions of this header claimed one or the other,
# and each time a reviewer had to measure the rustc command line to establish that
# the claim was false.
#
# WHAT IT DOES CATCH, measured:
#   - `crates/scp-node/examples/website.rs` naming `DhtMode::Memory`, because
#     scp-node's OWN `testing` feature is genuinely off in its dev closure. E0599.
#   - A published `examples/*.rs` that is no target's source, which
#     `autoexamples = false` and a redirected `path` key both produce.
#
# WHY ASSERTION 1 ITERATES TARGETS. `exclude = ["examples/*"]` empties the
# published file set while the target still exists; iterating published files
# would drop it from coverage in silence. Targets are what gets compiled.
#
# WHY EACH TARGET IS NAMED. The loop runs `--example NAME` per target and never
# `--examples`. Under `--examples` cargo skips a target whose `required-features`
# are off and exits 0; named, the same target fails. Case `requiredfeatures` in
# scripts/tests/examples-compile/run-tests.sh pins this.
#
# WHY PACKAGE SCOPE IS LOAD-BEARING. `cargo clippy --workspace --examples`
# unifies dev-dependency features across EVERY member: `crates/scp-ffi`
# dev-depends on `scp-ffi-common` with `features = ["testing"]`, whose `testing`
# list carries `scp-node?/testing`. Measured: the workspace-wide form exits 0 on
# the `DhtMode::Memory` defect; this loop exits 1.
#
# WHY ASSERTION 1 READS THE SOURCE. A target whose body sits behind
# `#[cfg(feature = "testing")] fn main() { ... }`, next to an empty
# `#[cfg(not(feature = "testing"))] fn main() {}`, compiles to nothing on the feature set
# the loop builds, and a compile alone counts it as checked. So the scan reads each target's
# source file and every `.rs` file under the package's `examples/`, published or not, and
# fails on any of these:
#   - A `cfg(` or `cfg!(` predicate that names anything but a platform key (`unix`,
#     `windows`, `target_*`) under `not`, `any` or `all`, or that is false on the host
#     running this gate, as `rustc --print cfg` reports it. A false platform predicate
#     removes code as a feature key does: `#[cfg(not(unix))]` on the Linux CI runner.
#     An empty `any()` or `all()` fails too.
#   - `cfg_attr`, `#[path]`, `include` and `macro_rules`. `cfg_attr` can carry a `path`
#     key, `#[path]` and `include!` bring in a file the scan never opens, and a local macro
#     can build a `cfg` attribute from an ident or drop its input tokens. No example in the
#     workspace uses any of the four.
#   - A block comment or string literal the scan cannot close. Block comments nest, as
#     rustc reads them, and an unclosed one fails the scan instead of desynchronizing it.
# String literals and comments are blanked first, so neither hides a predicate from the
# scan nor fakes one into it. Cases `cfgbody` to `macrorules` pin this, and case
# `platformcfg` pins what passes.
#
# RESIDUAL LIMITS. These are the bypasses known to the gate's authors, not a proof that
# no other exists:
#   - The dev-dependency closure stated above (lesson row 4b).
#   - Code outside `examples/` that an example calls or expands (lesson row 9c): a lib
#     item compiled only under a feature key beside an empty default twin, or a lib or
#     dependency macro (`#[tokio::main]` is one) that drops or feature-gates its input.
#     The scan reads example sources only. No human has ruled this acceptable.
#   - An edit to the crate's BUILD CONFIGURATION: its `build.rs`, a manifest key, or
#     `.cargo/config.toml` rustflags. "Write access to the crate" is not the criterion:
#     every defect this gate catches, including the `DhtMode::Memory` edit above, is
#     written by someone with that access, so write access separates nothing. A source
#     edit to an example is this gate's subject and never an exemption. `build.rs` is an
#     instance of the criterion that needs no manifest key, and one hypothesis stays
#     unmeasured: that a build script printing `cargo::rustc-cfg=feature="testing"` makes
#     `DhtMode::Memory` exist for every target of the package. Two attempts to reproduce
#     it made the gate exit 1 instead, because the injected cfg desynchronized the lib
#     from its dependency features. Review covers build-configuration edits.
# No hook guards this script. AGENTS.md lists it among the enforcement files a human must
# approve weakening, and review enforces that rule.
#
# See .docs/lessons/shipped-targets-need-a-default-feature-build.md.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
checked=0

# cfg_scan FILE LABEL: fail when FILE holds a construct the header's source rules reject.
# Each hit prints on its own line.
HOST_CFG="$(rustc --print cfg </dev/null)" || { echo "FAIL: 'rustc --print cfg' failed." >&2; exit 1; }
IFS= read -r -d '' CFG_SCAN <<'PL' || true
local $/; $_ = <STDIN>;
my @str;
my %plat = map { $_ => 1 } qw(unix windows target_os target_family target_arch
  target_pointer_width target_endian target_env target_vendor);
my %host = map { $_ => 1 } split /\n/, $ENV{HOST_CFG};
s{(b?r(\#*)"(.*?)"\2|b?"((?:[^"\\]|\\.)*)"|b?'(?:[^'\\]|\\.)')|//[^\n]*|(/\*(?:[^/*]++|/(?!\*)|\*(?!/)|(?5))*+\*/)}{
  !defined $1 ? ' ' : $1 =~ /^b?'/ ? '0' : do { push @str, defined $3 ? $3 : $4; qq{"$#str"} }
}gse;
print "unbalanced block comment\n" if m{/\*};
print "unbalanced string literal\n" if s/"\d+"//gr =~ /"/;
print "include!\n" if /\binclude\b/;
print "macro_rules!\n" if /\bmacro_rules\b/;
print "#[path]\n" if /#\s*!?\s*\[\s*path\b/;
print "cfg_attr\n" if /\bcfg_attr\b/;
sub ev {
  my $t = shift; my $k = shift @$t;
  return undef unless defined $k && $k =~ /^[A-Za-z_]/;
  if (@$t && $t->[0] eq '(') {
    return undef unless $k =~ /^(?:not|any|all)$/;
    shift @$t; my @v;
    while (@$t && $t->[0] ne ')') {
      my $x = ev($t); return undef unless defined $x; push @v, $x;
      last unless @$t && $t->[0] eq ','; shift @$t;
    }
    return undef unless @$t && shift(@$t) eq ')';
    return undef if $k eq 'not' ? @v != 1 : !@v;
    return $k eq 'not' ? !$v[0] : $k eq 'any' ? (grep { $_ } @v) > 0 : !(grep { !$_ } @v);
  }
  return undef unless $plat{$k};
  return $host{$k} ? 1 : 0 unless @$t && $t->[0] eq '=';
  shift @$t; my $s = shift @$t;
  return undef unless defined $s && $s =~ /^"(\d+)"$/;
  return $host{qq{$k="$str[$1]"}} ? 1 : 0;
}
while (/\bcfg\s*!?\s*\(/g) {
  my ($d, $p, $i) = (1, '', pos);
  for (; $i < length && $d; $i++) {
    my $c = substr($_, $i, 1);
    $d++ if $c eq '('; $d-- if $c eq ')';
    $p .= $c if $d;
  }
  my @t = $p =~ /\G\s*([A-Za-z_]\w*|"\d+"|[(),=])/gc;
  my $v = substr($p, pos($p) // 0) =~ /^\s*$/ ? ev(\@t) : undef;
  next if $v && !@t;
  (my $s = $p) =~ s/"(\d+)"/"$str[$1]"/g; $s =~ s/\s+/ /g;
  print "cfg($s)\n";
}
PL
cfg_scan() {
  local hits
  if ! hits="$(HOST_CFG="$HOST_CFG" perl -e "$CFG_SCAN" <"$1")"; then
    echo "FAIL: could not scan $2." >&2; status=1; return
  fi
  [ -n "$hits" ] || return 0
  echo "FAIL: $2 holds a construct that can remove code from this compile:" >&2
  printf '      %s\n' "$hits" >&2
  status=1
}

META="$(cargo metadata --no-deps --format-version 1)"

# name<TAB>manifest_dir<TAB>… for every workspace package.
PKG_TSV="$(printf '%s' "$META" | jq -r '.packages[] | [.name, (.manifest_path | sub("/Cargo.toml$"; ""))] | @tsv')"
[ -n "$PKG_TSV" ] || { echo "FAIL: cargo metadata reported no workspace package." >&2; exit 1; }

while IFS=$'\t' read -r pkg pkgdir; do
  [ -n "$pkg" ] || continue

  # target_name<TAB>src_path_relative_to_package_root
  TGT_TSV="$(printf '%s' "$META" | jq -r --arg p "$pkg" --arg d "$pkgdir/" '
      .packages[] | select(.name == $p)
      | .targets[] | select(.kind[] == "example")
      | [.name, (.src_path | ltrimstr($d))]
      | @tsv
    ')"

  # Every cargo call in this loop reads /dev/null, not the heredoc feeding the loop,
  # so no subprocess can drain the package list and end the loop after one package.
  # Cases `secondbroken` and `secondorphan` pin that every package is checked.
  #
  # Never swallow this exit code: `cargo package --list` fails (101) on a manifest
  # error such as a `readme` naming a missing file, and treating that as "no
  # published examples" would drop the crate from assertion 2 in silence.
  if ! RAW="$(cargo package --list -p "$pkg" --allow-dirty 2>&1 </dev/null)"; then
    # Unconditional. Gating this on the package having targets inverts it: an
    # `autoexamples = false` crate has none, which is exactly the state where a
    # published example file cannot be seen, so silence there is the failure mode
    # this branch exists to remove.
    echo "FAIL: 'cargo package --list -p $pkg' failed, so its published file set is unknown." >&2
    printf '%s\n' "$RAW" >&2
    status=1
  else
    # Every target's source path, one per line, for the path join below.
    SRCS="$(printf '%s' "$TGT_TSV" | cut -f2 | sort -u)"
    # Cargo auto-discovers BOTH `examples/NAME.rs` and `examples/NAME/main.rs`.
    # Measured: moving website.rs to examples/website/main.rs keeps the target and
    # keeps the file published, so a pattern matching only the flat form is blind to
    # a layout that needs no manifest edit at all. Any other file under examples/
    # (examples/support/mod.rs) is a helper module and is not expected to be a target.
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      printf '%s\n' "$SRCS" | grep -qxF -- "$file" && continue
      echo "FAIL: $pkg publishes '$file', which is no example target's source." >&2
      echo "      Nothing compiles it, in CI or for a consumer. Give it an [[example]]" >&2
      echo "      entry, drop 'autoexamples = false', or stop publishing the file." >&2
      status=1
    done <<EOF
$(printf '%s\n' "$RAW" | grep -E '^examples/([^/]+\.rs|[^/]+/main\.rs)$' || true)
EOF
  fi

  # Every .rs file on disk under examples/, published or not, helper modules included.
  if [ -d "$pkgdir/examples" ]; then
    while IFS= read -r file; do
      cfg_scan "$file" "$pkg '${file#"$pkgdir"/}'"
    done < <(find "$pkgdir/examples" -type f -name '*.rs' | sort)
  fi

  [ -n "$TGT_TSV" ] || continue
  while IFS=$'\t' read -r name src; do
    [ -n "$name" ] || continue
    checked=$((checked + 1))
    echo "── $pkg::$name  ($src)"
    case "$src" in /*) srcfile="$src" ;; *) srcfile="$pkgdir/$src" ;; esac
    cfg_scan "$srcfile" "$pkg example '$name'"
    if ! cargo clippy -p "$pkg" --example "$name" -- -D warnings </dev/null; then
      echo "FAIL: $pkg example '$name' does not compile." >&2
      status=1
    fi
  done <<EOF
$TGT_TSV
EOF
done <<EOF
$PKG_TSV
EOF

[ "$checked" -gt 0 ] || { echo "FAIL: no example target was checked; this must not pass vacuously." >&2; exit 1; }

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "Fix the example, or stop publishing a file no target compiles." >&2
else
  echo "OK: $checked example target(s) compile; every published examples/*.rs is a target source."
fi
exit "$status"
