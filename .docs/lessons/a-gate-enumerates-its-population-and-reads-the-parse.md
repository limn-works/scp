# A Gate Enumerates the Population It Quantifies Over, and Reads the Parse Rather Than the Text

A mechanical check states a criterion over a population — every container build, every
paths-filtered workflow, every root-level file. Two things then decide whether the check
holds: how it finds the members of that population, and how it reads each member. These
rules come from `scripts/check-toolchain-wiring.sh` and the gate it replaced.

## Finding the population

- **A check that names the things which must be present fails silently on the thing nobody
  added.** A check that enumerates the population and requires each member to be classified
  cannot fail that way. The gate here enumerates every root-level file in the git tree, and
  every cargo configuration file at any depth, and requires each one to be routed by a
  paths filter or declared in a list of files no compile reads. A file added at the root
  later belongs to neither list, so the gate fails until someone routes it or declares that
  no compile reads it.
- **A constant naming one member is not an enumeration.** The earlier gate opened
  `CI_WORKFLOW=".github/workflows/ci.yml"` and read that file alone, while two workflows in
  this repository guard jobs with a `dorny/paths-filter` step. The second one violated the
  gate's own criterion, and the gate printed `OK`. The gate now derives its list from the
  tree: each tracked file under `.github/workflows/` whose extension GitHub Actions runs
  and that declares a paths-filter step.
- **Derive the enumeration from the criterion, not from the examples in front of you.** The
  first root-file enumeration kept only paths holding no slash, which is a property of
  where the four files that prompted it happened to sit, not a property the criterion
  names. `.cargo/config.toml` satisfies the criterion and holds a slash: cargo reads it out
  of every ancestor of the directory a command runs in, no filter listed it, and a pull
  request deleting its `[target.wasm32-unknown-unknown]` stanza skipped every job while the
  aggregator reported success.
- **When a check asks whether a build system reads a file, read what the build system
  reads — a path, a manifest entry, a workflow input — not a keyword the file's contents
  carry.** A keyword search answers "does this text mention a container build", and a
  document that explains one mentions it exactly as loudly as a Dockerfile does. Searching
  the tree for a line-initial `FROM` naming a rust image made every architecture record and
  runbook that pasted a Dockerfile's first line into a fenced block fail a required check,
  and left that author two ways out: paste build-time shell into the prose, or reword the
  sentence so `FROM` no longer opened a line, which also hides a real container build whose
  author typed a leading space. Reading the path also closes a gap the text search had: a
  `Dockerfile` writing `  from rust:slim-bookworm`, indented and lowercase, which Docker
  accepts and the search never matched. The case
  `container-indents-a-lowercase-from` in `scripts/tests/toolchain-wiring/run-tests.sh`
  holds it.
- **Keep the tree-wide search as a classification check rather than as the discovery
  rule.** A file that neither path rule covers, and that holds a `FROM` line naming a rust
  image, must appear in a list declaring it as prose that quotes a build. The gate fails on
  a file that appears in neither list, so a container build kept under an unconventional
  name is still caught, and its author states which of the two the file is.

## Reading each member

- **When a file has a grammar and a parser for it, read the parse, not the text.** Asking
  whether `.mise.toml` gives its `tools` table a `rust` key with
  `grep -qE '^[[:space:]]*"?rust"?[[:space:]]*='` reads four of the eight spellings TOML
  offers for that key, and misses `[tools.rust]`, `[tools."rust"]`, a dotted top-level
  `tools.rust =`, and `rust.version =` under `[tools]`. Parsing with `tomllib` and asking
  whether the table `tools` holds the key `rust` answers yes for all eight, and for a ninth
  nobody has written, because TOML's grammar decides the answer rather than a pattern. A
  document the parser rejects fails the check rather than passing over it.
- **`grep -F` with a multi-line pattern is a line-membership test, not a block
  comparison.** grep splits a pattern holding newlines into one pattern per line and
  matches when any single one matches, so `grep -qzF` accepts a file holding one line of a
  three-line block and accepts the block in reverse order. Measured on GNU grep 3.12, BSD
  grep 2.6.0-FreeBSD, and ugrep 7.8.4; `-z` changes the input record separator and does not
  change how grep splits the pattern. Read the file into a variable and compare with bash's
  `[[ $text == *"$block"* ]]`, which is a literal substring test over the whole file.
- **Enumerating the spellings a grammar admits does not terminate; enumerating the
  permitted items does.** Three rounds of pattern-matching Docker's `FROM` syntax each drew
  a reviewer naming one more legal spelling — an indented keyword, a lowercase one, an
  untagged `FROM rust`, a registry-qualified image, a second stage naming no Debian
  release. CLAUDE.md names the review-pass count as the signal that an approach is the
  wrong one, and the third round finding a fourth spelling was already that evidence.

## See also

- `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` — the same closed
  whitelist rule applied to a source-text gate over a type definition, and the prior
  question of whether to build the check at all.
- `.docs/lessons/route-a-changed-file-to-every-lane-it-decides.md` — the routing criterion
  this gate enforces.
