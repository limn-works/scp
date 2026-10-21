#!/usr/bin/env python3.12
"""Fails when spec 25 or a Rust vector test drifts from the vector generator.

`.docs/specs/25-test-vectors.md` §25 states that `scripts/gen-test-vectors-p256.py`
produces every keyed byte the section prints. This check runs the generator and
enforces two inclusions:

1. Every hexadecimal value the generator emits under a `--- §25... ---` section
   appears in spec 25. The comparison removes whitespace and ignores case,
   because the spec wraps long values across lines. Sections without a `§25`
   heading hold values another file owns (the scp-client-wasm cross-target
   golden), so this check does not read them.
2. Every hexadecimal run of 32 or more characters that spec 25 prints (lines of
   bare hexadecimal joined into one run, and inline tokens) appears in the
   generator's output. Inclusion 1 alone misses a changed byte in a value the
   spec also prints inside a longer preimage; this direction catches it. The
   vectors in `NOT_GENERATED` are exempt, because spec 25 states that no script
   produces their bytes.
3. Every hexadecimal string literal of 32 or more characters in a Rust vector
   file appears in the generator's output, so a Rust test cannot assert a byte
   string the generator no longer produces. Spec 25 printing a value is not
   enough: check 2 exempts `NOT_GENERATED` vectors and skips `0x`-prefixed
   tokens, so a value the spec prints can still be one no generator emits. A Rust vector file is
   any tracked `.rs` file that cites spec 25 (`§25`, `25-test-vectors` or
   `spec 25`), found by `git ls-files`, so a new or renamed file joins the scan
   without an edit here. Adjacent pieces of one `concat!` and the lines of one
   backslash-continued string join into one literal first. A literal from another
   source (an RFC vector, a curve constant, a golden this check does not own)
   in such a file is declared in `FOREIGN` under its file with that source.
   Any other tracked `.rs` file that holds a value spec 25 prints or the
   generator emits under a `§25` section must cite spec 25, so that the scan
   follows it; `WELL_KNOWN` hashes are exempt.

4. Vector 48's bridge entry signs the identity routing ID of
   `10-infrastructure-and-self-hosting.md` §10.12.4.1 over Vector 41's
   identifier: this check recomputes `SHA-256("scp:did:" || identifier)` from
   the `vector_41.identifier` the generator emits and compares it with every
   `vector_48.entry_N.bridgeTarget` that is not the absent value
   `SHA-256(0x00)`. Inclusions 1 and 2 compare the generator with the spec and
   so pass a value the generator itself computed wrongly, as it did when it
   hashed the identifier before Vector 41 had set it.

The check fails when either inclusion finds no candidate at all, so an empty
generator run or a renamed test file cannot pass it.

Usage, from the repository root:

    python3.12 scripts/check-test-vectors-p256.py              # real scan
    python3.12 scripts/check-test-vectors-p256.py --self-test  # must-fail cases
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "scripts" / "gen-test-vectors-p256.py"
SPEC = ROOT / ".docs" / "specs" / "25-test-vectors.md"
CITES_SPEC_25_RE = re.compile(r"§25\b|25-test-vectors|[Ss]pec 25\b")
# Hashes a file can hold for reasons of its own that spec 25 also prints.
WELL_KNOWN = frozenset(
    hashlib.sha256(data).hexdigest() for data in (b"", b"hello world")
)
# Hex literals in Rust vector files that belong to another source, keyed by
# file, as the first 16 hex digits of SHA-256 over the lowercase literal.
FOREIGN: dict[str, tuple[str, frozenset[str]]] = {
    "crates/scp-client-wasm/tests/cross_target_determinism_kat.rs": (
        "cross-target goldens: leaf hashes, Merkle root, MLS, relay, pseudonym",
        frozenset(
            {
                "00e7c4577296bec3",
                "07a396c4d0b28c65",
                "1c95cfdc55ee9285",
                "4c2947a545bcc59e",
                "5b7633116204755d",
                "851b4a1b9770af45",
                "8c32ff1934a418a3",
                "a74b61701dcecfb1",
                "dace0c2cb9e1cc59",
                "dd3b620445da43ab",
                "f671aa64de5b8371",
                "fb2fbe4336c92309",
            }
        ),
    ),
    "crates/scp-client-wasm/tests/pseudonym_cross_target_kat.rs": (
        "Vector 58's pseudonym preimages, which spec 25 states no script generates",
        frozenset({"4d61919cc6c61257", "66d11a29cd90b328"}),
    ),
    "crates/scp-crypto/src/p256.rs": (
        "RFC 6979 A.2.5, RFC 7515 A.3, the ECDH vector, P-256 constants",
        frozenset(
            {
                "4d37a4137ed3b110",
                "52999df7f5debdae",
                "5615a2afcabb5928",
                "785dffa23ca4f1a3",
                "79e7728452d0a1cf",
                "7ae817c4e4ae17ae",
                "7bbdeccd628cab5d",
                "8cd3046264c9ea41",
                "b0d0fd417639c6ea",
                "be116a583c659993",
                "c5ab11629cee7222",
                "cc1e6dfb80a23a86",
                "d6018fc8bcfcd1ed",
                "d75199d770465e0b",
                "d89408daa5c1ef4c",
                "e64ce9e6ab8192d4",
                "e845966ffc323b76",
                "f227f5f941090edc",
                "fc603157674ea711",
                "ff8a23c4144f6b47",
            }
        ),
    ),
    "crates/scp-ffi/src/custody.rs": (
        "the compressed point 2G",
        frozenset({"1535d448d15d9886"}),
    ),
    "crates/scp-ffi/uniffi/src/bridge.rs": (
        "a 16-byte saga nonce fixture",
        frozenset({"5947d7c33d783f94"}),
    ),
    "crates/scp-kel/tests/kel/signature.rs": (
        "the P-256 group order n",
        frozenset({"f227f5f941090edc"}),
    ),
    "crates/scp-mls/src/keypackage_attestation.rs": (
        "the P-256 field prime p",
        frozenset({"8cd3046264c9ea41"}),
    ),
    "crates/scp-protocol/src/context/pseudonym.rs": (
        "Vector 58's pseudonym preimages, which spec 25 states no script generates",
        frozenset({"4d61919cc6c61257", "66d11a29cd90b328"}),
    ),
    "crates/scp-protocol/src/crypto/hpke/p256.rs": (
        "RFC 9180 A.3 and the P-256 group order n",
        frozenset(
            {
                "267f03bd2cd26d0a",
                "342485f35b0e7a26",
                "3d5308edf01c7362",
                "46607c1580e9bbcf",
                "468c0d83dfa390d5",
                "50d32e6fd783cceb",
                "590bdbf12243f74f",
                "5fcca0a2b6895dde",
                "6919271fd8b8d77e",
                "756372620e6c57c0",
                "7881be852e26013a",
                "86df2919627c8e49",
                "a31e1fef89895909",
                "b28eff17b08a157c",
                "b6743ce8bc7ba88a",
                "bb195b09e917505d",
                "c098f950edc195ca",
                "c9ac36e89b302247",
                "cb4775b45f1e1436",
                "d756c38bdf721bc3",
                "e2142ec91e0892ec",
                "e66b69c9fd7534b0",
                "f227f5f941090edc",
            }
        ),
    ),
    "crates/scp-protocol/src/trust/capability_definition.rs": (
        "the protocol-row digests of the 07-trust-validation-and-capabilities.md table",
        frozenset({"79c22d08d2b21756", "a0a19dc74ad3f614"}),
    ),
    "crates/scp-protocol/src/trust/custody_violation.rs": (
        "custody-violation signing vectors; §25.25 records them deleted",
        frozenset(
            {
                "13c257bcdd964579",
                "1f091ad3bbbc14b1",
                "21a346bc2ddb011a",
                "2f6c34b00060e519",
                "8fc2729503f0f3a8",
                "97637c7bce05663f",
                "b35121efde20b8d2",
            }
        ),
    ),
    "crates/scp-runtime/src/context/pseudonym_rotation_runtime_tests.rs": (
        "Vector 58's pseudonym preimages, which spec 25 states no script generates",
        frozenset({"4d61919cc6c61257", "66d11a29cd90b328"}),
    ),
    "crates/scp-runtime/src/crypto/access_keys/wire.rs": (
        "the access-key request JSON golden",
        frozenset({"36a9c4c54034fcef"}),
    ),
}

SECTION_RE = re.compile(r"^--- (.*) ---$")
HEX_LINE_RE = re.compile(r"^(\S+) = 0x([0-9a-fA-F]+)$")
RUST_HEX_STRING_RE = re.compile(r'"((?:[0-9a-fA-F]|\\\n\s*)+)"')
# Whitespace is consumed in one place per piece: after `concat!(`, then after
# each piece and after its comma, which separates the two runs. No two adjacent
# iterations can split the same characters two ways, so a scan that fails, such
# as an unclosed `concat!(` over many pieces, stays linear.
RUST_CONCAT_RE = re.compile(
    r'concat!\(\s*((?:(?:"[0-9a-fA-F]*"|//[^\n]*\n)\s*(?:,\s*)?)+)\)'
)
RUST_CONCAT_PIECE_RE = re.compile(r'"([0-9a-fA-F]*)"')
RUST_CONTINUATION_RE = re.compile(r"\\\n\s*")
SPEC_HEX_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{16,})\s*$")
SPEC_HEX_TOKEN_RE = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{32,})(?![0-9A-Za-z])")
SPEC_HEADING_RE = re.compile(r"^#{2,} ")
# Vector headings whose bytes spec 25 says no script generates.
NOT_GENERATED = ("### Vector 58:",)
WHITESPACE_RE = re.compile(r"\s")
EMITTED_HEX_RE = re.compile(
    r"^(vector_(?:41|48)\.[\w.]+) = 0x([0-9a-fA-F]+)$", re.MULTILINE
)
BRIDGE_TARGET_RE = re.compile(r"^vector_48\.entry_\d+\.bridgeTarget$")
ABSENT_BRIDGE_TARGET = hashlib.sha256(b"\x00").hexdigest()


def run_generator() -> str:
    """Returns the generator's standard output, or raises when it fails."""
    done = subprocess.run(
        [sys.executable, str(GENERATOR)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise SystemExit(f"{GENERATOR.name} exited {done.returncode}:\n{done.stderr}")
    return done.stdout


def spec_values(generated: str) -> list[tuple[str, str]]:
    """Returns (name, lowercase hex) for each hex value under a §25 section."""
    values = []
    in_spec_section = False
    for line in generated.splitlines():
        section = SECTION_RE.match(line)
        if section:
            in_spec_section = section.group(1).startswith("§25")
            continue
        value = HEX_LINE_RE.match(line)
        if in_spec_section and value:
            values.append((value.group(1), value.group(2).lower()))
    return values


def spec_hex_runs(spec: str) -> list[tuple[int, str]]:
    """Returns (line, hex run) for each long hex run spec 25 prints outside an exempt vector."""
    runs = []
    pending: list[str] = []
    pending_line = 0
    exempt = False
    for number, line in enumerate(spec.splitlines(), start=1):
        if SPEC_HEADING_RE.match(line):
            exempt = line.startswith(NOT_GENERATED)
        whole = SPEC_HEX_LINE_RE.match(line)
        if whole:
            if not pending:
                pending_line = number
            pending.append(whole.group(1))
            continue
        if pending:
            if not exempt:
                runs.append((pending_line, "".join(pending)))
            pending = []
        if not exempt:
            runs.extend((number, token) for token in SPEC_HEX_TOKEN_RE.findall(line))
    if pending and not exempt:
        runs.append((pending_line, "".join(pending)))
    return [(number, run) for number, run in runs if len(run) >= 32]


def problems(generated: str, spec: str, rust_tests: dict[str, str]) -> list[str]:
    """Returns one line per value that breaks either inclusion."""
    found = []
    values = spec_values(generated)
    if not values:
        found.append("the generator emitted no hex value under a §25 section")
    flat_spec = WHITESPACE_RE.sub("", spec).lower()
    for name, value in values:
        if value not in flat_spec:
            found.append(f"spec 25 does not print {name} = 0x{value}")
    flat_generated = WHITESPACE_RE.sub("", generated).lower()
    for heading in NOT_GENERATED:
        if not any(line.startswith(heading) for line in spec.splitlines()):
            found.append(f"spec 25 has no heading {heading!r}; remove its exemption")
    runs = spec_hex_runs(spec)
    if not runs:
        found.append("spec 25 prints no hex run of 32 or more characters")
    for number, run in runs:
        if run.lower() not in flat_generated:
            found.append(
                f"spec 25 line {number} prints {run[:48]}..., which the generator does not emit"
            )
    vector_files = rust_vector_files(rust_tests)
    literal_count = 0
    for path, source in sorted(vector_files.items()):
        source_name, declared = FOREIGN.get(path, ("", frozenset()))
        used = set()
        for line, literal in rust_hex_literals(source):
            literal_count += 1
            if literal in flat_generated:
                continue
            key = foreign_key(literal)
            if key in declared:
                used.add(key)
                continue
            found.append(
                f"{path}:{line} asserts {literal[:48]}..., which the generator does "
                f"not emit; if another source owns it, add {key} to "
                f"FOREIGN[{path!r}] with that source"
            )
        found.extend(
            f"FOREIGN[{path!r}] ({source_name}) lists {key}, which the file no longer holds"
            for key in sorted(declared - used)
        )
    found.extend(
        f"FOREIGN lists {path}, which is not a tracked Rust file citing spec 25"
        for path in sorted(FOREIGN.keys() - vector_files.keys())
    )
    if literal_count == 0:
        found.append(
            "the Rust vector files hold no hex literal of 32 or more characters"
        )
    printed = {value for _, value in values} | {run.lower() for _, run in runs}
    for path, source in sorted(rust_tests.items()):
        if path in vector_files:
            continue
        found.extend(
            f"{path}:{line} holds the spec 25 value {literal[:48]}... but cites no "
            "spec 25 section, so check 3 does not scan it"
            for line, literal in rust_hex_literals(source)
            if literal in printed and literal not in WELL_KNOWN
        )
    return found


def rust_vector_files(rust_tests: dict[str, str]) -> dict[str, str]:
    """Returns the Rust files that cite spec 25, which check 3 scans."""
    return {
        path: source
        for path, source in rust_tests.items()
        if CITES_SPEC_25_RE.search(source)
    }


def rust_hex_literals(source: str) -> list[tuple[int, str]]:
    """Returns (line, lowercase hex) for each hex string literal of 32 or more
    characters, joining `\\`-continued lines and the pieces of one `concat!`."""
    found = [
        (match.start(), RUST_CONTINUATION_RE.sub("", match.group(1)))
        for match in RUST_HEX_STRING_RE.finditer(source)
    ]
    found += [
        (match.start(), "".join(RUST_CONCAT_PIECE_RE.findall(match.group(1))))
        for match in RUST_CONCAT_RE.finditer(source)
    ]
    return [
        (source.count("\n", 0, at) + 1, literal.lower())
        for at, literal in sorted(found)
        if len(literal) >= 32
    ]


def foreign_key(literal: str) -> str:
    return hashlib.sha256(literal.encode()).hexdigest()[:16]


def bridge_target_problems(generated: str) -> list[str]:
    """Recomputes Vector 48's present bridgeTarget from Vector 41's identifier."""
    emitted = {name: value.lower() for name, value in EMITTED_HEX_RE.findall(generated)}
    identifier = emitted.get("vector_41.identifier")
    if identifier is None or len(identifier) != 64:
        return ["the generator emitted no 32-byte vector_41.identifier"]
    found = []
    if emitted.get("vector_48.identifier") != identifier:
        found.append("vector_48.identifier differs from vector_41.identifier")
    want = hashlib.sha256(b"scp:did:" + bytes.fromhex(identifier)).hexdigest()
    present = [
        (name, value)
        for name, value in emitted.items()
        if BRIDGE_TARGET_RE.match(name) and value != ABSENT_BRIDGE_TARGET
    ]
    if not present:
        found.append("vector_48 emits no entry with a present bridgeTarget")
    found.extend(
        f'{name} = 0x{value}, but SHA-256("scp:did:" || vector_41.identifier) = 0x{want}'
        for name, value in present
        if value != want
    )
    return found


def load_rust_tests() -> dict[str, str]:
    """Returns every tracked Rust file by repository path."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.rs"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return {
        path: (ROOT / path).read_text(encoding="utf-8", errors="replace")
        for path in listed.split("\0")
        if path
    }


def flip_hex_digit(text: str, at: int) -> str:
    """Returns `text` with the hex digit at `at` replaced by a different digit."""
    return text[:at] + ("0" if text[at] not in "0" else "1") + text[at + 1 :]


def plant_in_spec_line(spec: str, number: int, from_end: bool) -> str:
    """Changes one hex digit of the hex run that starts on spec line `number`."""
    lines = spec.split("\n")
    line = lines[number - 1]
    run = SPEC_HEX_TOKEN_RE.search(line) or SPEC_HEX_LINE_RE.match(line)
    assert run is not None, f"spec line {number} holds no hex run"
    group = 1
    at = run.end(group) - 1 if from_end else run.start(group)
    lines[number - 1] = flip_hex_digit(line, at)
    return "\n".join(lines)


def plant_import_time_bridge_target(generated: str) -> str:
    """Replaces each present Vector 48 bridgeTarget with SHA-256("scp:did:"),
    the value the generator emitted while it hashed INCEPTION_IDENTIFIER at
    import, before Vector 41 set it."""
    wrong = hashlib.sha256(b"scp:did:").hexdigest()
    lines = []
    for line in generated.splitlines():
        name, sep, value = line.partition(" = 0x")
        if (
            sep
            and BRIDGE_TARGET_RE.match(name)
            and value.lower() != ABSENT_BRIDGE_TARGET
        ):
            line = f"{name} = 0x{wrong}"
        lines.append(line)
    return "\n".join(lines)


def self_test(generated: str) -> int:
    """Plants one changed digit per case and requires a report that names the plant."""
    spec = SPEC.read_text(encoding="utf-8")
    rust_tests = load_rust_tests()
    if problems(generated, spec, rust_tests) or bridge_target_problems(generated):
        print("self-test: the unmodified tree must pass first", file=sys.stderr)
        return 1
    runs = spec_hex_runs(spec)
    first_line, _ = runs[0]
    last_line, _ = runs[-1]
    path = "crates/scp-runtime/tests/test_vectors.rs"
    source = rust_tests[path]
    _, literal = rust_hex_literals(source)[0]
    planted_literal = flip_hex_digit(literal, 0)
    # A file no list names: it cites spec 25 and asserts a drifted value.
    new_path = "crates/scp-new/tests/new_vectors.rs"
    new_file = f'// spec 25 Vector 1\nconst V: &str = "{planted_literal}";\n'
    # The last `concat!` piece of Vector 20's preimage is shorter than 32
    # characters, so only the joined literal can catch a change to it.
    kc_path = "crates/scp-protocol/src/crypto/key_continuity.rs"
    kc_source = rust_tests[kc_path]
    assert kc_source.count('"800512",') == 1, "Vector 20's last concat! piece moved"
    uncited = f'const V: &str = "{literal}";\n'
    # An unclosed `concat!(` over many empty pieces: a regex whose pieces can
    # share whitespace two ways backtracks exponentially on it.
    started = time.monotonic()
    rust_hex_literals("concat!(" + ' ""' * 5000)
    unclosed_concat_seconds = time.monotonic() - started
    # Two values spec 25 prints that the generator does not emit, each of a
    # kind check 2 lets through: Vector 58's preimage sits under a
    # NOT_GENERATED heading, and Vector 27's pseudonym_key is `0x`-prefixed,
    # which SPEC_HEX_TOKEN_RE skips. A Rust literal of either fails unless
    # FOREIGN declares it in its file.
    flat_generated = WHITESPACE_RE.sub("", generated).lower()
    flat_spec = WHITESPACE_RE.sub("", spec).lower()
    pseudonym_path = "crates/scp-protocol/src/context/pseudonym.rs"
    not_generated = [
        value
        for _, value in rust_hex_literals(rust_tests[pseudonym_path])
        if value not in flat_generated
    ]
    assert not_generated and all(v in flat_spec for v in not_generated), (
        "pseudonym.rs no longer holds a Vector 58 value spec 25 prints"
    )
    vector_27_key = "746573742d70736575646f6e796d2d6b6579"
    assert f"0x{vector_27_key}" in spec and vector_27_key not in flat_generated, (
        "Vector 27's pseudonym_key moved or is now generated"
    )
    cases = {
        f"the first digit of the spec 25 run at line {first_line}": (
            problems(
                generated, plant_in_spec_line(spec, first_line, False), rust_tests
            ),
            f"line {first_line} ",
        ),
        f"the last digit of the spec 25 run at line {last_line}": (
            problems(generated, plant_in_spec_line(spec, last_line, True), rust_tests),
            f"line {last_line} ",
        ),
        "a changed digit in a Rust vector test literal": (
            problems(
                generated,
                spec,
                {**rust_tests, path: source.replace(literal, planted_literal, 1)},
            ),
            planted_literal[:48],
        ),
        "a drifted literal in a new file that cites spec 25": (
            problems(generated, spec, {**rust_tests, new_path: new_file}),
            f"{new_path}:2 ",
        ),
        "a changed digit in the last concat! piece of Vector 20's preimage": (
            problems(
                generated,
                spec,
                {**rust_tests, kc_path: kc_source.replace('"800512",', '"800513",')},
            ),
            f"{kc_path}:",
        ),
        "an undeclared Vector 58 value in a file that cites spec 25": (
            problems(
                generated,
                spec,
                {
                    **rust_tests,
                    new_path: f'// spec 25 Vector 58\nconst V: &str = "{not_generated[0]}";\n',
                },
            ),
            f"{new_path}:2 ",
        ),
        "an undeclared 0x-prefixed spec 25 value in a file that cites spec 25": (
            problems(
                generated,
                spec,
                {
                    **rust_tests,
                    new_path: f'// spec 25 Vector 27\nconst V: &str = "{vector_27_key}";\n',
                },
            ),
            f"{new_path}:2 ",
        ),
        "a spec 25 value in a file that cites no spec 25 section": (
            problems(generated, spec, {**rust_tests, new_path: uncited}),
            "cites no spec 25 section",
        ),
        "an unclosed concat! of 5,000 pieces scanned in under one second": (
            [f"scanned in {unclosed_concat_seconds:.3f}s"]
            if unclosed_concat_seconds < 1.0
            else [],
            "scanned in ",
        ),
        "an empty generator run": (
            problems("", spec, rust_tests),
            "no hex value under a §25 section",
        ),
        "a Vector 48 bridgeTarget hashed over an empty identifier": (
            bridge_target_problems(plant_import_time_bridge_target(generated)),
            "vector_48.entry_",
        ),
    }
    missed = [
        name
        for name, (found, marker) in cases.items()
        if not any(marker in line for line in found)
    ]
    for name in missed:
        print(f"self-test: the check missed {name}", file=sys.stderr)
    if not missed:
        print(f"self-test: the check caught all {len(cases)} planted cases")
    return 1 if missed else 0


def main(argv: list[str]) -> int:
    generated = run_generator()
    if argv[1:] == ["--self-test"]:
        return self_test(generated)
    if argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    found = problems(generated, SPEC.read_text(encoding="utf-8"), load_rust_tests())
    found += bridge_target_problems(generated)
    for line in found:
        print(line, file=sys.stderr)
    if found:
        print(
            f"{len(found)} test-vector mismatches; regenerate with "
            "`python3.12 scripts/gen-test-vectors-p256.py`",
            file=sys.stderr,
        )
        return 1
    print(
        f"test vectors match: {len(spec_values(generated))} generated values in spec 25"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
