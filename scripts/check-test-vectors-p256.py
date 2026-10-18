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
3. Every hexadecimal string literal of 32 or more characters in the Rust vector
   tests (`RUST_VECTOR_TESTS`) appears in the generator's output, so a Rust test
   cannot assert a byte string the generator no longer produces.

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

ROOT = pathlib.Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "scripts" / "gen-test-vectors-p256.py"
SPEC = ROOT / ".docs" / "specs" / "25-test-vectors.md"
RUST_VECTOR_TESTS = (
    ROOT / "crates" / "scp-runtime" / "tests" / "test_vectors.rs",
    ROOT / "crates" / "scp-event-log" / "tests" / "test_vectors.rs",
)

SECTION_RE = re.compile(r"^--- (.*) ---$")
HEX_LINE_RE = re.compile(r"^(\S+) = 0x([0-9a-fA-F]+)$")
RUST_HEX_LITERAL_RE = re.compile(r'"([0-9a-fA-F]{32,})"')
SPEC_HEX_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{16,})\s*$")
SPEC_HEX_TOKEN_RE = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{32,})(?![0-9A-Za-z])")
SPEC_HEADING_RE = re.compile(r"^#{2,} ")
# Vector headings whose bytes spec 25 says no script generates.
NOT_GENERATED = ("### Vector 58:",)
WHITESPACE_RE = re.compile(r"\s")
EMITTED_HEX_RE = re.compile(r"^(vector_(?:41|48)\.[\w.]+) = 0x([0-9a-fA-F]+)$", re.MULTILINE)
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
    literal_count = 0
    for path, source in rust_tests.items():
        for literal in RUST_HEX_LITERAL_RE.findall(source):
            literal_count += 1
            if literal.lower() not in flat_generated:
                found.append(
                    f"{path} asserts {literal[:48]}..., which the generator does not emit"
                )
    if literal_count == 0:
        found.append(
            "the Rust vector tests hold no hex literal of 32 or more characters"
        )
    return found


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
        f"{name} = 0x{value}, but SHA-256(\"scp:did:\" || vector_41.identifier) = 0x{want}"
        for name, value in present
        if value != want
    )
    return found


def load_rust_tests() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
        for path in RUST_VECTOR_TESTS
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
        if sep and BRIDGE_TARGET_RE.match(name) and value.lower() != ABSENT_BRIDGE_TARGET:
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
    path, source = next(iter(rust_tests.items()))
    literal = RUST_HEX_LITERAL_RE.findall(source)[0]
    planted_literal = flip_hex_digit(literal, 0)
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
