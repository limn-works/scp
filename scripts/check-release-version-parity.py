#!/usr/bin/env python3.12
"""Refuse a release whose project files name a version other than the one asked for.

CRITERION: for the version string an operator hands `.github/workflows/release.yml`,
every project file this repository publishes from names that same version — each
Cargo manifest character for character, and the Python project file in the PEP 440
spelling of it. A file that names a different version publishes a different version:
`.github/workflows/build-matrix.yml` builds the five wheels straight from
`bindings/python/pyproject.toml` and stamps nothing onto them, and step 6b of
release.yml uploads whatever those wheels are named with no `skip-existing`, so a
stale string there either re-uploads a version PyPI already holds — which fails the
upload after the crates, the npm packages, the Maven artifacts and the Apple
XCFramework have already published — or publishes a wheel labelled for one release
inside another.

The three sibling SDKs need no entry here: release.yml writes `env.VERSION` into
`bindings/typescript/package.json`, passes `-PscpVersion` to Gradle, and names
`env.VERSION` in the Swift tag and the XCFramework file name, so their published
version comes from the input rather than from a checked-in string.

Run it two ways:

    scripts/check-release-version-parity.py 0.1.0-beta.2
    scripts/check-release-version-parity.py --pep440 0.1.0-beta.2
    scripts/check-release-version-parity.py --self-test

`--pep440` prints the canonical spelling of one version and checks nothing, so the
step that asks PyPI whether it already holds a release spells the version the way
PyPI names it without repeating the normalization table below.

`--self-test` plants a mismatched version in a fixture tree and proves this script
rejects it, before release.yml trusts it on the real tree.
"""

from __future__ import annotations

import re
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Every Cargo manifest whose version an operator bumps by hand. release.yml's
# "Create version tags" step tags seventeen crates; these three are the ones the
# loop this script replaced read, because the other fourteen inherit their version
# from the workspace.
CARGO_PROJECT_FILES = (
    "crates/scp-core/Cargo.toml",
    "crates/scp-protocol/Cargo.toml",
    "crates/scp-runtime/Cargo.toml",
)

# The one project file whose checked-in version decides what a published wheel is
# called.
PEP440_PROJECT_FILES = ("bindings/python/pyproject.toml",)

# PEP 440 §Normalization, restricted to a release segment and an optional
# pre-release segment. Nothing else parses: an epoch, a post-release, a dev
# release and a local version all raise, so this script never compares two
# spellings it did not understand.
_PEP440 = re.compile(
    r"^v?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<label>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<number>[0-9]+)?)?$"
)

# PEP 440 §Pre-release spelling: the spellings PEP 440 collapses onto `a`, `b`
# and `rc`.
_LABELS = {
    "alpha": "a",
    "a": "a",
    "beta": "b",
    "b": "b",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
    "rc": "rc",
}


class Unparsed(ValueError):
    """The version string uses a PEP 440 segment this script does not handle."""


def normalize_pep440(version: str) -> str:
    """Return the PEP 440 canonical spelling of `version`.

    Raises Unparsed when the string carries an epoch, a post-release segment, a
    dev-release segment or a local version, so a shape this script cannot compare
    fails the release instead of comparing equal by accident.
    """
    match = _PEP440.match(version.strip())
    if match is None:
        raise Unparsed(
            f"{version!r} is not a release or pre-release version this script "
            f"compares; it handles N(.N)* with an optional a/b/rc segment, and "
            f"handles no epoch, post-release, dev-release or local version"
        )
    canonical = match.group("release")
    if match.group("label"):
        canonical += _LABELS[match.group("label")] + (match.group("number") or "0")
    return canonical


def cargo_version(path: Path) -> str:
    """Return the `[package] version` a Cargo manifest declares."""
    return str(tomllib.loads(path.read_text()).get("package", {}).get("version", ""))


def project_version(path: Path) -> str:
    """Return the `[project] version` a PEP 621 project file declares."""
    return str(tomllib.loads(path.read_text()).get("project", {}).get("version", ""))


def failures(root: Path, release_version: str) -> list[str]:
    """Return one message per project file that names another version."""
    found: list[str] = []
    for relative in CARGO_PROJECT_FILES:
        path = root / relative
        if not path.is_file():
            found.append(f"{relative} does not exist")
            continue
        declared = cargo_version(path)
        if declared != release_version:
            found.append(
                f"{relative} declares version {declared!r}, and the release asked "
                f"for {release_version!r}; edit that manifest before releasing"
            )
    for relative in PEP440_PROJECT_FILES:
        path = root / relative
        if not path.is_file():
            found.append(f"{relative} does not exist")
            continue
        declared = project_version(path)
        try:
            declared_canonical = normalize_pep440(declared)
            wanted_canonical = normalize_pep440(release_version)
        except Unparsed as error:
            found.append(f"{relative}: {error}")
            continue
        if declared_canonical != wanted_canonical:
            found.append(
                f"{relative} declares version {declared!r}, whose PEP 440 spelling "
                f"is {declared_canonical!r}, and the release asked for "
                f"{release_version!r}, whose PEP 440 spelling is "
                f"{wanted_canonical!r}. build-matrix.yml builds the wheels straight "
                f"from that file and stamps nothing onto them, so the publish would "
                f"upload a wheel named for {declared_canonical!r}"
            )
    return found


def write_fixture(root: Path, python_version: str, core_version: str) -> None:
    """Write the four project files this script reads into `root`."""
    for relative in CARGO_PROJECT_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'[package]\nname = "x"\nversion = "{core_version}"\n')
    project = root / PEP440_PROJECT_FILES[0]
    project.parent.mkdir(parents=True, exist_ok=True)
    project.write_text(
        f'[project]\nname = "scp-python"\nversion = "{python_version}"\n'
    )


def self_test() -> int:
    """Prove this script accepts an agreeing tree and rejects each disagreement."""
    passed = True

    def expect(label: str, ok: bool, detail: str = "") -> None:
        nonlocal passed
        print(f"{'PASS' if ok else 'FAIL'} — {label}")
        if not ok:
            passed = False
            if detail:
                print(f"       {detail}")

    for raw, canonical in (
        ("0.1.0-beta.2", "0.1.0b2"),
        ("0.1.0b2", "0.1.0b2"),
        ("0.1.0.beta.2", "0.1.0b2"),
        ("0.1.0-alpha1", "0.1.0a1"),
        ("0.1.0-rc", "0.1.0rc0"),
        ("0.1.0c1", "0.1.0rc1"),
        ("0.1.0-preview.3", "0.1.0rc3"),
        ("1.2.3", "1.2.3"),
    ):
        try:
            got = normalize_pep440(raw)
        except Unparsed as error:
            expect(f"{raw!r} normalizes to {canonical!r}", False, str(error))
            continue
        expect(f"{raw!r} normalizes to {canonical!r}", got == canonical, f"got {got!r}")

    for raw in ("0.1.0.post1", "1!1.0", "0.1.0.dev3", "0.1.0+local", "beta"):
        rejected = False
        try:
            normalize_pep440(raw)
        except Unparsed:
            rejected = True
        expect(f"{raw!r} raises rather than comparing equal by accident", rejected)

    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)

        write_fixture(root, python_version="0.1.0b2", core_version="0.1.0-beta.2")
        found = failures(root, "0.1.0-beta.2")
        expect("an agreeing tree reports nothing", found == [], "; ".join(found))

        # The defect this script exists to catch: a Python project file left at the
        # version a previous publish used.
        write_fixture(root, python_version="0.1.0b3", core_version="0.1.0-beta.2")
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a stale Python version is rejected",
            any(PEP440_PROJECT_FILES[0] in message for message in found),
            f"reported {found}",
        )

        write_fixture(root, python_version="0.1.0b2", core_version="0.1.0-beta.1")
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a stale Cargo version is rejected",
            any(CARGO_PROJECT_FILES[0] in message for message in found),
            f"reported {found}",
        )

        (root / PEP440_PROJECT_FILES[0]).unlink()
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a missing project file is rejected",
            any("does not exist" in message for message in found),
            f"reported {found}",
        )

    expect(
        "--pep440 prints the canonical spelling and exits 0",
        main(["", "--pep440", "0.1.0-beta.2"]) == 0,
    )
    expect(
        "--pep440 rejects a spelling this script does not handle",
        main(["", "--pep440", "0.1.0.post1"]) == 1,
    )

    print("self-test passed" if passed else "self-test FAILED")
    return 0 if passed else 1


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--pep440":
        try:
            print(normalize_pep440(argv[2]))
        except Unparsed as error:
            print(f"::error::{error}")
            return 1
        return 0
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--self-test":
        return self_test()
    release_version = argv[1]
    found = failures(REPO, release_version)
    for message in found:
        print(f"::error::{message}")
    if found:
        print(
            f"Release version {release_version!r} does not match every project file. "
            f"Bump the files named above, or run the release with the version they "
            f"already name."
        )
        return 1
    print(f"Every project file names release version {release_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
