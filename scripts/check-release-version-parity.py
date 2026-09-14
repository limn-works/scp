#!/usr/bin/env python3.12
"""Refuse a release whose project files name a version other than the one asked for.

CRITERION: for the version string an operator hands `.github/workflows/release.yml`,
every project file this repository publishes from names that same version — each
publishable Cargo manifest character for character, and the Python project file in
the PEP 440 spelling of it. A file that names a different version publishes a
different version: the "Create version tags" step of release.yml tags each crate at
the version the operator typed while `cargo publish` uploads the version the
manifest declares, and `.github/workflows/build-matrix.yml` builds the five wheels
straight from `bindings/python/pyproject.toml` and stamps nothing onto them, so a
stale string there either re-uploads a version PyPI already holds — which fails the
upload after the crates, the npm packages, the Maven artifacts and the Apple
XCFramework have already published — or publishes a wheel labelled for one release
inside another.

This script reads no hand-written list of crates. `[workspace] members` of the root
`Cargo.toml` names every crate, and a crate whose `[package] publish` key is `false`
or an empty registry list reaches no registry, so that key is the one exemption and
each manifest declares it about itself. A hand-written list drifts from the
workspace silently, which is the defect this script was rewritten to remove: its
first version read three of the eighteen publishable manifests on the premise that
the other fifteen inherited a workspace version, and `[workspace.package]` declares
no `version` key at all.

The three sibling SDKs need no entry here: release.yml writes `env.VERSION` into
`bindings/typescript/package.json`, passes `-PscpVersion` to Gradle, and names
`env.VERSION` in the Swift tag and the XCFramework file name, so their published
version comes from the input rather than from a checked-in string.

SECOND CRITERION: the two hand-written crate lists inside release.yml — the `TAGS`
array of the "Create version tags" step, and the `cargo publish -p <crate>` commands
of job publish-crates — each name exactly the publishable crates the workspace
holds. A crate the `TAGS` array omits reaches crates.io under no git tag; a crate
`TAGS` names that the workspace no longer publishes pushes a tag for nothing.
Checking the version of a manifest no release step reaches, and skipping one that a
release step does reach, are the same drift in two directions, so this script closes
both.

Run it four ways:

    scripts/check-release-version-parity.py 0.1.0-beta.2
    scripts/check-release-version-parity.py --pep440 0.1.0-beta.2
    scripts/check-release-version-parity.py --dist-name
    scripts/check-release-version-parity.py --self-test

`--pep440` prints the canonical spelling of one version and checks nothing, so the
step that asks PyPI whether it already holds a release spells the version the way
PyPI names it without repeating the normalization table below.

`--dist-name` prints the `[project] name` of `bindings/python/pyproject.toml` and
checks nothing, so that same step asks PyPI about the distribution this repository
uploads rather than about whichever name a shell literal happens to carry.

`--self-test` plants each defect in a fixture tree and proves this script rejects
it, before release.yml trusts it on the real tree.
"""

from __future__ import annotations

import re
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# The one project file whose checked-in version decides what a published wheel is
# called.
PEP440_PROJECT_FILES = ("bindings/python/pyproject.toml",)

# The workflow whose two hand-written crate lists this script holds to the
# workspace.
RELEASE_WORKFLOW = ".github/workflows/release.yml"

# A workspace that resolves to fewer publishable crates than this floor has had
# members deleted rather than added, and a reader that silently returned a short
# list would report that every manifest it found agreed. The workspace holds
# eighteen publishable crates today.
MINIMUM_PUBLISHABLE_CRATES = 10


class Unparsed(ValueError):
    """The version string uses a PEP 440 segment this script does not handle."""


class Unreadable(ValueError):
    """A file this script derives its list of manifests from does not parse."""


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

# The `TAGS=(` array of the "Create version tags" step, read as the shell literal
# it is: one double-quoted `<crate>@${{ env.VERSION }}` entry per line.
_TAGS_BLOCK = re.compile(r"^\s*TAGS=\(\s*$(.*?)^\s*\)\s*$", re.M | re.S)
_TAG_ENTRY = re.compile(r'"([A-Za-z0-9_.-]+)@\$\{\{\s*env\.VERSION\s*\}\}"')

# The commands that upload a crate. Reading the command rather than the step name
# means a renamed step changes nothing here.
_PUBLISH_COMMAND = re.compile(r"cargo publish -p ([A-Za-z0-9_.-]+)")


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


def workspace_members(root: Path) -> list[str]:
    """Return the `[workspace] members` paths the root Cargo.toml names.

    Raises Unreadable when the root manifest is absent or names no members, so a
    tree this script cannot enumerate fails the release instead of checking an
    empty list of manifests.
    """
    path = root / "Cargo.toml"
    if not path.is_file():
        raise Unreadable(f"{path} does not exist, so no workspace member was read")
    members = tomllib.loads(path.read_text()).get("workspace", {}).get("members")
    if not isinstance(members, list) or not members:
        raise Unreadable(
            f"Cargo.toml carries no '[workspace] members' array, so this script "
            f"enumerated no crate manifest"
        )
    return [str(member) for member in members]


def workspace_version(root: Path) -> str:
    """Return the `[workspace.package] version`, or the empty string when absent."""
    path = root / "Cargo.toml"
    table = tomllib.loads(path.read_text()).get("workspace", {}).get("package", {})
    version = table.get("version")
    return version if isinstance(version, str) else ""


def publishes_to_a_registry(package: dict) -> bool:
    """Say whether a `[package]` table lets `cargo publish` upload the crate.

    Cargo reads `publish = false` and `publish = []` as "upload to no registry",
    and reads a non-empty list as "upload to these registries"; an absent key
    means the default registry. So those two spellings are the exemption, and
    every other manifest is checked.
    """
    publish = package.get("publish", True)
    if publish is False:
        return False
    if isinstance(publish, list) and not publish:
        return False
    return True


def publishable_crates(root: Path) -> list[tuple[str, str]]:
    """Return `(crate name, manifest path)` for every workspace member that publishes.

    Raises Unreadable when a member manifest is absent, carries no `[package]`
    table, carries no `name`, or when the result falls below
    MINIMUM_PUBLISHABLE_CRATES.
    """
    found: list[tuple[str, str]] = []
    for member in workspace_members(root):
        relative = f"{member}/Cargo.toml"
        path = root / relative
        if not path.is_file():
            raise Unreadable(
                f"'[workspace] members' names {member}, and {relative} does not exist"
            )
        package = tomllib.loads(path.read_text()).get("package")
        if not isinstance(package, dict):
            raise Unreadable(f"{relative} carries no '[package]' table")
        if not publishes_to_a_registry(package):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            raise Unreadable(f"{relative} carries no '[package] name'")
        found.append((name, relative))
    if len(found) < MINIMUM_PUBLISHABLE_CRATES:
        raise Unreadable(
            f"the workspace resolved to {len(found)} publishable crates, below the "
            f"floor of {MINIMUM_PUBLISHABLE_CRATES}; this script read a workspace it "
            f"does not recognize rather than a short list whose every entry agreed"
        )
    return found


def cargo_version(path: Path, root: Path) -> str:
    """Return the version a Cargo manifest declares, following workspace inheritance.

    Returns the empty string when the manifest declares no version and when it
    writes `version.workspace = true` against a workspace that declares none, so
    either shape reports a mismatch rather than comparing equal to nothing.
    """
    package = tomllib.loads(path.read_text()).get("package", {})
    version = package.get("version")
    if isinstance(version, dict) and version.get("workspace") is True:
        return workspace_version(root)
    return version if isinstance(version, str) else ""


def project_version(path: Path) -> str:
    """Return the `[project] version` a PEP 621 project file declares."""
    return str(tomllib.loads(path.read_text()).get("project", {}).get("version", ""))


def project_name(path: Path) -> str:
    """Return the `[project] name` a PEP 621 project file declares.

    Raises Unreadable when the file is absent or names none, so the release step
    that asks PyPI about this distribution never asks about an empty name.
    """
    if not path.is_file():
        raise Unreadable(f"{path} does not exist, so no distribution name was read")
    name = tomllib.loads(path.read_text()).get("project", {}).get("name")
    if not isinstance(name, str) or not name:
        raise Unreadable(f"{path} carries no '[project] name'")
    return name


def failures(root: Path, release_version: str) -> list[str]:
    """Return one message per project file that names another version."""
    found: list[str] = []
    try:
        crates = publishable_crates(root)
    except Unreadable as error:
        return [str(error)]
    for _name, relative in crates:
        declared = cargo_version(root / relative, root)
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


def workflow_coverage_failures(root: Path) -> list[str]:
    """Return one message per crate the release workflow's two lists get wrong."""
    found: list[str] = []
    try:
        expected = {name for name, _relative in publishable_crates(root)}
    except Unreadable as error:
        return [str(error)]
    path = root / RELEASE_WORKFLOW
    if not path.is_file():
        return [f"{RELEASE_WORKFLOW} does not exist, so neither crate list was read"]
    text = path.read_text()

    block = _TAGS_BLOCK.search(text)
    if block is None:
        found.append(
            f"{RELEASE_WORKFLOW} carries no 'TAGS=(' array that a ')' closes, so "
            f"this script read no tag list rather than reading a short one"
        )
    else:
        tagged = set(_TAG_ENTRY.findall(block.group(1)))
        for crate in sorted(expected - tagged):
            found.append(
                f"{RELEASE_WORKFLOW} publishes {crate} and its TAGS array names no "
                f"entry for it, so that crate would reach crates.io under no git "
                f"tag; add the entry"
            )
        for crate in sorted(tagged - expected):
            found.append(
                f"{RELEASE_WORKFLOW}'s TAGS array names {crate}, and the workspace "
                f"publishes no such crate; delete the entry"
            )

    published = set(_PUBLISH_COMMAND.findall(text))
    if not published:
        found.append(
            f"{RELEASE_WORKFLOW} carries no 'cargo publish -p <crate>' command, so "
            f"this script read no publish list rather than reading a short one"
        )
    else:
        for crate in sorted(expected - published):
            found.append(
                f"{crate} publishes to a registry and {RELEASE_WORKFLOW} runs no "
                f"'cargo publish -p {crate}', so the release pushes a tag for a "
                f"crate it never uploads; add the step, or write 'publish = false' "
                f"in that crate's manifest"
            )
        for crate in sorted(published - expected):
            found.append(
                f"{RELEASE_WORKFLOW} runs 'cargo publish -p {crate}', and no "
                f"workspace member of that name publishes; delete the step"
            )
    return found


def write_fixture(
    root: Path,
    python_version: str,
    crate_version: str,
    *,
    members: tuple[str, ...] = (),
    unpublished: tuple[str, ...] = (),
    tagged: tuple[str, ...] | None = None,
    publish_commands: tuple[str, ...] | None = None,
) -> None:
    """Write a workspace, its member manifests, the wheel project file and release.yml."""
    names = members or tuple(f"crate-{index:02d}" for index in range(12))
    listing = "".join(f'    "crates/{name}",\n' for name in names)
    (root / "Cargo.toml").write_text(
        f'[workspace]\nresolver = "2"\nmembers = [\n{listing}]\n\n'
        f'[workspace.package]\nedition = "2024"\n'
    )
    for name in names:
        path = root / "crates" / name / "Cargo.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        suffix = "publish = false\n" if name in unpublished else ""
        path.write_text(
            f'[package]\nname = "{name}"\nversion = "{crate_version}"\n{suffix}'
        )
    published = tuple(name for name in names if name not in unpublished)
    project = root / PEP440_PROJECT_FILES[0]
    project.parent.mkdir(parents=True, exist_ok=True)
    project.write_text(f'[project]\nname = "scp-python"\nversion = "{python_version}"\n')
    tag_entries = published if tagged is None else tagged
    commands = published if publish_commands is None else publish_commands
    workflow = root / RELEASE_WORKFLOW
    workflow.parent.mkdir(parents=True, exist_ok=True)
    tags = "".join(
        '            "%s@${{ env.VERSION }}"\n' % name for name in tag_entries
    )
    steps = "".join(
        f"      - name: Publish {name}\n"
        f"        run: cargo publish -p {name} --allow-dirty\n"
        for name in commands
    )
    workflow.write_text(
        "jobs:\n  version-tags:\n    steps:\n"
        "      - name: Create version tags\n        run: |\n"
        f"          TAGS=(\n{tags}          )\n"
        f"  publish-crates:\n    steps:\n{steps}"
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

        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.2")
        found = failures(root, "0.1.0-beta.2")
        expect("an agreeing tree reports nothing", found == [], "; ".join(found))
        found = workflow_coverage_failures(root)
        expect(
            "an agreeing release workflow reports nothing",
            found == [],
            "; ".join(found),
        )

        # The defect this script exists to catch: a Python project file left at the
        # version a previous publish used.
        write_fixture(root, python_version="0.1.0b3", crate_version="0.1.0-beta.2")
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a stale Python version is rejected",
            any(PEP440_PROJECT_FILES[0] in message for message in found),
            f"reported {found}",
        )

        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.1")
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a stale Cargo version is rejected",
            any("crate-00/Cargo.toml" in message for message in found),
            f"reported {found}",
        )

        # The defect the three-manifest predecessor could not catch: one publishable
        # crate left behind while every other crate was bumped.
        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.2")
        stale = root / "crates" / "crate-07" / "Cargo.toml"
        stale.write_text('[package]\nname = "crate-07"\nversion = "0.1.0-beta.1"\n')
        found = failures(root, "0.1.0-beta.2")
        expect(
            "one stale crate among many agreeing crates is rejected",
            any("crate-07/Cargo.toml" in message for message in found),
            f"reported {found}",
        )

        # A crate that reaches no registry is the one exemption, and it is exempt
        # from the two workflow lists for the same reason.
        write_fixture(
            root,
            python_version="0.1.0b2",
            crate_version="0.1.0-beta.2",
            unpublished=("crate-03",),
        )
        skipped = root / "crates" / "crate-03" / "Cargo.toml"
        skipped.write_text(
            '[package]\nname = "crate-03"\nversion = "9.9.9"\npublish = false\n'
        )
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a 'publish = false' crate is exempt from the version check",
            found == [],
            f"reported {found}",
        )
        found = workflow_coverage_failures(root)
        expect(
            "a 'publish = false' crate is exempt from both workflow lists",
            found == [],
            f"reported {found}",
        )

        # A crate that writes `publish = []` reaches no registry either.
        skipped.write_text(
            '[package]\nname = "crate-03"\nversion = "9.9.9"\npublish = []\n'
        )
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a 'publish = []' crate is exempt from the version check",
            found == [],
            f"reported {found}",
        )

        # A crate inheriting a version the workspace never declares reads as absent
        # rather than as agreement.
        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.2")
        inheriting = root / "crates" / "crate-05" / "Cargo.toml"
        inheriting.write_text('[package]\nname = "crate-05"\nversion.workspace = true\n')
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a crate inheriting a version no workspace declares is rejected",
            any("crate-05/Cargo.toml" in message for message in found),
            f"reported {found}",
        )

        # The same inheritance against a workspace that does declare one agrees.
        (root / "Cargo.toml").write_text(
            (root / "Cargo.toml")
            .read_text()
            .replace(
                '[workspace.package]\nedition = "2024"\n',
                '[workspace.package]\nedition = "2024"\nversion = "0.1.0-beta.2"\n',
            )
        )
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a crate inheriting a version the workspace does declare agrees",
            found == [],
            f"reported {found}",
        )

        # The drift the second criterion exists to catch.
        write_fixture(
            root,
            python_version="0.1.0b2",
            crate_version="0.1.0-beta.2",
            tagged=tuple(f"crate-{index:02d}" for index in range(11)),
        )
        found = workflow_coverage_failures(root)
        expect(
            "a published crate the TAGS array omits is rejected",
            any("crate-11" in message and "TAGS" in message for message in found),
            f"reported {found}",
        )

        write_fixture(
            root,
            python_version="0.1.0b2",
            crate_version="0.1.0-beta.2",
            publish_commands=tuple(f"crate-{index:02d}" for index in range(11)),
        )
        found = workflow_coverage_failures(root)
        expect(
            "a publishable crate no 'cargo publish -p' command names is rejected",
            any(
                "crate-11" in message and "cargo publish" in message
                for message in found
            ),
            f"reported {found}",
        )

        write_fixture(
            root,
            python_version="0.1.0b2",
            crate_version="0.1.0-beta.2",
            tagged=tuple(f"crate-{index:02d}" for index in range(12)) + ("crate-99",),
        )
        found = workflow_coverage_failures(root)
        expect(
            "a TAGS entry naming no publishable crate is rejected",
            any("crate-99" in message for message in found),
            f"reported {found}",
        )

        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.2")
        (root / RELEASE_WORKFLOW).write_text("jobs: {}\n")
        found = workflow_coverage_failures(root)
        expect(
            "a release workflow carrying neither crate list is rejected",
            len(found) == 2,
            f"reported {found}",
        )

        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.2")
        (root / PEP440_PROJECT_FILES[0]).unlink()
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a missing project file is rejected",
            any("does not exist" in message for message in found),
            f"reported {found}",
        )

        # A tree this script cannot enumerate fails rather than checking nothing.
        (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a workspace naming no members is rejected",
            any("members" in message for message in found),
            f"reported {found}",
        )

        write_fixture(
            root,
            python_version="0.1.0b2",
            crate_version="0.1.0-beta.2",
            members=("only-one", "only-two"),
        )
        found = failures(root, "0.1.0-beta.2")
        expect(
            "a workspace below the publishable-crate floor is rejected",
            any("floor" in message for message in found),
            f"reported {found}",
        )

        write_fixture(root, python_version="0.1.0b2", crate_version="0.1.0-beta.2")
        expect(
            "--dist-name reads the [project] name of the wheel's project file",
            project_name(root / PEP440_PROJECT_FILES[0]) == "scp-python",
        )
        (root / PEP440_PROJECT_FILES[0]).write_text('[project]\nversion = "1"\n')
        named = False
        try:
            project_name(root / PEP440_PROJECT_FILES[0])
        except Unreadable:
            named = True
        expect("a project file carrying no name raises rather than printing ''", named)

    expect(
        "--pep440 prints the canonical spelling and exits 0",
        main(["", "--pep440", "0.1.0-beta.2"]) == 0,
    )
    expect(
        "--pep440 rejects a spelling this script does not handle",
        main(["", "--pep440", "0.1.0.post1"]) == 1,
    )
    expect(
        "--dist-name prints this repository's distribution name and exits 0",
        main(["", "--dist-name"]) == 0,
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
    if len(argv) == 2 and argv[1] == "--dist-name":
        try:
            print(project_name(REPO / PEP440_PROJECT_FILES[0]))
        except Unreadable as error:
            print(f"::error::{error}")
            return 1
        return 0
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--self-test":
        return self_test()
    release_version = argv[1]
    found = failures(REPO, release_version) + workflow_coverage_failures(REPO)
    for message in found:
        print(f"::error::{message}")
    if found:
        print(
            f"Release version {release_version!r} does not match every project file. "
            f"Bump the files named above, or run the release with the version they "
            f"already name."
        )
        return 1
    print(
        f"Every publishable crate manifest and the wheel's project file name release "
        f"version {release_version}, and both crate lists in {RELEASE_WORKFLOW} name "
        f"exactly the crates the workspace publishes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
