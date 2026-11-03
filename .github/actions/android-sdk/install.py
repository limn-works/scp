#!/usr/bin/env python3
"""Install pinned Android SDK packages from archives checked before they are unpacked.

`action.yml` beside this file is the one caller in CI. Each argument is an SDK package
path as sdkmanager spells it (`ndk;27.2.12479018`); PINS below must name it.

WHY NOT `sdkmanager --install`. sdkmanager unpacks what it downloaded without a check
that reaches the job: on 2026-10-20 job 118835960956 died on `Error on ZipFile unknown
archive` while unpacking the NDK, and on 2026-11-02 job 125594057792 printed `Error
reading Zip content from a SeekableByteChannel` for the emulator package, installed no
emulator, and failed later at `adb emu kill` with no test run. Both reruns passed. This
script downloads each archive itself, compares its size and the SHA-1 Google publishes
for it in https://dl.google.com/android/repository/repository2-3.xml (system images:
sys-img/android/sys-img2-3.xml) against PINS, and retries a mismatch. Only an archive
that matches is unpacked; when every attempt mismatches, the step fails naming the
package and its URL. SHA-1 is the only digest that manifest publishes.

WHAT MAKES AN UNPACKED ARCHIVE AN INSTALLED PACKAGE. Every pinned archive holds one
top-level directory with a `source.properties` that names the package revision, and the
script moves that directory to the package's path under the SDK root. sdkmanager lists a
package by its `package.xml`. For a platform or a system image, whose `source.properties`
carries the API level, tag and ABI, `sdkmanager --list_installed` writes that file
itself, with the type details avdmanager and the Android Gradle plugin read. It does not
recognize the side-by-side NDK or the emulator from their `source.properties` (job
125641934068 listed neither), so for a package whose pin names a `display_name` (the
generic packages, whose type details are empty) this script writes the `package.xml`
sdkmanager would have written. The final check runs that listing and fails unless every
requested package appears at its pinned revision; a later `sdkmanager --install` of the
same package downloads nothing.

WHY A PACKAGE ALREADY AT ITS PINNED REVISION IS KEPT. The runner image preinstalls
some packages (`platforms;android-35` among them). A directory whose `source.properties`
already names the pinned revision came with the image, not from a download in this job,
so it stays and nothing is fetched for it.

A package not in PINS fails the step: pin it here from the manifest above, with the
`complete` archive's url, size and checksum for host-os linux.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from verified_download import InstallError, download_verified

BASE_URL = "https://dl.google.com/android/repository/"


class Pin(NamedTuple):
    # The revision the archive's `source.properties` records, which is what sdkmanager
    # lists once the archive is unpacked.
    revision: str
    archive: str
    size: int
    sha1: str
    # Set for a generic package sdkmanager does not recognize from `source.properties`:
    # the manifest's display name, written into the package.xml this script creates.
    display_name: str | None = None


PINS: dict[str, Pin] = {
    "platforms;android-35": Pin(
        "2", "platform-35_r02.zip", 64273788, "0bb560a90a7a2cbd0dd8348224d518b638fe7949"
    ),
    "ndk;27.2.12479018": Pin(
        "27.2.12479018",
        "android-ndk-r27c-linux.zip",
        663987688,
        "090e8083a715fdb1a3e402d0763c388abb03fb4e",
        "NDK (Side by side) 27.2.12479018",
    ),
    "platform-tools": Pin(
        "37.0.1",
        "platform-tools_r37.0.1-linux.zip",
        9054187,
        "477254aa5f903c15cf51001717bdf347fb6b53e0",
        "Android SDK Platform-Tools",
    ),
    # The stable channel's emulator on 2026-11-02, the one the emulator runner action
    # installed as "latest" until this pin replaced it.
    "emulator": Pin(
        "37.2.13",
        "emulator-linux_x64-16740729.zip",
        349658551,
        "f41f9e31eb5ca64926603c03265c50bbc0ff4172",
        "Android Emulator",
    ),
    # The manifest lists this archive as revision 11; its source.properties records 10.
    "system-images;android-30;default;x86_64": Pin(
        "10",
        "sys-img/android/x86_64-30_r11.zip",
        676379777,
        "5e4de3946d46f88856c35efcc4d797b381456347",
    ),
    "system-images;android-33;default;x86_64": Pin(
        "2",
        "sys-img/android/x86_64-33_r02.zip",
        694005732,
        "d4698590184a21fe1e8754284130ad3006b5fc79",
    ),
}


def revision_key(text: str) -> tuple[int, ...]:
    """`35.0.0` and `35` name one revision; sdkmanager prints whichever it read."""
    parts = [int(part) for part in text.strip().split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def properties_revision(directory: Path) -> str | None:
    path = directory / "source.properties"
    if not path.is_file():
        return None
    for line in path.read_text(errors="replace").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "Pkg.Revision":
            return value.strip()
    return None


def unpack(package: str, pin: Pin, archive: Path, target: Path, root: Path) -> None:
    """Unzip archive under root and move its one top-level directory to target."""
    # Staged under the SDK root, so the move below is a rename on one filesystem.
    staging = Path(tempfile.mkdtemp(prefix=".unpack-", dir=root))
    try:
        # `unzip`, not zipfile: zipfile drops the executable bits every NDK and
        # emulator binary needs.
        subprocess.run(["unzip", "-q", str(archive), "-d", str(staging)], check=True)
        tops = list(staging.iterdir())
        if len(tops) != 1 or not tops[0].is_dir():
            raise InstallError(
                f"{package}: {pin.archive} holds {sorted(p.name for p in tops)}, "
                f"not one top-level directory"
            )
        revision = properties_revision(tops[0])
        if revision is None or revision_key(revision) != revision_key(pin.revision):
            raise InstallError(
                f"{package}: {pin.archive} names revision {revision!r} in "
                f"source.properties, not the pinned {pin.revision}"
            )
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tops[0]), str(target))
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def package_xml(package: str, pin: Pin) -> str:
    """The package.xml sdkmanager writes for a generic package it installed."""
    assert pin.display_name is not None
    names = ("major", "minor", "micro")
    parts = pin.revision.split(".")
    revision = "".join(f"<{n}>{p}</{n}>" for n, p in zip(names, parts, strict=False))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<ns2:repository xmlns:ns2="http://schemas.android.com/repository/android/common/02"'
        ' xmlns:ns5="http://schemas.android.com/repository/android/generic/02">'
        '<license id="android-sdk-license" type="text"/>'
        f'<localPackage path="{package}" obsolete="false">'
        '<type-details xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xsi:type="ns5:genericDetailsType"/>'
        f"<revision>{revision}</revision>"
        f"<display-name>{pin.display_name}</display-name>"
        '<uses-license ref="android-sdk-license"/>'
        "</localPackage></ns2:repository>"
    )


def installed_revisions(sdkmanager: Path, root: Path) -> dict[str, str]:
    """Return each package path `sdkmanager --list_installed` prints, with its version."""
    listing = subprocess.run(
        [str(sdkmanager), f"--sdk_root={root}", "--list_installed"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    found = {}
    for line in listing.splitlines():
        columns = [column.strip() for column in line.split("|")]
        if len(columns) >= 2 and columns[0] and columns[0] not in ("Path", "-------"):
            found[columns[0]] = columns[1]
    return found


def append(variable: str, line: str) -> None:
    with open(os.environ[variable], "a") as out:
        out.write(line + "\n")


def main(packages: list[str]) -> int:
    root_text = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not root_text:
        raise InstallError(
            "neither ANDROID_HOME nor ANDROID_SDK_ROOT names the SDK root"
        )
    root = Path(root_text)
    tools = root / "cmdline-tools/latest/bin"
    if not (tools / "sdkmanager").is_file():
        raise InstallError(
            f"{tools}/sdkmanager does not exist; the runner image's command-line tools "
            f"are what this step lists packages and creates AVDs with"
        )
    unknown = [package for package in packages if package not in PINS]
    if unknown:
        raise InstallError(f"no pin in {__file__} for {unknown}")
    with tempfile.TemporaryDirectory() as downloads:
        for package in packages:
            pin = PINS[package]
            target = root.joinpath(*package.split(";"))
            present = properties_revision(target)
            if present is not None and revision_key(present) == revision_key(
                pin.revision
            ):
                print(f"{package}: {target} already holds revision {pin.revision}")
                continue
            archive = Path(downloads) / Path(pin.archive).name
            download_verified(
                package, BASE_URL + pin.archive, pin.size, pin.sha1, archive, "sha1"
            )
            unpack(package, pin, archive, target, root)
            archive.unlink()
            if pin.display_name is not None:
                (target / "package.xml").write_text(package_xml(package, pin))
    installed = installed_revisions(tools / "sdkmanager", root)
    wrong = {
        package: installed.get(package)
        for package in packages
        if installed.get(package) is None
        or revision_key(installed[package]) != revision_key(PINS[package].revision)
    }
    if wrong:
        raise InstallError(
            f"sdkmanager --list_installed shows {wrong}, not the pinned revisions"
        )
    append("GITHUB_PATH", str(tools))
    append("GITHUB_PATH", str(root / "platform-tools"))
    append("GITHUB_PATH", str(root / "emulator"))
    # The Android Gradle plugin installs a missing SDK package it needs through the same
    # unchecked download path; with this property off it fails naming the package, which
    # then belongs in PINS.
    opts = os.environ.get("GRADLE_OPTS", "")
    flag = "-Dorg.gradle.project.android.builder.sdkDownload=false"
    append("GITHUB_ENV", f"GRADLE_OPTS={opts + ' ' if opts else ''}{flag}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except InstallError as error:
        print(f"::error::{error}")
        sys.exit(1)
