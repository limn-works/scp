#!/usr/bin/env python3
"""Install a pinned tool from an archive checked against a pinned digest.

`action.yml` beside this file is the one caller in CI. The argument names a tool in
PINS; the script picks the archive for the runner's OS and CPU, downloads it through
`.github/actions/lib/verified_download.py` (size and SHA-256 must match, a mismatch is
retried, and the step fails naming the tool and URL when every attempt mismatches), and
only then unpacks it.

WHY NOT THE UPSTREAM SETUP ACTIONS. oven-sh/setup-bun@v2 (src/action.ts:182-183),
ilammy/setup-nasm@v1 (index.js:65-76), PyO3/maturin-action@v1 (src/index.ts:550-556)
and actions/setup-python@v5 (src/install-python.ts:133-139) each unpack what
`@actions/tool-cache`'s downloadTool returned, with no digest comparison.

WHERE EACH DIGEST COMES FROM.
  bun      SHASUMS256.txt in the oven-sh/bun release the version names, which agrees
           with the digest GitHub records for each asset.
  nasm     www.nasm.us publishes no checksum; the digest is the SHA-256 of the archive
           as fetched from www.nasm.us and from setup-nasm's GitHub mirror on
           2026-11-02, which agreed.
  maturin  the SHA-256 GitHub records for each PyO3/maturin release asset
           (`gh api repos/PyO3/maturin/releases/tags/<tag>`, field `digest`).
  python   the same GitHub-recorded digest for the actions/python-versions asset where
           GitHub records one (3.10.22 for Linux); the 3.10.11 macOS and Windows
           assets predate GitHub's digests, so theirs is the SHA-256 of the asset as
           fetched on 2026-11-02. The pip and certifi wheels carry the SHA-256 PyPI
           publishes for them.

PYTHON 3.10. No runner image caches CPython 3.10 (actions/runner-images
images/*/toolsets/toolset-*.json list 3.11 and later), so actions/setup-python
downloads it on every run. This script installs the same actions/python-versions
package setup-python would, by running the setup.sh or setup.ps1 inside it, into
$RUNNER_TOOL_CACHE/Python; `.github/actions/toolcache-setup` then finds it there.
Each setup script ends with `pip install --upgrade --force-reinstall pip`, and the
macOS one runs "Install Certificates.command", which installs certifi; both would fetch
from PyPI unchecked, so the script runs with PIP_NO_INDEX=1 and PIP_FIND_LINKS naming a
directory holding only the pinned, checked pip and certifi wheels.

maturin goes where PyO3/maturin-action looks before it downloads: installMaturin
(src/index.ts:568-576) calls `tc.find('maturin', <version>, 'x64')` and uses a hit, so
the binary is unpacked to $RUNNER_TOOL_CACHE/maturin/<version>/x64 with the
`x64.complete` marker tc.find requires (maturin-action passes `x64` on every CPU), and
every maturin-action step passes the same version as `maturin-version`. Job
python-wheels-linux in build-matrix.yml runs no maturin-action; it mounts the binary from
that directory into its manylinux container.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from verified_download import InstallError, download_verified


class Archive(NamedTuple):
    url: str
    size: int
    sha256: str
    # Paths inside the archive of the executables to install, each placed flat in the
    # tool's bin directory. Empty for a python-versions package, which installs itself.
    members: tuple[str, ...] = ()


BUN_VERSION = "1.3.9"
NASM_VERSION = "2.16.01"
MATURIN_VERSION = "1.16.0"
MATURIN_URL = f"https://github.com/PyO3/maturin/releases/download/v{MATURIN_VERSION}/"
PYTHON_VERSIONS_URL = "https://github.com/actions/python-versions/releases/download/"

# (tool, runner OS, CPU) -> archive.
PINS: dict[tuple[str, str, str], Archive] = {
    ("bun", "Linux", "X64"): Archive(
        f"https://github.com/oven-sh/bun/releases/download/bun-v{BUN_VERSION}/bun-linux-x64.zip",
        38812800,
        "4680e80e44e32aa718560ceae85d22ecfbf2efb8f3641782e35e4b7efd65a1aa",
        ("bun-linux-x64/bun",),
    ),
    # The build for x64 CPUs without AVX2; select() picks it the way setup-bun did
    # (src/utils.ts:106-111 at v2: no `avx2` in /proc/cpuinfo).
    ("bun", "Linux", "X64-baseline"): Archive(
        f"https://github.com/oven-sh/bun/releases/download/bun-v{BUN_VERSION}/bun-linux-x64-baseline.zip",
        38670145,
        "104d4d037f4b35e10215c0507e1779691f39c57bd91ddeefe11cad781e3fc4b9",
        ("bun-linux-x64-baseline/bun",),
    ),
    ("nasm", "Windows", "X64"): Archive(
        f"https://www.nasm.us/pub/nasm/releasebuilds/{NASM_VERSION}/win64/nasm-{NASM_VERSION}-win64.zip",
        506056,
        "029eed31faf0d2c5f95783294432cbea6c15bf633430f254bb3c1f195c67ca3a",
        (f"nasm-{NASM_VERSION}/nasm.exe", f"nasm-{NASM_VERSION}/ndisasm.exe"),
    ),
    ("maturin", "Linux", "X64"): Archive(
        MATURIN_URL + "maturin-x86_64-unknown-linux-musl.tar.gz",
        10440643,
        "804add817bf3b8a3760324ace2e2c39c345f7a99b3ace1296aeed1abc3a1d8c4",
        ("maturin",),
    ),
    # build-matrix.yml job python-wheels-linux mounts this static binary into the
    # manylinux image of an arm64 runner.
    ("maturin", "Linux", "ARM64"): Archive(
        MATURIN_URL + "maturin-aarch64-unknown-linux-musl.tar.gz",
        9863420,
        "7b7321340805f90d65f138ba8831c789b706086153f1cfb97d915c5ac6ad6c4d",
        ("maturin",),
    ),
    ("maturin", "macOS", "ARM64"): Archive(
        MATURIN_URL + "maturin-aarch64-apple-darwin.tar.gz",
        9194641,
        "1abe6c9d188b674103a4c3d9bbaa6817cc45c4b7e2ecd5908643624ff5cbf657",
        ("maturin",),
    ),
    ("maturin", "macOS", "X64"): Archive(
        MATURIN_URL + "maturin-x86_64-apple-darwin.tar.gz",
        9969248,
        "ef7dd01584717c0ebf49b9a2aedf49a6586d17543adb2e8f08577af7d987a525",
        ("maturin",),
    ),
    ("maturin", "Windows", "X64"): Archive(
        MATURIN_URL + "maturin-x86_64-pc-windows-msvc.zip",
        9794754,
        "ca9fa03d2b37bbfc2851a62a787f1b6948b33ebd9cc6856376244a340377961b",
        ("maturin.exe",),
    ),
    ("python3.10", "Linux", "X64"): Archive(
        PYTHON_VERSIONS_URL
        + "3.10.22-36876129702/python-3.10.22-linux-24.04-x64.tar.gz",
        64577634,
        "4c96c0e9380150d436c38be322bafa04a5632db7eb2def147b7553ed7e88fd16",
    ),
    ("python3.10", "macOS", "ARM64"): Archive(
        PYTHON_VERSIONS_URL + "3.10.11-11114431484/python-3.10.11-darwin-arm64.tar.gz",
        40749885,
        "ee7efaad2965fa5076c9686899f5b599a8b0131d1404035b76b31de0dd9d35fb",
    ),
    ("python3.10", "Windows", "X64"): Archive(
        PYTHON_VERSIONS_URL + "3.10.11-11114431484/python-3.10.11-win32-x64.zip",
        28756669,
        "c7c029492644331f01facb97382d1f145882b162d920f6b58b297af22bf459c4",
    ),
}

# The only distributions the python-versions setup scripts may install from PyPI.
WHEELS = (
    Archive(
        "https://files.pythonhosted.org/packages/07/25/"
        "ee8c38ae72d66b844ce8eb9711ba905dba21ca1a8a0c960057c41cd23337/"
        "pip-26.3-py3-none-any.whl",
        1950951,
        "f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13",
    ),
    Archive(
        "https://files.pythonhosted.org/packages/32/d1/"
        "a3652fe2c19134d0d15922177821d863cbd7e842d53a21bbe7e8e3a1b5ac/"
        "certifi-2026.10.23-py3-none-any.whl",
        135082,
        "e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1",
    ),
)


def extract(archive: Path, members: tuple[str, ...], bin_dir: Path) -> None:
    """Copy each member out of archive into bin_dir, executable."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    for member in members:
        target = bin_dir / Path(member).name
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z, z.open(member) as src:
                target.write_bytes(src.read())
        else:
            with tarfile.open(archive) as t:
                src = t.extractfile(member)
                if src is None:
                    raise InstallError(f"{archive.name} has no file {member}")
                target.write_bytes(src.read())
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def append(variable: str, line: str) -> None:
    with open(os.environ[variable], "a") as out:
        out.write(line + "\n")


def bin_dir_for(tool: str) -> Path:
    if tool == "maturin":
        # The directory tc.find('maturin', MATURIN_VERSION, 'x64') returns.
        return Path(os.environ["RUNNER_TOOL_CACHE"], "maturin", MATURIN_VERSION, "x64")
    if tool == "bun":
        # Where oven-sh/setup-bun put it.
        return Path.home() / ".bun" / "bin"
    return Path(os.environ["RUNNER_TEMP"], tool)


def file_name(url: str) -> str:
    return url.rsplit("/", 1)[1]


def install_python_package(archive: Path, downloads: Path) -> None:
    """Unpack a python-versions package and run its setup script against pinned wheels."""
    wheelhouse = downloads / "wheelhouse"
    wheelhouse.mkdir()
    for wheel in WHEELS:
        name = file_name(wheel.url)
        download_verified(name, wheel.url, wheel.size, wheel.sha256, wheelhouse / name)
    package = downloads / "package"
    package.mkdir()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            z.extractall(package)
        command = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive"]
        command += ["-ExecutionPolicy", "Unrestricted", "-File", "setup.ps1"]
    else:
        with tarfile.open(archive) as t:
            t.extractall(package, filter="data")
        command = ["bash", "./setup.sh"]
    env = dict(os.environ, PIP_NO_INDEX="1", PIP_FIND_LINKS=str(wheelhouse))
    subprocess.run(command, cwd=package, env=env, check=True)


def runner_platform(tool: str) -> tuple[str, str]:
    """The (runner OS, CPU) key of PINS for tool on this runner."""
    system, cpu = os.environ.get("RUNNER_OS", ""), os.environ.get("RUNNER_ARCH", "")
    if tool == "bun" and (system, cpu) == ("Linux", "X64"):
        cpuinfo = Path("/proc/cpuinfo")
        if not (cpuinfo.is_file() and "avx2" in cpuinfo.read_text()):
            cpu = "X64-baseline"
    return system, cpu


def main(tool: str) -> int:
    runner = runner_platform(tool)
    archive = PINS.get((tool, *runner))
    if archive is None:
        raise InstallError(
            f"no pin in {__file__} for {tool} on {runner[0]} {runner[1]} "
            f"(machine {platform.machine()})"
        )
    with tempfile.TemporaryDirectory() as temp:
        downloads = Path(temp)
        path = downloads / file_name(archive.url)
        download_verified(tool, archive.url, archive.size, archive.sha256, path)
        if not archive.members:
            install_python_package(path, downloads)
            print(f"{tool}: installed {file_name(archive.url)} into the tool cache")
            return 0
        bin_dir = bin_dir_for(tool)
        if bin_dir.exists():
            shutil.rmtree(bin_dir)
        extract(path, archive.members, bin_dir)
    if tool == "bun":
        (bin_dir / "bunx").symlink_to(bin_dir / "bun")
    if tool == "maturin":
        (bin_dir.parent / "x64.complete").write_text("")
    append("GITHUB_PATH", str(bin_dir))
    print(f"{tool}: installed {', '.join(archive.members)} to {bin_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1]))
    except (InstallError, subprocess.CalledProcessError) as error:
        print(f"::error::{sys.argv[1]}: {error}")
        sys.exit(1)
