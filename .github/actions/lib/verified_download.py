"""Download a file and accept it only when its size and digest match a pin.

`.github/actions/android-sdk/install.py` and `.github/actions/pinned-tool/install.py`
import this module; neither unpacks an archive this module has not accepted. Check
`verified-download` in scripts/tests/ci-gate/ci_gate_selftest.py feeds it a truncated
archive that must be refused.
"""

from __future__ import annotations

import hashlib
import http.client
import time
import urllib.request
from pathlib import Path

ATTEMPTS = 4


class InstallError(Exception):
    pass


def fetch_once(url: str, destination: Path, algorithm: str) -> tuple[int, str]:
    """Write url to destination; return its size and its digest under algorithm."""
    digest, size = hashlib.new(algorithm), 0
    with (
        urllib.request.urlopen(url, timeout=120) as response,
        destination.open("wb") as out,
    ):
        while chunk := response.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    return size, digest.hexdigest()


def download_verified(
    name: str,
    url: str,
    size: int,
    digest: str,
    destination: Path,
    algorithm: str = "sha256",
    attempts: int = ATTEMPTS,
    backoff: float = 10.0,
) -> None:
    """Download url until its size and digest match, or raise naming the artifact."""
    problem = "no attempt ran"
    for attempt in range(1, attempts + 1):
        try:
            got_size, got_digest = fetch_once(url, destination, algorithm)
            if got_size == size and got_digest == digest:
                print(f"{name}: {url} matches size {size} and {algorithm} {digest}")
                return
            problem = (
                f"got {got_size} bytes with {algorithm} {got_digest}, "
                f"want {size} bytes with {algorithm} {digest}"
            )
        # http.client raises IncompleteRead when a chunked body ends early, and
        # BadStatusLine on a garbled reply; neither subclasses OSError.
        except (OSError, http.client.HTTPException) as error:
            problem = f"download failed: {error}"
        destination.unlink(missing_ok=True)
        print(f"::warning::{name}: attempt {attempt} of {attempts}: {url}: {problem}")
        if attempt < attempts:
            time.sleep(backoff * attempt)
    raise InstallError(
        f"{name}: no download of {url} matched its pinned digest in "
        f"{attempts} attempts; the last one {problem}"
    )
