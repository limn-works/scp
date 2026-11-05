"""Download a file and accept it only when its size and digest match a pin.

`.github/actions/android-sdk/install.py` and `.github/actions/pinned-tool/install.py`
import this module; neither unpacks an archive this module has not accepted. Check
`verified-download` in scripts/tests/ci-gate/ci_gate_selftest.py feeds it a truncated
archive, a stalled server, a server that trickles bytes, an oversized body and a wrong
Content-Length, each of which must be refused.

BOUNDS. Each attempt has a wall-clock deadline of `deadline_floor` seconds plus the
pinned size at `min_rate`, and a read that waits `stall` seconds for a byte fails. A
per-read timeout alone does not bound a transfer: a connection that keeps trickling
bytes never times out, and in run 41658245042 the API 30 leg of `Kotlin / instrumented`
spent 1704 s of a 1890 s job downloading the Android SDK. Each read therefore returns
after one socket read (`read1`), so the deadline is checked at least once every `stall`
seconds. A response whose Content-Length differs from the pinned size is refused before
its body is read, and a body that runs past the pinned size is refused at the first byte
past it, so a server cannot fill the disk. A failed attempt is retried up to ATTEMPTS
times, and then the download raises naming the artifact and its URL.
"""

from __future__ import annotations

import hashlib
import http.client
import time
import urllib.request
from pathlib import Path
from typing import NamedTuple

ATTEMPTS = 4
CHUNK = 1 << 20


class Limits(NamedTuple):
    stall: float = 30.0
    min_rate: float = 8 * (1 << 20)
    deadline_floor: float = 60.0


LIMITS = Limits()


class InstallError(Exception):
    pass


class WrongSize(Exception):
    """The server declared or sent a body whose length is not the pinned size."""


def fetch_once(
    url: str, destination: Path, algorithm: str, size: int, limits: Limits = LIMITS
) -> tuple[int, str]:
    """Write url to destination within one attempt's bounds; return its size and digest."""
    budget = limits.deadline_floor + size / limits.min_rate
    deadline = time.monotonic() + budget
    digest, got = hashlib.new(algorithm), 0
    with (
        urllib.request.urlopen(url, timeout=limits.stall) as response,
        destination.open("wb") as out,
    ):
        declared = response.headers.get("Content-Length")
        if declared is not None and declared.strip() != str(size):
            raise WrongSize(
                f"server declares Content-Length {declared}, the pin {size}"
            )
        # read1 makes one socket read, so a connection that trickles bytes still
        # reaches the deadline check; asking for one byte past the pin finds an
        # oversized body without reading more of it.
        while chunk := response.read1(min(CHUNK, size + 1 - got)):
            if time.monotonic() > deadline:
                # TimeoutError is an OSError, so download_verified retries it.
                raise TimeoutError(
                    f"{url}: attempt passed its {budget:.0f}-second deadline"
                )
            if got + len(chunk) > size:
                raise WrongSize(f"body runs past the pinned {size} bytes")
            digest.update(chunk)
            got += len(chunk)
            out.write(chunk)
    return got, digest.hexdigest()


def download_verified(
    name: str,
    url: str,
    size: int,
    digest: str,
    destination: Path,
    algorithm: str = "sha256",
    attempts: int = ATTEMPTS,
    backoff: float = 10.0,
    limits: Limits = LIMITS,
) -> None:
    """Download url until its size and digest match, or raise naming the artifact."""
    problem = "no attempt ran"
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        try:
            got_size, got_digest = fetch_once(url, destination, algorithm, size, limits)
            if got_size == size and got_digest == digest:
                seconds = time.monotonic() - started
                print(
                    f"{name}: {url} matches size {size} and {algorithm} {digest} "
                    f"({seconds:.1f} s, {size / (1 << 20) / max(seconds, 0.001):.1f} MiB/s)"
                )
                return
            problem = (
                f"got {got_size} bytes with {algorithm} {got_digest}, "
                f"want {size} bytes with {algorithm} {digest}"
            )
        except WrongSize as error:
            problem = f"refused: {error}"
        # http.client raises IncompleteRead when a body ends early, and BadStatusLine
        # on a garbled reply; neither subclasses OSError.
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
