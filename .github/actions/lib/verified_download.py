"""Download a file and accept it only when its size and digest match a pin.

`.github/actions/android-sdk/install.py` and `.github/actions/pinned-tool/install.py`
import this module; neither unpacks an archive this module has not accepted. Check
`verified-download` in scripts/tests/ci-gate/ci_gate_selftest.py feeds it a truncated
archive, a corrupt byte range and a stalled server, each of which must be refused.

BOUNDS. Each attempt has a wall-clock deadline of `deadline_floor` seconds plus the
pinned size at `min_rate`, and a read that waits `stall` seconds for a byte fails. A
failed attempt is retried up to ATTEMPTS times, and then the download raises naming the
artifact and its URL. A per-read timeout alone does not bound a transfer: a connection
that keeps trickling bytes never times out, and in run 41658245042 the API 30 leg of
`Kotlin / instrumented` spent 1704 s of a 1890 s job downloading the Android SDK.

RANGES. A file of at least `segment_min` bytes is fetched as `segments` byte ranges over
separate connections and written into place. A range whose connection stalls or drops is
requested again from the byte it reached, up to `segment_retries` times, so one slow
connection to a mirror costs one range and not the whole file. The whole file is hashed
once every range is in, and that digest alone decides acceptance, so a range a server
answered from a different object fails the pin like any other corruption. A range request
answered with anything but 206 and the exact Content-Range asked for falls back, in the
same attempt, to one stream, as does a smaller file and every download on Windows.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import NamedTuple

ATTEMPTS = 4
CHUNK = 1 << 20


class Limits(NamedTuple):
    stall: float = 30.0
    min_rate: float = 8 * (1 << 20)
    deadline_floor: float = 60.0
    segments: int = 8
    segment_min: int = 32 * (1 << 20)
    segment_retries: int = 3


LIMITS = Limits()


class InstallError(Exception):
    pass


class RangeRefused(Exception):
    """The server did not answer a range request with that exact range."""


def check_deadline(url: str, deadline: float, budget: float) -> None:
    # TimeoutError is an OSError, so download_verified retries it like a dropped
    # connection, and a range worker does not retry it (see fetch_range).
    if time.monotonic() > deadline:
        raise TimeoutError(f"{url}: attempt passed its {budget:.0f}-second deadline")


def file_digest(path: Path, algorithm: str) -> tuple[int, str]:
    digest, size = hashlib.new(algorithm), 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def fetch_stream(
    url: str,
    destination: Path,
    algorithm: str,
    deadline: float,
    budget: float,
    stall: float,
) -> tuple[int, str]:
    digest, size = hashlib.new(algorithm), 0
    with (
        urllib.request.urlopen(url, timeout=stall) as response,
        destination.open("wb") as out,
    ):
        while chunk := response.read(CHUNK):
            check_deadline(url, deadline, budget)
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    return size, digest.hexdigest()


def fetch_range(
    url: str,
    descriptor: int,
    first: int,
    last: int,
    total: int,
    deadline: float,
    budget: float,
    limits: Limits,
    stop: threading.Event,
) -> None:
    """Write bytes first..last (inclusive) of url at their offsets in descriptor."""
    position, failures = first, 0
    while position <= last:
        if stop.is_set():
            return
        wanted = f"bytes {position}-{last}/{total}"
        request = urllib.request.Request(
            url, headers={"Range": f"bytes={position}-{last}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=limits.stall) as response:
                got = response.headers.get("Content-Range")
                if response.status != 206 or got != wanted:
                    raise RangeRefused(
                        f"asked for {wanted}, got status {response.status} with "
                        f"Content-Range {got!r}"
                    )
                while position <= last:
                    chunk = response.read(min(CHUNK, last + 1 - position))
                    if not chunk:
                        raise http.client.IncompleteRead(b"", last + 1 - position)
                    check_deadline(url, deadline, budget)
                    if stop.is_set():
                        return
                    os.pwrite(descriptor, chunk, position)
                    position += len(chunk)
        except RangeRefused:
            raise
        except (OSError, http.client.HTTPException) as error:
            failures += 1
            if failures > limits.segment_retries or time.monotonic() > deadline:
                raise
            print(
                f"::warning::{url}: range from byte {position} failed ({error}); "
                f"requesting it again ({failures} of {limits.segment_retries})",
                flush=True,
            )


def fetch_ranges(
    url: str,
    destination: Path,
    size: int,
    deadline: float,
    budget: float,
    limits: Limits,
) -> None:
    step = -(-size // limits.segments)
    bounds = [(first, min(first + step, size) - 1) for first in range(0, size, step)]
    stop = threading.Event()
    errors: list[BaseException] = []
    with destination.open("wb") as out:
        out.truncate(size)
        with ThreadPoolExecutor(len(bounds)) as pool:
            futures = [
                pool.submit(
                    fetch_range,
                    url,
                    out.fileno(),
                    first,
                    last,
                    size,
                    deadline,
                    budget,
                    limits,
                    stop,
                )
                for first, last in bounds
            ]
            for future in as_completed(futures):
                error = future.exception()
                if error is not None:
                    stop.set()
                    errors.append(error)
    if errors:
        refused = [error for error in errors if isinstance(error, RangeRefused)]
        raise refused[0] if refused else errors[0]


def fetch_once(
    url: str, destination: Path, algorithm: str, size: int, limits: Limits = LIMITS
) -> tuple[int, str]:
    """Write url to destination within one attempt's deadline; return its size and digest."""
    budget = limits.deadline_floor + size / limits.min_rate
    deadline = time.monotonic() + budget
    # os.pwrite does not exist on Windows, where pinned-tool also runs.
    if limits.segments > 1 and size >= limits.segment_min and hasattr(os, "pwrite"):
        try:
            fetch_ranges(url, destination, size, deadline, budget, limits)
            return file_digest(destination, algorithm)
        except RangeRefused as refusal:
            print(f"{url}: {refusal}; fetching it as one stream", flush=True)
    return fetch_stream(url, destination, algorithm, deadline, budget, limits.stall)


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
                    f"({seconds:.1f} s, {size / (1 << 20) / max(seconds, 0.001):.1f} MiB/s)",
                    flush=True,
                )
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
        print(
            f"::warning::{name}: attempt {attempt} of {attempts}: {url}: {problem}",
            flush=True,
        )
        if attempt < attempts:
            time.sleep(backoff * attempt)
    raise InstallError(
        f"{name}: no download of {url} matched its pinned digest in "
        f"{attempts} attempts; the last one {problem}"
    )
