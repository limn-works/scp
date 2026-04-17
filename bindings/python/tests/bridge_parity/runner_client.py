"""JSON-RPC client for the long-lived Bun bridge runner.

This client communicates with `node_bridge_runner.ts` over length-prefixed
JSON-RPC frames on stdin/stdout. The framing is HTTP-style:

    Content-Length: N\r\n
    \r\n
    <N bytes of JSON>

One request per call, one response per request. Errors from the child are
returned as dicts with an "error" key; timeouts and protocol violations
raise Python exceptions.

The timeout is a full-frame budget, not a first-byte budget. Every
`read()` inside the body loop re-checks the remaining budget with
`select()` — a child that writes a partial frame and hangs will trip
`RunnerTimeout` rather than block pytest forever.

Frame size is capped at `MAX_FRAME_BYTES` (16 MiB) and the header at
`MAX_HEADER_BYTES` (4 KiB). A JSON-specific sub-cap of
`MAX_JSON_BODY_BYTES` (1 MiB) short-circuits before `json.loads` so a
deeply-nested adversarial payload cannot RecursionError. A malicious /
malfunctioning runner cannot OOM or stack-blow the test process by
sending a large Content-Length value.

See ADR-046.
"""

from __future__ import annotations

import json
import select
import subprocess
from dataclasses import dataclass, field
from time import monotonic
from typing import Literal

DEFAULT_TIMEOUT_SECS = 30.0

# Hard caps to prevent a misbehaving runner from OOMing the test process
# on an adversarial Content-Length value or a never-ending header line.
# The parity ops are small (identity/DID/signature payloads); 16 MiB is
# generous. The header is a single `Content-Length:` line plus CRLF —
# 4 KiB is orders of magnitude above need.
MAX_FRAME_BYTES = 16 * 1024 * 1024
MAX_HEADER_BYTES = 4 * 1024

# Sub-cap inside MAX_FRAME_BYTES specifically for JSON response bodies.
# Parity responses carry DIDs, signatures, error codes — kilobytes at
# most. 1 MiB is generously above need and well below the point where
# `json.loads` on a deeply-nested adversarial payload could RecursionError
# or blow the stack before yielding a clear error. A 16 MiB body will
# reach `json.loads` today; this cap short-circuits before that.
MAX_JSON_BODY_BYTES = 1 * 1024 * 1024


class RunnerError(RuntimeError):
    """Base class for runner_client failures."""


class RunnerTimeout(RunnerError):
    """Raised when a call exceeds its timeout budget."""


class RunnerClosed(RunnerError):
    """Raised when the runner subprocess has exited unexpectedly."""


class RunnerProtocolError(RunnerError):
    """Raised when the wire protocol is violated (malformed frame, bad JSON)."""


@dataclass
class RunnerClient:
    """Client for a long-lived Bun bridge runner subprocess.

    The subprocess is expected to read length-prefixed JSON requests on
    stdin and write length-prefixed JSON responses on stdout. The client
    does not manage the subprocess lifecycle — the caller is responsible
    for spawning and tearing down (the `bun_runner` pytest fixture does
    this).
    """

    proc: subprocess.Popen[bytes]
    timeout_secs: float = DEFAULT_TIMEOUT_SECS
    _request_id: int = field(default=0, init=False)

    def call(
        self,
        op: str,
        args: dict[str, object],
        mode: Literal["napi", "wasm"],
    ) -> dict[str, object]:
        """Send one RPC call to the runner and return the parsed response.

        The response is always a dict. On success, the dict contains the
        bridge's raw output. On bridge-level errors, the dict contains an
        "error" key with a structured error shape (at least "code" and
        "message").

        Raises RunnerTimeout, RunnerClosed, or RunnerProtocolError on
        transport failures. These are distinct from bridge-level errors,
        which are returned in the response dict.
        """
        if self.proc.poll() is not None:
            rc = self.proc.returncode
            raise RunnerClosed(f"runner subprocess has exited with code {rc}")

        self._request_id += 1
        # Wire field is `bridgeMode` (camelCase) rather than `mode` to avoid
        # colliding with the DOM `RequestMode` type on the TS runner side.
        payload = {
            "id": self._request_id,
            "op": op,
            "args": args,
            "bridgeMode": mode,
        }
        deadline = monotonic() + self.timeout_secs
        self._write_frame(payload)
        return self._read_frame(deadline)

    def reset(self) -> None:
        """Ask the runner to clear its module-global bridge caches.

        Forces re-initialization on the next call so per-test state does
        not leak across session-scoped uses of the bun_runner fixture.
        """
        if self.proc.poll() is not None:
            return
        self._request_id += 1
        deadline = monotonic() + self.timeout_secs
        self._write_frame(
            {
                "id": self._request_id,
                "op": "reset",
                "args": {},
                "bridgeMode": "napi",
            }
        )
        # Consume the response so the next call doesn't see stale framing.
        self._read_frame(deadline)

    def shutdown(self) -> None:
        """Send a graceful shutdown request. Safe to call multiple times."""
        if self.proc.poll() is not None:
            return
        try:
            self._write_frame({"id": 0, "op": "shutdown", "args": {}, "bridgeMode": "napi"})
        except (BrokenPipeError, RunnerClosed):
            # Child already exited — nothing to do.
            pass

    # ------------------------------------------------------------------
    # Internal: wire protocol
    # ------------------------------------------------------------------

    def _write_frame(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        stdin = self.proc.stdin
        if stdin is None:
            raise RunnerClosed("runner stdin is not open")
        try:
            stdin.write(header)
            stdin.write(body)
            stdin.flush()
        except BrokenPipeError as err:
            raise RunnerClosed(f"runner stdin closed: {err}") from err

    def _read_frame(self, deadline: float) -> dict[str, object]:
        stdout = self.proc.stdout
        if stdout is None:
            raise RunnerClosed("runner stdout is not open")

        header_line = self._read_until(stdout, b"\r\n", deadline, MAX_HEADER_BYTES)
        if not header_line.lower().startswith(b"content-length:"):
            raise RunnerProtocolError(f"expected Content-Length header, got: {header_line!r}")
        try:
            length = int(header_line.split(b":", 1)[1].strip())
        except ValueError as err:
            raise RunnerProtocolError(f"invalid Content-Length: {header_line!r}") from err
        if length < 0:
            raise RunnerProtocolError(f"negative Content-Length: {length}")
        if length > MAX_FRAME_BYTES:
            raise RunnerProtocolError(
                f"Content-Length {length} exceeds MAX_FRAME_BYTES {MAX_FRAME_BYTES}"
            )
        # JSON-specific sub-cap: we parse the body with json.loads, which
        # can RecursionError (or take pathological time/memory) on deeply
        # nested adversarial input. Parity responses are small — fail
        # fast if a body somehow exceeds the JSON cap.
        if length > MAX_JSON_BODY_BYTES:
            raise RunnerProtocolError(
                f"Content-Length {length} exceeds MAX_JSON_BODY_BYTES {MAX_JSON_BODY_BYTES}"
            )

        # Consume the blank separator line (also bounded).
        separator = self._read_until(stdout, b"\r\n", deadline, MAX_HEADER_BYTES)
        if separator != b"":
            raise RunnerProtocolError(f"expected blank line after header, got: {separator!r}")

        body = self._read_exact(stdout, length, deadline)
        try:
            parsed = json.loads(body)
        except (RecursionError, json.JSONDecodeError, ValueError) as err:
            # RecursionError: pathologically nested JSON exceeds Python's
            # recursion limit. ValueError covers json subclasses on older
            # runtimes; json.JSONDecodeError is the typical case.
            raise RunnerProtocolError(f"invalid JSON frame: {err}") from err
        if not isinstance(parsed, dict):
            raise RunnerProtocolError(f"expected object response, got: {type(parsed).__name__}")
        return parsed

    @staticmethod
    def _wait_readable(stream: object, deadline: float) -> None:
        remaining = max(0.0, deadline - monotonic())
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            raise RunnerTimeout(f"runner read exceeded budget (deadline {deadline:.3f})")

    @classmethod
    def _read_until(
        cls,
        stream: object,
        terminator: bytes,
        deadline: float,
        max_bytes: int,
    ) -> bytes:
        """Read bytes until (and consuming) `terminator`, returning the prefix.

        Enforces the full-frame `deadline` on every chunk read, not just
        the first byte — a child that writes one byte and hangs will
        still trip the budget. Caps the accumulated buffer at `max_bytes`
        so a runner that never emits the terminator cannot OOM us.
        """
        read1 = getattr(stream, "read", None)
        if read1 is None:
            raise RunnerClosed("stdout does not support read()")
        buf = bytearray()
        while True:
            cls._wait_readable(stream, deadline)
            byte = read1(1)
            if byte == b"" or byte is None:
                raise RunnerClosed("runner stdout closed mid-frame")
            buf.extend(byte)
            if len(buf) > max_bytes:
                raise RunnerProtocolError(
                    f"exceeded {max_bytes} bytes waiting for terminator {terminator!r}"
                )
            if buf.endswith(terminator):
                return bytes(buf[: -len(terminator)])

    @classmethod
    def _read_exact(cls, stream: object, n: int, deadline: float) -> bytes:
        """Read exactly `n` bytes, enforcing `deadline` on each read."""
        read1 = getattr(stream, "read", None)
        if read1 is None:
            raise RunnerClosed("stdout does not support read()")
        buf = bytearray()
        while len(buf) < n:
            cls._wait_readable(stream, deadline)
            chunk = read1(n - len(buf))
            if chunk == b"" or chunk is None:
                raise RunnerClosed(f"runner stdout closed mid-body ({len(buf)}/{n} bytes)")
            buf.extend(chunk)
        return bytes(buf)
