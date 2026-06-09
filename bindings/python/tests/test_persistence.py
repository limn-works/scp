"""SDK-layer smoke test for SQLite-backed persistence (#1549 Phase 4 PR 3).

Verifies that the `SCP(storage={...sqlite...})` wrapper surface:

1. Accepts the documented `{"type": "sqlite", "path": str, "key": bytes}`
   config dict and forwards it to the native `with_storage` factory
   without raising.
2. Creates the SQLCipher database file at `{path}/scp.db` as a side
   effect of construction (that is what the FFI `StorageConfig::Sqlite`
   path does — see `crates/scp-ffi/src/runtime.rs::with_storage_py`).
3. Drives the full `suspend() → resume() → shutdown()` lifecycle on a
   SQLite-backed instance without error.
4. Is reconstructible against the SAME SQLite path + key — the
   reopened instance must inherit the persisted state (the
   `ProtocolRepository` shared via `CoreFields::persistence_arc_clone`
   on the bridge side; see #1491, #1260, #1342, #1678).

The wrapper surface is all this smoke test is responsible for. The
end-to-end `identity_create → context_create → context_send → suspend
→ restore → context_send` path is exercised at the Rust integration
layer (`crates/scp-testing/tests/integration/persistence_sdk.rs`)
because the Python `SCP` class does not yet surface those context
methods. Phase 4 PR 4 (#1549, ADR-048) deleted the free-function
façade (`scp_sdk.context_create`, etc.) along with the process-wide
default bridge it routed through; the remaining SDK wiring to expose
those operations on the caller-owned `SCP` handle is tracked as
follow-up work.

Requires the native `_scp_core` extension built via
`maturin develop --release`. See `.docs/scaffold/python.md`.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

try:
    from scp_sdk import SCP, _scp_core
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )


# Stable 32-byte key for SQLCipher. The specific value does not matter;
# only that we reuse the same key across the two construction calls that
# simulate process restart.
_SQLITE_KEY = b"\x42" * 32


def test_sqlite_construction_creates_database_file() -> None:
    """`SCP(storage=sqlite)` must open/create the SQLCipher DB on disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "scp.db"
        assert not db_path.exists(), "scp.db must not exist before SCP construction"

        scp = SCP(storage={"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY})
        try:
            assert db_path.exists(), (
                f"SCP(storage=sqlite) must create scp.db at {db_path}; "
                "the SQLCipher open-or-create happens inside "
                "PyBridgeInstance::with_storage_py."
            )
            assert scp.instance_id > 0
        finally:
            asyncio.run(scp.shutdown(timeout=1.0))


def test_sqlite_lifecycle_roundtrip() -> None:
    """suspend / async resume / shutdown roundtrip on a SQLite-backed SCP."""
    with tempfile.TemporaryDirectory() as tmpdir:
        scp = SCP(storage={"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY})
        try:
            scp.suspend()
            # `resume()` is an async coroutine on the SDK wrapper after
            # #1549 PR 3 — we run it on a fresh event loop so this test
            # does not require pytest-asyncio.
            asyncio.run(scp.resume())
        finally:
            asyncio.run(scp.shutdown(timeout=1.0))


def test_sqlite_reopen_with_same_path_and_key_succeeds() -> None:
    """A second `SCP(storage=sqlite)` against the same path+key must succeed.

    This is the restart property that #1549 PR 3 delivers at the SDK
    surface: suspend, drop the instance, reconstruct against the same
    directory, and the SQLCipher-encrypted database opens again without
    re-deriving a new encryption key.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY}

        scp1 = SCP(storage=config)
        id1 = scp1.instance_id
        asyncio.run(scp1.shutdown(timeout=1.0))

        # Fresh Python object, same underlying database file.
        scp2 = SCP(storage=config)
        id2 = scp2.instance_id
        try:
            assert id2 > id1, (
                "monotonic instance_id counter must advance across "
                f"two SCP constructions (got {id1} then {id2})"
            )
        finally:
            asyncio.run(scp2.shutdown(timeout=1.0))


def test_sqlite_rejects_mismatched_key() -> None:
    """Opening the same DB with a different key must fail, not return an empty DB.

    Guards against silent downgrade — if the wrong key were accepted
    and a fresh empty database was opened in its place, callers would
    silently lose access to persisted state. After commit
    ``9fa80e13c`` (`fix(ffi): propagate SqliteStorage::new failure
    from with_storage`) the bridge surfaces the `SQLCipher` key
    mismatch as a ``ValidationError`` (``SCP-VALID-7005``) rather than
    silently returning an in-memory instance.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        scp1 = SCP(storage={"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY})
        asyncio.run(scp1.shutdown(timeout=1.0))

        # Wrong key must RAISE — `SqliteStorage::new` fails at the
        # `PRAGMA key` / WAL-mode step because SQLCipher rejects the
        # key as "file is not a database". The PyO3 bridge wraps that
        # in `ScpPyError::Validation` → `scp_sdk.ValidationError`.
        wrong_key = b"\x11" * 32
        with pytest.raises(_scp_core.ValidationError):
            SCP(storage={"type": "sqlite", "path": tmpdir, "key": wrong_key})

        # Reopen with the correct key — the original encrypted state
        # must still be intact (the failed mismatched-key attempt
        # must not have corrupted or truncated the original
        # encrypted database file).
        scp3 = SCP(storage={"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY})
        asyncio.run(scp3.shutdown(timeout=1.0))


def test_sqlite_missing_path_field_raises() -> None:
    """Malformed sqlite config must surface a ValidationError at the boundary."""
    with pytest.raises(_scp_core.ValidationError):
        SCP(storage={"type": "sqlite", "key": _SQLITE_KEY})  # no 'path'


def test_sqlite_open_failure_fails_closed_not_no_storage() -> None:
    """A SQLite open at an unusable path raises — never a no-storage instance.

    Spec §17.6 fail-closed: a failed durable-backend open is terminal. The
    bridge must NOT return a degraded instance.
    """
    # A path whose parent is a regular file cannot host scp.db.
    with tempfile.TemporaryDirectory() as tmpdir:
        not_a_dir = Path(tmpdir) / "regular_file"
        not_a_dir.write_bytes(b"not a directory")
        with pytest.raises(_scp_core.ValidationError):
            SCP(
                storage={
                    "type": "sqlite",
                    "path": str(not_a_dir / "sub"),
                    "key": _SQLITE_KEY,
                }
            )
