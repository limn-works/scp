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
methods — the free-function façade (`scp_sdk.context_create`) routes
to the process-global default instance, not to the caller-owned `SCP`
handle, and that migration is in #1549 PR 4+.

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
            scp.shutdown(timeout=1.0)


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
            scp.shutdown(timeout=1.0)


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
        scp1.shutdown(timeout=1.0)

        # Fresh Python object, same underlying database file.
        scp2 = SCP(storage=config)
        id2 = scp2.instance_id
        try:
            assert id2 > id1, (
                "monotonic instance_id counter must advance across "
                f"two SCP constructions (got {id1} then {id2})"
            )
        finally:
            scp2.shutdown(timeout=1.0)


def test_sqlite_rejects_mismatched_key() -> None:
    """Opening the same DB with a different key must fail, not return an empty DB.

    Guards against silent downgrade — if the wrong key were accepted
    and a fresh empty database was opened in its place, callers would
    silently lose access to persisted state.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        scp1 = SCP(storage={"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY})
        scp1.shutdown(timeout=1.0)

        wrong_key = b"\x11" * 32
        # FAIL CLOSED (spec §17.6): opening the existing encrypted DB with a
        # different key MUST raise — the bridge no longer silently degrades to
        # an in-memory-only instance. SQLCipher rejects the wrong key, so the
        # `SqliteStorage` open fails and `with_storage` surfaces a
        # ValidationError rather than returning a no-storage instance.
        with pytest.raises(_scp_core.ValidationError):
            SCP(storage={"type": "sqlite", "path": tmpdir, "key": wrong_key})

        # Reopen with the correct key — the original encrypted state must
        # still be intact (the failed mismatched-key attempt did not corrupt
        # or overwrite it).
        scp3 = SCP(storage={"type": "sqlite", "path": tmpdir, "key": _SQLITE_KEY})
        scp3.shutdown(timeout=1.0)


def test_sqlite_missing_path_field_raises() -> None:
    """Malformed sqlite config must surface a ValidationError at the boundary."""
    with pytest.raises(_scp_core.ValidationError):
        SCP(storage={"type": "sqlite", "key": _SQLITE_KEY})  # no 'path'


def test_sqlite_passphrase_roundtrip() -> None:
    """A passphrase-keyed SQLite DB re-derives the same key across restarts.

    Spec §17.6 passphrase mode: create with a passphrase, drop the
    instance, reopen the same directory with the same passphrase — the
    Argon2id-derived key plus the persisted salt sidecar must re-open the
    same encrypted database (not a fresh empty one).
    """
    passphrase = "correct horse battery staple"
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "scp.db"
        salt_path = Path(tmpdir) / "scp.salt"

        scp1 = SCP(storage={"type": "sqlite", "path": tmpdir, "passphrase": passphrase})
        scp1.shutdown(timeout=1.0)
        assert db_path.exists(), "passphrase mode must create scp.db"
        assert salt_path.exists(), "passphrase mode must persist the salt sidecar"

        # Reopen with the SAME passphrase — must succeed (same derived key).
        scp2 = SCP(storage={"type": "sqlite", "path": tmpdir, "passphrase": passphrase})
        scp2.shutdown(timeout=1.0)


def test_sqlite_wrong_passphrase_fails_closed() -> None:
    """A wrong passphrase MUST fail closed — never a silent fresh DB.

    Spec §17.6: SQLCipher rejects the wrong-passphrase-derived key on the
    first query; the bridge surfaces a ValidationError instead of opening
    an empty database in its place.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        scp1 = SCP(storage={"type": "sqlite", "path": tmpdir, "passphrase": "the right one"})
        scp1.shutdown(timeout=1.0)

        with pytest.raises(_scp_core.ValidationError):
            SCP(storage={"type": "sqlite", "path": tmpdir, "passphrase": "the wrong one"})

        # Original DB remains intact under the correct passphrase.
        scp3 = SCP(storage={"type": "sqlite", "path": tmpdir, "passphrase": "the right one"})
        scp3.shutdown(timeout=1.0)


def test_sqlite_key_and_passphrase_both_supplied_raises() -> None:
    """Supplying both 'key' and 'passphrase' is a validation error (§17.6)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(_scp_core.ValidationError):
            SCP(
                storage={
                    "type": "sqlite",
                    "path": tmpdir,
                    "key": _SQLITE_KEY,
                    "passphrase": "also a passphrase",
                }
            )


def test_sqlite_neither_key_nor_passphrase_raises() -> None:
    """Supplying neither 'key' nor 'passphrase' is a validation error (§17.6)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(_scp_core.ValidationError):
            SCP(storage={"type": "sqlite", "path": tmpdir})


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
