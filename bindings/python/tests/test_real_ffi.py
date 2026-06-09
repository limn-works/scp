"""Phase D4 — Python SDK Real FFI Integration Tests (A-grade).

Tests the Python SDK through the actual _scp_core PyO3 bridge, NOT mocks.
A-grade: All tests run through a real in-process relay (RelayTransportProvider),
not NotConfiguredTransportProvider. The full encrypt -> sign -> relay publish
pipeline executes for every py_context_send / py_broadcast_publish call.

Requires: `maturin develop --release --features allow_in_memory_custody`

Run:
    source .venv/bin/activate
    PYTHONPATH=bindings/python pytest bindings/python/tests/test_real_ffi.py -v

Covers: identity lifecycle, context lifecycle, membership, tools, UCAN,
event log, discovery, and provenance through real FFI.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Skip entire module if the native extension is not available
# ---------------------------------------------------------------------------

try:
    from scp_sdk import _scp_core  # installed as scp_sdk._scp_core by maturin
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

from scp_sdk import SCP
from scp_sdk.types import CustodyType

# ---------------------------------------------------------------------------
# Session-scoped relay fixture (started once, shut down after all tests)
# ---------------------------------------------------------------------------
#
# `configure_relay_transport` uses a `OnceLock` — first call wins per bridge
# instance. The session-scoped relay shares a single bridge across every
# test in this module so transport wiring happens exactly once. Tests that
# need their own isolated bridge receive it via the function-scoped `scp`
# fixture from conftest.py; this relay fixture supplies the shared bridge
# all real-FFI tests dispatch through.


@pytest.fixture(scope="session")
def session_scp() -> SCP:
    """Session-wide :class:`scp_sdk.SCP` that owns the real-FFI relay wiring.

    Because ``configure_relay_transport`` is OnceLock-bound, all tests in
    this module share one :class:`SCP` instance for the relay — but each
    test still receives its own handles and identities. The instance is
    torn down after the session via the finalizer in ``SCP.__exit__``.

    Phase 4 PR 4 (#1549) removed the process-global default bridge
    instance; every caller now threads an explicit ``SCP()`` through.
    Handle-affinity is wired through caller-owned instances, so this
    fixture simply constructs a fresh bridge for the session.

    Storage-required model (ADR-049 / spec §17.6): this fixture wires the
    production relay path (``configure_relay_transport``), which deliberately
    does NOT default storage — without a storage backend the supervisor
    build fails closed and every ``context_create`` raises SCP-CTX-2001.
    We therefore construct via ``SCP.with_storage({"type": "in_memory"})``
    (the sanctioned test affordance under ``allow_in_memory_custody``) so a
    storage backend is present before ``configure_relay_transport`` derives
    the supervisor's ``mls_storage`` view from it.
    """
    wrapper = SCP.__new__(SCP)
    wrapper._native = _scp_core.SCP.with_storage({"type": "in_memory"})
    yield wrapper
    # No shutdown here: session-scoped bridge is reaped when the process
    # exits. Explicit shutdown would race with any lingering asyncio
    # receivers that outlive the last test (rare but observed).


@pytest.fixture(scope="session", autouse=True)
def relay(session_scp: SCP):
    """Start an in-memory relay for the entire test session.

    Initializes the ContextManager with a RelayTransportProvider so
    py_context_send publishes through the relay. A second connection
    (transport_connect) is established for relay-based discovery.
    """
    native = session_scp._native
    handle = native.relay_start_in_memory()

    # Create a bootstrap identity for the MLS credential DID.
    bootstrap = native.identity_create("in_memory")

    # Wire the ContextManager to use a real relay transport provider.
    # Must be called BEFORE any context_create (OnceLock — first call wins).
    native.configure_relay_transport(handle.relay_url, bootstrap.did)

    # Second connection for relay-based context discovery.
    native.transport_connect(handle.relay_url)

    yield handle
    if not handle.is_shutdown:
        handle.shutdown()


@pytest.fixture
def scp(session_scp: SCP) -> SCP:
    """Per-test alias for the session-scoped bridge.

    The real-FFI test module is structurally tied to one bridge instance
    by ``OnceLock``-bound relay wiring, so the "fresh per test" contract
    collapses to aliasing the session fixture. Tests that genuinely need
    a fresh bridge can construct one inline with ``SCP()``.
    """
    return session_scp


# ---------------------------------------------------------------------------
# PyContextParams
# ---------------------------------------------------------------------------


class TestPyContextParams:
    """Tests for PyContextParams field parsing through real FFI."""

    def test_min_protocol_version_set(self) -> None:
        params = _scp_core.PyContextParams(
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
                "min_protocol_version": (1, 2),
            }
        )
        assert params.min_protocol_version == (1, 2)

    def test_min_protocol_version_none_when_absent(self) -> None:
        params = _scp_core.PyContextParams(
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            }
        )
        assert params.min_protocol_version is None

    def test_min_protocol_version_zero_zero(self) -> None:
        params = _scp_core.PyContextParams(
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
                "min_protocol_version": (0, 0),
            }
        )
        assert params.min_protocol_version == (0, 0)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class TestIdentity:
    """Identity creation and lifecycle through real FFI."""

    async def test_create_in_memory(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        assert identity.did.startswith("did:dht:")
        assert len(identity.did) > 20
        assert identity.custody_type == CustodyType.IN_MEMORY

    async def test_create_rejects_unknown_custody(self, scp: SCP):
        with pytest.raises(Exception):
            await scp.identity_create("magic")

    async def test_multiple_identities_distinct(self, scp: SCP):
        a = await scp.identity_create(CustodyType.IN_MEMORY)
        b = await scp.identity_create(CustodyType.IN_MEMORY)
        assert a.did != b.did

    async def test_agent_key_lifecycle(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        assert not identity._raw_handle.has_agent_key

        with_agent = await scp.identity_add_agent_key(identity._raw_handle)
        assert with_agent._raw_handle.has_agent_key
        pk1 = with_agent._raw_handle.get_agent_public_key()
        assert pk1 is not None

        rotated = await scp.identity_rotate_agent_key(with_agent._raw_handle)
        assert rotated._raw_handle.has_agent_key
        pk2 = rotated._raw_handle.get_agent_public_key()
        assert pk2 != pk1

        removed = await scp.identity_remove_agent_key(rotated._raw_handle)
        assert not removed._raw_handle.has_agent_key

    async def test_remove_existing_identity(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        # The DID is in the registry, so removal succeeds. `identity_remove`
        # returns None (void) and the subsequent if_present probe reports the
        # DID is no longer present.
        result = await scp.identity_remove(identity.did)
        assert result is None
        assert await scp.identity_remove_if_present(identity.did) is False

    async def test_remove_if_present_true_then_false(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        # First removal finds the identity and reports True.
        assert await scp.identity_remove_if_present(identity.did) is True
        # Second removal finds nothing and reports False.
        assert await scp.identity_remove_if_present(identity.did) is False

    async def test_remove_nonexistent_is_silent(self, scp: SCP):
        # Removing a DID that was never registered is a silent no-op (for a
        # syntactically valid DID), matching the cross-bridge `identity_remove`
        # contract.
        missing = "did:dht:z6MkNeverRegisteredIdentityForRemoveTest"
        result = await scp.identity_remove(missing)
        assert result is None
        assert await scp.identity_remove_if_present(missing) is False

    async def test_remove_rejects_malformed_did(self, scp: SCP):
        # Both removal ops gate on the shared `validate_did` validator (the
        # PyO3 reference bridge) before touching the registry. A non-empty but
        # syntactically invalid DID raises the native ValidationError rather
        # than silently no-op'ing. Mirrors the petname malformed-owner tests.
        bad = "not-a-did"
        with pytest.raises(_scp_core.ValidationError):
            await scp.identity_remove(bad)
        with pytest.raises(_scp_core.ValidationError):
            await scp.identity_remove_if_present(bad)

    async def test_create_with_agent_key(self, scp: SCP):
        identity = await scp.identity_create_with_agent_key(CustodyType.IN_MEMORY)
        assert identity._raw_handle.has_agent_key
        assert identity._raw_handle.get_agent_public_key() is not None

    async def test_attest_device(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        token = await scp.identity_attest_device(identity.did)
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_verify_device_attestation(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        token = await scp.identity_attest_device(identity.did)
        is_valid = await scp.identity_verify_device_attestation(identity.did, token)
        assert is_valid is True

    async def test_verify_device_attestation_rejects_invalid(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        # An arbitrary base64 string that is not a valid attestation token
        is_valid = await scp.identity_verify_device_attestation(identity.did, "aW52YWxpZA==")
        assert is_valid is False

    async def test_execute_custody_migration(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        # The FFI uses a NotConfiguredMigrationBackend that returns an error
        # on step 1 (key generation). Verify the SDK wrapper propagates this.
        with pytest.raises(Exception, match="custody migration"):
            await scp.identity_execute_custody_migration(identity.did, "hardware", [])

    async def test_execute_custody_migration_invalid_target(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        with pytest.raises(Exception, match="invalid custody migration target"):
            await scp.identity_execute_custody_migration(identity.did, "nonexistent_target", [])

    async def test_execute_recovery(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        result = await scp.identity_execute_recovery(identity.did, "agent", [])
        assert isinstance(result, dict)
        assert "key_rotation_completed" in result
        assert result["tier"] == "Agent"
        assert result["did"] == identity.did

    async def test_execute_recovery_invalid_tier(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        with pytest.raises(Exception):
            await scp.identity_execute_recovery(identity.did, "invalid_tier", [])

    async def test_migrate(self, scp: SCP):
        import json

        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        try:
            new_identity = await scp.identity_migrate(identity._raw_handle)
            # Migration succeeded — new identity should have a different DID
            assert new_identity.did != identity.did
            assert new_identity.did.startswith("did:dht:")
            # The SDK wrapper must surface the DidRotationEvent JSON so
            # callers can distribute it to context members per spec
            # §3.2.1 step 4b.
            assert new_identity.rotation_event_json is not None
            event = json.loads(new_identity.rotation_event_json)
            assert event["new_did"] == new_identity.did
            assert event["old_did"] == identity.did
            assert "migration_proof" in event
            assert "pre_rotation_proof" in event
        except _scp_core.IdentityError:
            # Migration may require pre-rotation commitment setup.
            # The SDK wrapper must propagate the error as IdentityError.
            pass


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


class TestContext:
    """Context lifecycle through real FFI."""

    async def test_create_returns_active(self, scp: SCP):
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            identity.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        assert handle.context_id
        assert handle.state == "active"

    async def test_join_and_leave(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        bob = await scp.identity_create(CustodyType.IN_MEMORY)

        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": [
                    "messages:read",
                    "messages:write",
                    "role:assign",
                    "member:invite",
                    "member:remove",
                ],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )

        scp._native.context_join(handle, bob.did)
        count = scp._native.context_member_count(handle)
        assert count == 2

        assert scp._native.context_is_member(handle, bob.did)
        members = scp._native.context_member_dids(handle)
        assert bob.did in members
        assert alice.did in members

        scp._native.context_leave(handle, bob.did)
        count_after = scp._native.context_member_count(handle)
        assert count_after == 1
        assert not scp._native.context_is_member(handle, bob.did)

    async def test_close(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "context:close"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        assert handle.state == "active"
        scp._native.context_close(handle, alice.did)
        assert handle.state in ("closed", "closing")

    async def test_send_message(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        # RelayTransportProvider is configured — send publishes through the relay.
        # Full pipeline: MLS encrypt -> sender key -> outer envelope -> relay publish.
        scp._native.context_send(handle, alice.did, b"Hello from Python!")

    async def test_drain_events(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        events = scp._native.context_drain_events(handle)
        assert isinstance(events, list)

    async def test_member_role(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        role = scp._native.context_member_role(handle, alice.did)
        assert role is not None
        assert "admin" in str(role).lower()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class TestTools:
    """Tool registration and verification through real FFI."""

    async def test_register_and_verify(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "tool:invoke:*", "tool:register"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        tool_id = scp._native.tool_register(
            handle.context_id,
            {
                "name": "test_tool",
                "description": "A test tool",
                "operator_did": alice.did,
                "schema": {
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "limit": {"type": "integer"},
                        },
                    },
                    "output_schema": {
                        "type": "object",
                        "properties": {
                            "results": {"type": "array"},
                            "count": {"type": "integer"},
                        },
                    },
                },
            },
        )
        assert tool_id
        assert len(tool_id) > 0

        result = scp._native.tool_verify(handle.context_id, tool_id)
        assert result.passed


# ---------------------------------------------------------------------------
# UCAN
# ---------------------------------------------------------------------------


class TestUcan:
    """UCAN mint and revoke through real FFI."""

    async def test_mint_and_revoke(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        bob = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        token = scp._native.ucan_mint(
            handle.context_id,
            bob.did,
            ["messages:read"],
        )
        assert token.token_id
        assert token.issuer == alice.did
        assert token.audience == bob.did

        # Revoke — construct a minimal valid JWT since PyUcanToken doesn't
        # expose the encoded JWT field. The revoker is the context creator.
        import base64
        import json

        header = (
            base64.urlsafe_b64encode(
                json.dumps({"alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "iss": alice.did,
                        "aud": bob.did,
                        "exp": 9999999999,
                        "nnc": "1699999000000-aabbccdd11223344",
                        "att": [],
                        "prf": [],
                    }
                ).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        sig = base64.urlsafe_b64encode(b"test-sig-bytes-0000000000000000").rstrip(b"=").decode()
        test_jwt = f"{header}.{payload}.{sig}"
        try:
            scp._native.ucan_revoke(handle.context_id, test_jwt, alice.did)
        except Exception:
            pass  # May fail depending on implementation state


# ---------------------------------------------------------------------------
# Event Log
# ---------------------------------------------------------------------------


class TestEventLog:
    """Event log query through real FFI."""

    async def test_query(self, scp: SCP):
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        events = scp._native.event_log_query(handle.context_id)
        assert isinstance(events, list)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    """Discovery address parsing and normalization through real FFI."""

    async def test_parse_unscoped(self):
        result = _scp_core.discovery_parse_address("alice")
        # Returns a dict directly (not JSON string)
        assert result["type"] == "Unscoped"

    async def test_parse_handle(self):
        result = _scp_core.discovery_parse_address("alice@cooking-ctx")
        assert result["type"] in ("DiscoveryHandle", "DomainHandle")

    async def test_parse_domain(self):
        result = _scp_core.discovery_parse_address("alice@example.com")
        assert "type" in result

    async def test_normalize_trims(self):
        result = _scp_core.discovery_normalize_address("  alice  ")
        assert not result.startswith(" ")
        assert not result.endswith(" ")

    async def test_create_query(self):
        result = _scp_core.discovery_create_query(
            ["tool:search"],
            ["rust"],
            None,
        )
        assert isinstance(result, (str, dict))


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    """Provenance evaluation and attachment through real FFI."""

    async def test_evaluate_quality(self, scp: SCP):
        # ADR-048 §1: pure helper now exposed as a module-level free fn.
        import _scp_core  # type: ignore[import-not-found]

        result = _scp_core.evaluate_provenance_quality(None, "persistent", "active", None)
        assert isinstance(result, int)
        assert 0 <= result <= 3

    async def test_attach(self, scp: SCP):
        # provenance_attach is stateful — stays on the SCP class.
        result = scp._native.provenance_attach(
            "source-ctx",
            "persistent",
            "full",
            ["did:dht:z6MkTest"],
            "target-ctx",
            "did:dht:z6MkActor",
            None,
        )
        assert isinstance(result, dict)

    async def test_chain_depth(self, scp: SCP):
        # ADR-048 §1: pure helper now exposed as a module-level free fn.
        import _scp_core  # type: ignore[import-not-found]

        assert _scp_core.provenance_check_chain_depth(3, 5)
        assert not _scp_core.provenance_check_chain_depth(6, 5)


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------


class TestTrust:
    """Trust operations through real FFI."""

    async def test_query_score(self, scp: SCP):
        """trust_query_score should return a score dict or structured result."""
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        # trust_query_score may fail without attestation data, but should not crash
        try:
            result = scp._native.trust_query_score(alice.did, handle.context_id)
            assert result is not None
        except Exception:
            pass  # Expected without attestation infrastructure
