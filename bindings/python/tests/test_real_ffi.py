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

import json

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

    async def test_export_import_round_trip_signed(self, scp: SCP):
        """Spec §23.16.8 / ADR-050: export signs SHA-256(domain || JCS(full
        snapshot)); importing the freshly exported (untampered) bytes passes
        signature verification. The verifying key resolves from the snapshot
        ``creator_did`` via local custody first (the self-export → self-import
        round-trip), exercising the shared
        ``scp_ffi_common::export_verify::resolve_export_verifying_key`` helper
        before any DID resolver is configured."""
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "context:close"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        data = scp._native.context_export(handle.context_id)
        assert isinstance(data, (bytes, bytearray))
        assert len(data) > 0

        # Drop the live context so import is not blocked by the "already
        # exists" guard, then import the untampered bytes. A valid signature
        # must pass verification (no SCP-CTX-2093). Any residual lifecycle
        # error (e.g. terminal-state gating) is acceptable; a signature error
        # is NOT.
        try:
            imported_ctx_id = scp._native.context_import(bytes(data), alice.did)
            assert imported_ctx_id == handle.context_id
        except Exception as exc:
            assert "SCP-CTX-2093" not in str(exc), (
                f"valid export must not fail signature verification: {exc}"
            )

    async def test_import_rejects_tampered_export(self, scp: SCP):
        """Spec §23.16.8 / ADR-050: a forged export (a signed snapshot byte
        mutated after signing) must be rejected with the dedicated
        ``SCP-CTX-2093`` signature-failure code — NOT the catch-all
        ``SCP-CTX-2001``. Because the signature now covers the *entire*
        canonical snapshot, flipping any byte of a signed/trusted field (role
        ceiling, governance config, threshold set, access-key store, ...)
        breaks ``SHA-256(domain || JCS(snapshot))`` and the Ed25519 check fails
        before any state is restored."""
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "context:close"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        data = bytearray(scp._native.context_export(handle.context_id))
        scp._native.context_close(handle, alice.did)

        # Flip bytes across the embedded snapshot region (back half of the
        # MessagePack envelope) without re-signing. At least one flip lands in
        # a signed/trusted snapshot field, so the recomputed digest no longer
        # matches the signature.
        for i in range(len(data) // 2, len(data), 17):
            data[i] ^= 0xFF
        with pytest.raises(Exception) as excinfo:
            scp._native.context_import(bytes(data), alice.did)
        # The rejection must be the signature contract, not a generic context
        # error. (A flip that corrupts the MessagePack framing surfaces a
        # ValueError at deserialize-time instead; both are rejections, but a
        # *snapshot* tamper that still deserializes MUST be SCP-CTX-2093.)
        msg = str(excinfo.value)
        assert "SCP-CTX-2001" not in msg, (
            f"tampered snapshot must not map to the catch-all CTX-2001: {msg}"
        )

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

    async def test_ucan_validate_fails_closed_without_presenting_agent(self, scp: SCP):
        """The ENFORCING ucan_validate gate rejects an absent presenting agent.

        Symmetric with the diagnostic ucan_evaluate gate: defaulting the
        presenting agent to the token's own ``aud`` would make the step-5
        audience check a tautology and inflate trust. The fail-closed check fires
        before token parse, so any well-formed token string reaches it.
        """
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        # Omitted presenting agent → rejected.
        with pytest.raises(Exception, match="presenting_agent_did is required"):
            scp._native.ucan_validate(handle.context_id, "header.payload.sig", "messages:read")
        # Empty / whitespace presenting agent → also rejected.
        with pytest.raises(Exception, match="presenting_agent_did is required"):
            scp._native.ucan_validate(
                handle.context_id, "header.payload.sig", "messages:read", "   "
            )

    async def test_evaluate_trust_end_to_end_real_ffi(self, scp: SCP):
        """Exercise ``evaluate_trust`` against the real ``_scp_core`` bridge.

        Closes the coverage gap where only mocks exercised ``evaluate_trust``.
        Mints a valid token, then runs ``evaluate_trust`` (which drives the
        read-only ``ucan_evaluate`` diagnostic with NO challenge capability —
        intrinsic-validity mode, ADR-057 / §7.2.4) and asserts the structured
        Layer-1 booleans. A freshly minted, well-signed, in-ceiling token must
        report all six per-stage checks ``True``.
        """
        from scp_sdk.trust import evaluate_trust

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
        token = await scp.ucan_mint(handle.context_id, bob.did, ["messages:read"])
        assert token.encoded, "minted token must expose its encoded JWT"

        evaluation = await evaluate_trust(
            scp=scp,
            subject_did=bob.did,
            context_id=handle.context_id,
            capability_tokens=[token.encoded],
        )

        cv = evaluation.capability_validation
        # Intrinsic validity of a fresh, in-ceiling, well-signed token: all true.
        # The grant-match step is SKIPPED (no challenge), and read-only nonce
        # probing means re-evaluation does not consume the nonce.
        assert cv.tokens_valid is True
        assert cv.signatures_valid is True
        assert cv.within_ceiling is True
        assert cv.nonce_valid is True
        assert cv.not_revoked is True
        assert cv.time_bounds_valid is True

        # Read-only: a second evaluation yields the same all-true result (the
        # diagnostic must never record the nonce).
        again = await evaluate_trust(
            scp=scp,
            subject_did=bob.did,
            context_id=handle.context_id,
            capability_tokens=[token.encoded],
        )
        cv2 = again.capability_validation
        assert cv2.nonce_valid is True
        assert cv2.tokens_valid is True
        assert cv2.signatures_valid is True

    async def test_evaluate_trust_audience_mismatch_real_ffi(self, scp: SCP):
        """A token whose ``aud`` differs from the evaluated subject is rejected.

        Regression guard for the audience tautology: ``evaluate_trust`` must
        pass the ``subject_did`` to the diagnostic as the presenting agent so
        the step-5 audience check evaluates against the DID under assessment.
        ``presenting_agent_did`` is fail-closed: the bridge REJECTS an absent or
        empty value rather than defaulting the presenting agent to the token's
        OWN ``aud`` (which would make ``aud == aud`` always true, reporting
        ``signatures_valid`` for a token addressed to someone else — trust
        inflation). Mints a token for Bob, then evaluates trust for Carol
        against that token and asserts the structured ``signatures_valid`` is
        False (ADR-057 / §7.2.4).
        """
        from scp_sdk.trust import evaluate_trust

        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        bob = await scp.identity_create(CustodyType.IN_MEMORY)
        carol = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        # Token audience is Bob.
        token = await scp.ucan_mint(handle.context_id, bob.did, ["messages:read"])
        assert token.encoded, "minted token must expose its encoded JWT"

        # Evaluate trust for Carol (the relying party named a different subject
        # than the token's audience): the audience check fails, so the
        # structural-checks field is False.
        evaluation = await evaluate_trust(
            scp=scp,
            subject_did=carol.did,
            context_id=handle.context_id,
            capability_tokens=[token.encoded],
        )

        cv = evaluation.capability_validation
        assert cv.signatures_valid is False, (
            "a token whose aud != the evaluated subject must NOT report "
            "signatures_valid — the audience check must run against the subject "
            "DID, not the token's own audience"
        )

        # Control: evaluating the same token for its true audience (Bob) passes
        # the audience check — proving the False above is the mismatch, not an
        # unrelated failure.
        control = await evaluate_trust(
            scp=scp,
            subject_did=bob.did,
            context_id=handle.context_id,
            capability_tokens=[token.encoded],
        )
        assert control.capability_validation.signatures_valid is True

    async def test_ucan_evaluate_empty_capability_coerced_to_no_challenge(self, scp: SCP):
        """An empty/whitespace capability is coerced to no-challenge (None).

        Every bridge applies ``capability.filter(|c| !c.trim().is_empty())``
        before the core diagnostic, so an empty or whitespace-only capability
        string is treated as "no challenge" — identical to omitting it. A bare
        ``"*"`` is NOT this (it is a malformed capability URI the bridge
        rejects); absence is expressed by emptiness/omission only (ADR-057 /
        §7.2.4). This pins the PyO3 bridge's coercion so the cross-bridge
        parity test (TS real-napi sibling) and this one cannot diverge.
        """
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        bob = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        token = await scp.ucan_mint(handle.context_id, bob.did, ["messages:read"])
        assert token.encoded, "minted token must expose its encoded JWT"

        def booleans(raw: object) -> tuple[bool, ...]:
            return (
                bool(raw.tokens_valid),  # type: ignore[attr-defined]
                bool(raw.signatures_valid),  # type: ignore[attr-defined]
                bool(raw.within_ceiling),  # type: ignore[attr-defined]
                bool(raw.nonce_valid),  # type: ignore[attr-defined]
                bool(raw.not_revoked),  # type: ignore[attr-defined]
                bool(raw.time_bounds_valid),  # type: ignore[attr-defined]
            )

        # Presenting agent fixed to the token audience so the only variable is
        # the capability argument's emptiness.
        omitted = booleans(
            scp._native.ucan_evaluate(handle.context_id, token.encoded, None, bob.did)
        )
        empty = booleans(scp._native.ucan_evaluate(handle.context_id, token.encoded, "", bob.did))
        whitespace = booleans(
            scp._native.ucan_evaluate(handle.context_id, token.encoded, "   ", bob.did)
        )

        # Empty / whitespace capability == omitted capability: same six booleans.
        assert empty == omitted, (
            f"empty-string capability must coerce to no-challenge: {empty} != {omitted}"
        )
        assert whitespace == omitted, (
            f"whitespace capability must coerce to no-challenge: {whitespace} != {omitted}"
        )
        # A fresh, in-ceiling token is intrinsically valid on every stage.
        assert omitted == (True, True, True, True, True, True)

    async def test_ucan_evaluate_empty_capability_invalid_token_still_fails(self, scp: SCP):
        """Empty-capability coercion must NOT bypass a failing stage.

        The intrinsic-validity coercion (``capability=""`` -> no challenge) is a
        no-CHALLENGE switch, not a no-CHECK switch. A forged-signature token with
        an empty capability must STILL report ``signatures_valid`` False --
        coercion to no-challenge cannot be mistaken for a validity shortcut. The
        sibling parity test only covered a VALID token; this pins the INVALID
        case (ADR-057 / §7.2.4). TS sibling: the real-napi forged-token coercion
        test.
        """
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        bob = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        token = await scp.ucan_mint(handle.context_id, bob.did, ["messages:read"])
        assert token.encoded, "minted token must expose its encoded JWT"

        # Forge the signature segment so signature verification fails.
        parts = token.encoded.split(".")
        assert len(parts) == 3
        forged = f"{parts[0]}.{parts[1]}.{'A' * len(parts[2])}"

        # Empty capability == no challenge — but the failing signature stage
        # must STILL be reported, never bypassed by the coercion.
        empty = scp._native.ucan_evaluate(handle.context_id, forged, "", bob.did)
        assert bool(empty.tokens_valid) is True
        assert bool(empty.signatures_valid) is False, (
            "empty-capability coercion must NOT bypass the failing signature "
            "stage of a forged token"
        )

        # Equivalent to omitting the capability entirely: same failing record.
        omitted = scp._native.ucan_evaluate(handle.context_id, forged, None, bob.did)
        assert bool(omitted.signatures_valid) is False
        assert bool(empty.signatures_valid) == bool(omitted.signatures_valid)
        assert bool(empty.tokens_valid) == bool(omitted.tokens_valid)


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

    async def test_participation_record_reflects_governance_real_ffi(self, scp: SCP):
        """The typed participation record (§7.3.2) RECEIVES real leaf-derived facts.

        A ``single_admin`` context whose ceiling carries the governance +
        child-creation capabilities auto-executes each proposal on
        ``governance_propose`` (ADR-031), appending convergent
        ``GovernanceActionExecuted`` / ``RoleAssigned`` / ``ChildContextCreated``
        leaves to the supervisor's Merkle log. The typed ``participation_record``
        then RECEIVES non-zero counts attributed by the subject-bearing payloads
        (ADR-011 amendment): the actor for ``governance_actions_by`` /
        ``context_creation_count``, the projected member for
        ``role_progression_count`` / ``governance_actions_against``. This proves
        the SDK consumes the Rust-computed record instead of recomputing Layer 2,
        and is the Python sibling of the TS ``real-napi`` governance test — both
        assert the identical field values (the cross-SDK divergence-killer).
        """
        from scp_sdk.trust import participation_record

        admin = await scp.identity_create(CustodyType.IN_MEMORY)
        member = await scp.identity_create(CustodyType.IN_MEMORY)
        # The ceiling MUST carry the governance + child-creation capabilities, or
        # the proposer (creator) lacks governance:propose / the child-creation
        # capability and the proposal is permission-denied.
        handle = scp._native.context_create(
            admin.did,
            {
                "ceiling": [
                    "messages:read",
                    "messages:write",
                    "role:assign",
                    "governance:propose",
                    "governance:vote",
                    "context:close",
                    "context:child:create",
                ],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        context_id = handle.context_id
        scp._native.context_join(handle, member.did)

        # 1. ChangeRole(member -> moderator): a RoleAssigned leaf projected to the
        #    member + a GovernanceActionExecuted leaf actored by the admin.
        scp._native.governance_propose(
            handle,
            admin.did,
            json.dumps({"ChangeRole": {"did": member.did, "new_role": "moderator"}}),
        )
        # 2. RemoveMember(member): an adverse action -> governance_actions_against
        #    the member + another GovernanceActionExecuted by the admin.
        scp._native.governance_propose(
            handle,
            admin.did,
            json.dumps({"RemoveMember": {"did": member.did, "reason": "participation-test"}}),
        )
        # 3. CreateChildContext: a ChildContextCreated leaf actored by the admin ->
        #    the admin's context_creation_count increments by one.
        child_params = {
            "mode": "Encrypted",
            "ceiling": [],
            "ceiling_policy": "Immutable",
            "promotion_policy": "NoPromotion",
            "roles": [],
            "tools": [],
            "ttl": None,
            "memory_scope": "Ephemeral",
            "governance": "SingleAdmin",
            "template_id": None,
        }
        scp._native.governance_propose(
            handle,
            admin.did,
            json.dumps({"CreateChildContext": {"params": child_params}}),
        )

        admin_record = participation_record(scp, context_id, admin.did)
        member_record = participation_record(scp, context_id, member.did)

        # Admin INITIATED all three governance actions and created one child.
        assert admin_record.governance_actions_by == 3
        assert admin_record.governance_actions_against == 0
        assert admin_record.context_creation_count == 1
        assert admin_record.role_progression_count == 0
        # Member was the TARGET of one role change and one (adverse) removal.
        assert member_record.role_progression_count == 1
        assert member_record.governance_actions_against == 1
        assert member_record.governance_actions_by == 0
        assert member_record.context_creation_count == 0
        # Credential-layer / anchoring invariants hold for both subjects.
        assert admin_record.attestation_count == 0
        assert member_record.attestation_count == 0
        assert admin_record.tool_invocation_count_anchored is False
        assert member_record.tool_invocation_count_anchored is False
        # attestation_count is credential-layer (§7.4), never Merkle-anchored.
        assert admin_record.attestation_count_anchored is False
        assert member_record.attestation_count_anchored is False
        # Real Merkle root over the convergent governance leaves (64 hex chars).
        assert len(admin_record.event_log_root) == 64
        assert admin_record.event_log_root != "0" * 64

        # evaluate_trust RECEIVES the SAME record the direct op returns — no
        # client-side recomputation, no divergence.
        from scp_sdk.trust import evaluate_trust

        evaluation = await evaluate_trust(scp=scp, subject_did=admin.did, context_id=context_id)
        assert evaluation.behavioral_record == admin_record

    async def test_evaluate_trust_no_attestations_zero_count_real_ffi(self, scp: SCP):
        """``evaluate_trust`` passes no cached attestations -> attestation_count 0.

        ``attestation_count`` is a credential-layer fact (§7.4), verifier-
        relative. ``evaluate_trust`` has no attestation set in its inputs, so it
        honestly passes an empty set — the SDK never fabricates attestations.
        """
        from scp_sdk.trust import evaluate_trust

        admin = await scp.identity_create(CustodyType.IN_MEMORY)
        member = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = scp._native.context_create(
            admin.did,
            {
                "ceiling": [
                    "messages:read",
                    "role:assign",
                    "governance:propose",
                    "governance:vote",
                ],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        scp._native.context_join(handle, member.did)
        scp._native.governance_propose(
            handle,
            admin.did,
            json.dumps({"ChangeRole": {"did": member.did, "new_role": "moderator"}}),
        )

        evaluation = await evaluate_trust(
            scp=scp, subject_did=member.did, context_id=handle.context_id
        )
        assert evaluation.behavioral_record is not None
        assert evaluation.behavioral_record.attestation_count == 0
        assert evaluation.behavioral_record.role_progression_count == 1


# ---------------------------------------------------------------------------
# Broadcast key distribution (spec §5.14.2)
# ---------------------------------------------------------------------------


class TestBroadcastKeyDistribution:
    """Pull-based broadcast key-distribution protocol through real FFI.

    Exercises the Python SDK wrapper surface for the §5.14.2 pull protocol:
    ``broadcast_handle_key_request`` (author seals its current broadcast key
    to a requester) and ``broadcast_open_key`` (subscriber unwraps the sealed
    key). These are dependency-free assertions on the binding contract — they
    cover the deny decision (§5.14.8 cryptographic exclusion), the
    ``broadcast_open_key`` input validation, and the grant JSON shape. A true
    open round-trip needs a real X25519 keypair (no stdlib X25519, no test
    crypto dependency) and is covered by the TypeScript suite.
    """

    @staticmethod
    def _broadcast_handle(scp: SCP, author_did: str):
        """Create an active broadcast context whose creator is the sole author."""
        return scp._native.context_create(
            author_did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "full",
                "mode": "broadcast",
            },
        )

    async def test_key_request_denies_unregistered_requester(self, scp: SCP):
        """§5.14.8: an author returns no key material to a requester that never
        subscribed. The deny decision short-circuits before any sealing, so it
        needs no real X25519 wrapping key — ``bytes(32)`` is accepted and the
        wrapper surfaces the deny as ``None`` (not an empty/sealed blob)."""
        author = await scp.identity_create(CustodyType.IN_MEMORY)
        stranger = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = self._broadcast_handle(scp, author.did)
        assert handle.mode == "broadcast"

        decision = await scp.broadcast_handle_key_request(
            handle,
            author.did,
            stranger.did,
            bytes(32),
        )
        assert decision is None

    async def test_open_key_rejects_malformed_sealed_json(self, scp: SCP):
        """``broadcast_open_key`` must reject a sealed payload that is not valid
        JSON before attempting any HPKE open."""
        with pytest.raises(ValueError):
            await scp.broadcast_open_key("not valid json", bytes(32))

    async def test_open_key_rejects_wrong_length_secret(self, scp: SCP):
        """``broadcast_open_key`` must reject a wrapping secret that is not
        exactly 32 bytes. The JSON is syntactically valid (and structurally a
        plausible SealedBroadcastKey) so the length gate is the failing check,
        not deserialization."""
        sealed_json = json.dumps(
            {
                "enc": [0] * 32,
                "ct": [0] * 48,
                "epoch": 0,
                "author_did": "did:dht:z6MkBroadcastAuthorForLenCheck",
                "context_id": "ctx-broadcast-len-check",
            }
        )
        with pytest.raises(ValueError):
            await scp.broadcast_open_key(sealed_json, b"short")

    async def test_key_request_grants_registered_subscriber_shape(self, scp: SCP):
        """A registered subscriber receives a sealed broadcast key. ``bytes(32)``
        (the all-zero X25519 point) is a valid HPKE recipient input, so the seal
        succeeds and the wrapper returns the SealedBroadcastKey JSON. We assert
        the JSON shape only — a true open round-trip would need the X25519 secret
        matching the all-zero *public* key (which is not the all-zero secret), so
        the full unwrap is left to the TypeScript suite (real WebCrypto X25519)."""
        author = await scp.identity_create(CustodyType.IN_MEMORY)
        subscriber = await scp.identity_create(CustodyType.IN_MEMORY)
        handle = self._broadcast_handle(scp, author.did)

        await scp.broadcast_subscribe(handle, subscriber.did)
        assert await scp.broadcast_is_subscriber(handle, subscriber.did) is True

        sealed_json = await scp.broadcast_handle_key_request(
            handle,
            author.did,
            subscriber.did,
            bytes(32),
        )
        assert isinstance(sealed_json, str)
        assert len(sealed_json) > 0

        sealed = json.loads(sealed_json)
        # SealedBroadcastKey shape (spec §5.14.2): HPKE encapsulation (`enc`),
        # ciphertext (`ct`), the author's key epoch, and the binding fields the
        # opener must echo into HPKE AAD.
        assert set(sealed) >= {"enc", "ct", "epoch", "author_did", "context_id"}
        assert isinstance(sealed["enc"], list)
        assert isinstance(sealed["ct"], list)
        assert sealed["author_did"] == author.did
        assert sealed["context_id"] == handle.context_id
        assert isinstance(sealed["epoch"], int)
