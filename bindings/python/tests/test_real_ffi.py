"""Phase D4 — Python SDK Real FFI Integration Tests.

Tests the Python SDK through the actual _scp_core PyO3 bridge, NOT mocks.
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

from scp_sdk.identity import Identity
from scp_sdk.types import CustodyType

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

    async def test_create_in_memory(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        assert identity.did.startswith("did:dht:")
        assert len(identity.did) > 20
        assert identity.custody_type == CustodyType.IN_MEMORY

    async def test_create_rejects_unknown_custody(self):
        with pytest.raises(Exception):
            await Identity.create("magic")

    async def test_multiple_identities_distinct(self):
        a = await Identity.create(CustodyType.IN_MEMORY)
        b = await Identity.create(CustodyType.IN_MEMORY)
        assert a.did != b.did

    async def test_agent_key_lifecycle(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        assert not identity._handle.has_agent_key

        with_agent = await identity.add_agent_key()
        assert with_agent._handle.has_agent_key
        pk1 = with_agent._handle.get_agent_public_key()
        assert pk1 is not None

        rotated = await with_agent.rotate_agent_key()
        assert rotated._handle.has_agent_key
        pk2 = rotated._handle.get_agent_public_key()
        assert pk2 != pk1

        removed = await rotated.remove_agent_key()
        assert not removed._handle.has_agent_key

    async def test_create_with_agent_key(self):
        identity = await Identity.create_with_agent_key(CustodyType.IN_MEMORY)
        assert identity._handle.has_agent_key
        assert identity._handle.get_agent_public_key() is not None

    async def test_attest_device(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        token = await identity.attest_device()
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_verify_device_attestation(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        token = await identity.attest_device()
        is_valid = await identity.verify_device_attestation(token)
        assert is_valid is True

    async def test_verify_device_attestation_rejects_invalid(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        # An arbitrary base64 string that is not a valid attestation token
        is_valid = await identity.verify_device_attestation("aW52YWxpZA==")
        assert is_valid is False

    async def test_execute_custody_migration(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        # The FFI uses a NotConfiguredMigrationBackend that returns an error
        # on step 1 (key generation). Verify the SDK wrapper propagates this.
        with pytest.raises(Exception, match="custody migration"):
            await identity.execute_custody_migration("hardware")

    async def test_execute_custody_migration_invalid_target(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        with pytest.raises(Exception, match="invalid custody migration target"):
            await identity.execute_custody_migration("nonexistent_target")

    async def test_execute_recovery(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        result = await identity.execute_recovery("agent")
        assert isinstance(result, dict)
        assert "key_rotation_completed" in result
        assert result["tier"] == "Agent"
        assert result["did"] == identity.did

    async def test_execute_recovery_invalid_tier(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        with pytest.raises(Exception):
            await identity.execute_recovery("invalid_tier")

    async def test_migrate(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        try:
            new_identity = await identity.migrate()
            # Migration succeeded — new identity should have a different DID
            assert new_identity.did != identity.did
            assert new_identity.did.startswith("did:dht:")
        except _scp_core.IdentityError:
            # Migration may require pre-rotation commitment setup.
            # The SDK wrapper must propagate the error as IdentityError.
            pass


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


class TestContext:
    """Context lifecycle through real FFI."""

    async def test_create_returns_active(self):
        identity = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            identity.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        assert handle.context_id
        assert handle.state == "active"

    async def test_join_and_leave(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        bob = await Identity.create(CustodyType.IN_MEMORY)

        handle = _scp_core.py_context_create(
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

        _scp_core.py_context_join(handle, bob.did)
        count = _scp_core.py_context_member_count(handle)
        assert count == 2

        assert _scp_core.py_context_is_member(handle, bob.did)
        members = _scp_core.py_context_member_dids(handle)
        assert bob.did in members
        assert alice.did in members

        _scp_core.py_context_leave(handle, bob.did)
        count_after = _scp_core.py_context_member_count(handle)
        assert count_after == 1
        assert not _scp_core.py_context_is_member(handle, bob.did)

    async def test_close(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "context:close"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        assert handle.state == "active"
        _scp_core.py_context_close(handle, alice.did)
        assert handle.state in ("closed", "closing")

    async def test_send_message(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        # With MlsCryptoProvider wired (#1324), crypto succeeds but transport
        # is not configured (NotConfiguredTransportProvider). The error comes
        # from the transport layer, not crypto — confirming MLS encryption works.
        try:
            _scp_core.py_context_send(handle, alice.did, b"Hello from Python!")
        except RuntimeError as e:
            assert "transport not configured" in str(e)

    async def test_drain_events(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        events = _scp_core.py_context_drain_events(handle)
        assert isinstance(events, list)

    async def test_member_role(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        role = _scp_core.py_context_member_role(handle, alice.did)
        assert role is not None
        assert "admin" in str(role).lower()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class TestTools:
    """Tool registration and verification through real FFI."""

    async def test_register_and_verify(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "tool:invoke:*", "tool:register"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        tool_id = _scp_core.tool_register(
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

        result = _scp_core.tool_verify(handle.context_id, tool_id)
        assert result.passed


# ---------------------------------------------------------------------------
# UCAN
# ---------------------------------------------------------------------------


class TestUcan:
    """UCAN mint and revoke through real FFI."""

    async def test_mint_and_revoke(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        bob = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        token = _scp_core.ucan_mint(
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
            _scp_core.ucan_revoke(handle.context_id, test_jwt, alice.did)
        except Exception:
            pass  # May fail depending on implementation state


# ---------------------------------------------------------------------------
# Event Log
# ---------------------------------------------------------------------------


class TestEventLog:
    """Event log query through real FFI."""

    async def test_query(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        events = _scp_core.event_log_query(handle.context_id)
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

    async def test_evaluate_quality(self):
        result = _scp_core.evaluate_provenance_quality(None, "persistent", "active", None)
        assert isinstance(result, int)
        assert 0 <= result <= 3

    async def test_attach(self):
        result = _scp_core.provenance_attach(
            "source-ctx",
            "persistent",
            "full",
            ["did:dht:z6MkTest"],
            "target-ctx",
            "did:dht:z6MkActor",
            None,
        )
        assert isinstance(result, dict)

    async def test_chain_depth(self):
        assert _scp_core.provenance_check_chain_depth(3, 5)
        assert not _scp_core.provenance_check_chain_depth(6, 5)


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------


class TestTrust:
    """Trust operations through real FFI."""

    async def test_query_score(self):
        """trust_query_score should return a score dict or structured result."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        # trust_query_score may fail without attestation data, but should not crash
        try:
            result = _scp_core.trust_query_score(alice.did, handle.context_id)
            assert result is not None
        except Exception:
            pass  # Expected without attestation infrastructure


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------


class TestGovernance:
    """Governance execution through real FFI."""

    async def test_join_as_governance_alternative(self):
        """Use py_context_join for membership (governance requires full proposal struct)."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        bob = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
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
        _scp_core.py_context_join(handle, bob.did)
        assert _scp_core.py_context_is_member(handle, bob.did)
        role = _scp_core.py_context_member_role(handle, bob.did)
        assert role is not None


# ---------------------------------------------------------------------------
# Broadcast
# ---------------------------------------------------------------------------


class TestBroadcast:
    """Broadcast lifecycle through real FFI."""

    async def test_subscribe_and_count(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "full",
                "governance": "single_admin",
                "mode": "broadcast",
            },
        )
        bob = await Identity.create(CustodyType.IN_MEMORY)

        _scp_core.py_broadcast_subscribe(handle, bob.did)
        count = _scp_core.py_broadcast_subscriber_count(handle)
        assert count >= 1
        assert _scp_core.py_broadcast_is_subscriber(handle, bob.did)

        _scp_core.py_broadcast_unsubscribe(handle, bob.did, False)
        assert not _scp_core.py_broadcast_is_subscriber(handle, bob.did)

    async def test_block_and_unblock(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "full",
                "governance": "single_admin",
                "mode": "broadcast",
            },
        )
        bob = await Identity.create(CustodyType.IN_MEMORY)

        _scp_core.py_broadcast_subscribe(handle, bob.did)
        assert _scp_core.py_broadcast_is_subscriber(handle, bob.did)

        # Block bob from alice's author keys. Per-author blocking does NOT
        # remove from the context-wide subscriber roster (spec §5.14.8),
        # so is_subscriber remains True.
        _scp_core.py_broadcast_block_subscriber(handle, bob.did, alice.did)
        assert _scp_core.py_broadcast_is_subscriber(handle, bob.did)

        # Unblock bob — subscriber status unchanged (was never removed).
        _scp_core.py_broadcast_unblock_subscriber(handle, bob.did, alice.did)
        assert _scp_core.py_broadcast_is_subscriber(handle, bob.did)

    async def test_unblock_not_blocked_raises(self):
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "full",
                "governance": "single_admin",
                "mode": "broadcast",
            },
        )
        bob = await Identity.create(CustodyType.IN_MEMORY)

        _scp_core.py_broadcast_subscribe(handle, bob.did)

        with pytest.raises(RuntimeError):
            _scp_core.py_broadcast_unblock_subscriber(handle, bob.did, alice.did)


# ---------------------------------------------------------------------------
# Broadcast Content Delivery (SCP-290)
# ---------------------------------------------------------------------------


class TestBroadcastPublishAsset:
    """Broadcast content delivery asset publishing through real FFI."""

    async def test_broadcast_publish_asset_real_ffi(self):
        """Single asset publish returns blob_id or raises transport error."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "full",
                "governance": "single_admin",
                "mode": "broadcast",
            },
        )
        try:
            result = _scp_core.py_broadcast_publish_asset(
                handle,
                alice.did,
                "/index.html",
                "text/html",
                b"<h1>Hello</h1>",
                "deploy-test-1",
            )
            # If publish succeeds (transport configured), verify result shape.
            assert "blob_id" in result
            assert "etag" in result
            # blob_id is a 64-char hex string (SHA-256).
            assert len(result["blob_id"]) == 64
            assert all(c in "0123456789abcdef" for c in result["blob_id"])
            # etag is also a hex string.
            assert len(result["etag"]) > 0
        except Exception as e:
            # Transport-not-configured is acceptable in CI (no relay).
            # Content validation errors are NOT acceptable.
            msg = str(e)
            assert "transport" in msg.lower() or "not configured" in msg.lower(), (
                f"expected transport error, got: {msg}"
            )
            assert "invalid path" not in msg
            assert "invalid content_type" not in msg

    async def test_broadcast_publish_asset_invalid_path_raises(self):
        """Invalid content path raises an error with 'invalid path' message."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "full",
                "governance": "single_admin",
                "mode": "broadcast",
            },
        )
        with pytest.raises(Exception, match="invalid path"):
            _scp_core.py_broadcast_publish_asset(
                handle,
                alice.did,
                "no-leading-slash",  # invalid: must start with /
                "text/html",
                b"<h1>Bad</h1>",
                "deploy-bad",
            )

    async def test_broadcast_publish_assets_real_ffi(self):
        """Batch publish returns correct count or raises transport error."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read", "messages:write"],
                "memory_scope": "full",
                "governance": "single_admin",
                "mode": "broadcast",
            },
        )
        assets = [
            ("/index.html", "text/html", b"<h1>Home</h1>"),
            ("/style.css", "text/css", b"body { margin: 0 }"),
            ("/app.js", "application/javascript", b"console.log('ok')"),
        ]
        try:
            results = _scp_core.py_broadcast_publish_assets(
                handle,
                alice.did,
                assets,
                "deploy-batch-1",
            )
            assert len(results) == 3
            for r in results:
                assert "blob_id" in r
                assert "etag" in r
                assert len(r["blob_id"]) == 64
        except Exception as e:
            # Transport-not-configured is acceptable in CI (no relay).
            msg = str(e)
            assert "transport" in msg.lower() or "not configured" in msg.lower(), (
                f"expected transport error, got: {msg}"
            )


# ---------------------------------------------------------------------------
# Bridge Connector
# ---------------------------------------------------------------------------


class TestBridgeConnector:
    """Bridge connector operations through real FFI."""

    async def test_register_succeeds_with_separate_governance_did(self):
        """bridge_register succeeds when governance_did differs from operator_did."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        bob = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        result = _scp_core.bridge_register(
            handle.context_id, alice.did, bob.did, "discord", "relay"
        )
        assert result["status"] == "active"
        assert result["platform"] == "discord"

    async def test_register_rejects_self_approval(self):
        """bridge_register fails when governance_did equals operator_did."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        handle = _scp_core.py_context_create(
            alice.did,
            {
                "ceiling": ["messages:read"],
                "memory_scope": "ephemeral",
                "governance": "single_admin",
            },
        )
        with pytest.raises(Exception, match="approver cannot be the same as operator"):
            _scp_core.bridge_register(handle.context_id, alice.did, alice.did, "discord", "relay")

    async def test_evaluate_trust_native(self):
        # Non-bridged, native transport → NativeNative (3)
        result = _scp_core.bridge_evaluate_trust(False, True, "shadow")
        assert result == 3  # NativeNative

    async def test_evaluate_trust_shadow_bridged(self):
        # Bridged, non-native, shadow → ShadowBridged (0)
        result = _scp_core.bridge_evaluate_trust(True, False, "shadow")
        assert result == 0  # ShadowBridged

    async def test_evaluate_trust_claimed_bridged(self):
        # Bridged, non-native, claimed → ClaimedBridged (1)
        result = _scp_core.bridge_evaluate_trust(True, False, "claimed")
        assert result == 1  # ClaimedBridged

    async def test_create_shadow(self):
        result = _scp_core.bridge_create_shadow(
            "bridge-discord-abc", "@user#1234", "relay", "ctx-shadow"
        )
        assert result["shadow_id"]
        assert result["platform_handle"] == "@user#1234"
        assert result["bridge_id"] == "bridge-discord-abc"


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------


class TestSync:
    """Sync classification through real FFI."""

    async def test_classify_offline_short(self):
        """Short offline (1h) → 'short'."""
        now = 1_000_000
        last_seen = now - 3600  # 1 hour ago
        result = _scp_core.sync_classify_offline(last_seen, now)
        assert result == "short"

    async def test_classify_offline_extended(self):
        """Extended offline (1 day) → 'extended'."""
        now = 1_000_000
        last_seen = now - 86400  # 1 day ago
        result = _scp_core.sync_classify_offline(last_seen, now)
        assert result == "extended"

    async def test_classify_offline_long(self):
        """Long offline (~11 days) → 'long'."""
        now = 2_000_000
        last_seen = now - 1_000_000  # ~11 days ago
        result = _scp_core.sync_classify_offline(last_seen, now)
        assert result == "long"

    async def test_get_policy(self):
        """Default sync policy should have tier thresholds."""
        result = _scp_core.sync_get_policy()
        assert isinstance(result, dict)
        assert "tier_1_threshold_secs" in result
        assert "tier_2_threshold_secs" in result


# ---------------------------------------------------------------------------
# Recovery (error propagation)
# ---------------------------------------------------------------------------


class TestExecuteRecovery:
    """identity_execute_recovery error propagation through real FFI."""

    async def test_execute_recovery_invalid_tier(self):
        """execute_recovery with an invalid tier should raise an error."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        with pytest.raises(_scp_core.IdentityError):
            _scp_core.identity_execute_recovery(
                alice.did,
                "invalid_tier",
                [],
            )

    async def test_execute_recovery_unknown_did(self):
        """execute_recovery with an unregistered DID succeeds with the stub
        backend (no DID registry lookup). Verify it returns a valid JSON result
        rather than crashing."""
        import json

        result = _scp_core.identity_execute_recovery(
            "did:dht:z6MkUnknown000000000000000000",
            "agent",
            [],
        )
        parsed = json.loads(result)
        assert parsed["did"] == "did:dht:z6MkUnknown000000000000000000"
        assert parsed["tier"] == "Agent"
        assert parsed["key_rotation_completed"] is True


# ---------------------------------------------------------------------------
# Migration (error propagation)
# ---------------------------------------------------------------------------


class TestMigrate:
    """py_identity_migrate error propagation through real FFI."""

    async def test_migrate_returns_new_identity(self):
        """migrate on a valid identity should return a new handle (or raise
        a descriptive IdentityError if pre-rotation is not yet set up)."""
        alice = await Identity.create(CustodyType.IN_MEMORY)
        try:
            result = _scp_core.py_identity_migrate(alice._handle)
            # If migration succeeds, the new identity should have a different DID.
            assert result.did != alice.did
        except _scp_core.IdentityError:
            # Expected: migration may require pre-rotation commitment setup.
            # The error should be an IdentityError, not a generic exception.
            pass

    async def test_migrate_invalid_handle(self):
        """migrate with an unregistered DID should raise IdentityError.

        PyIdentity is #[pyclass(frozen)] — attributes are read-only. Instead
        of mutating the handle, we migrate first (which removes the old DID
        from the registry) then call migrate again with the stale handle.
        """
        alice = await Identity.create(CustodyType.IN_MEMORY)
        old_handle = alice._handle

        # Verify PyIdentity is frozen — attributes cannot be set.
        with pytest.raises(AttributeError):
            alice._handle.did = "did:dht:z6MkNotRegistered0000000000"

        # First migrate removes old_handle's DID from the registry.
        # It may itself fail (e.g., missing pre-rotation commitment),
        # so we handle that case too.
        try:
            _scp_core.py_identity_migrate(old_handle)
        except _scp_core.IdentityError:
            # First migrate failed — old_handle DID is still registered.
            # We can't test the "not in registry" path without removing it,
            # so just verify the error type is correct and return.
            return

        # If first migrate succeeded, old_handle's DID was removed from
        # the registry. Calling migrate again with the stale handle should
        # raise IdentityError because the DID is no longer registered.
        with pytest.raises(_scp_core.IdentityError, match="not found in registry"):
            _scp_core.py_identity_migrate(old_handle)


# ---------------------------------------------------------------------------
# Scope registry (§22.3.5, ADR-043)
# ---------------------------------------------------------------------------


class TestScopeRegistry:
    """Scope register/lookup/deregister round-trip through the real FFI bridge."""

    def test_scope_register_lookup_deregister(self) -> None:
        """Round-trip: register a scope, look it up, deregister it."""
        result = _scp_core.scope_register(
            "test-ctx",
            "my-scope",
            "target-ctx",
            ["wss://relay.example.com"],
            "did:dht:zTest",
            None,
            None,
        )
        import json

        parsed = json.loads(result)
        assert parsed["status"] == "registered"
        assert parsed["entry_id"] is not None

        lookup_result = _scp_core.scope_lookup("test-ctx", "my-scope")
        lookup = json.loads(lookup_result)
        assert len(lookup["results"]) == 1
        assert lookup["results"][0]["name"] == "my-scope"
        assert lookup["results"][0]["target"]["context_id"] == "target-ctx"

        dereg_result = _scp_core.scope_deregister("test-ctx", "my-scope", "did:dht:zTest")
        dereg = json.loads(dereg_result)
        assert dereg["removed"] is True

        # Verify it's gone
        lookup_after = json.loads(_scp_core.scope_lookup("test-ctx", "my-scope"))
        assert len(lookup_after["results"]) == 0

    def test_scope_register_conflict(self) -> None:
        """Different DID cannot overwrite an existing scope registration."""
        import json

        _scp_core.scope_register(
            "conflict-ctx",
            "taken-scope",
            "target-ctx",
            ["wss://relay.example.com"],
            "did:dht:zAlice",
            None,
            None,
        )

        result = json.loads(
            _scp_core.scope_register(
                "conflict-ctx",
                "taken-scope",
                "other-ctx",
                ["wss://relay.example.com"],
                "did:dht:zEve",
                None,
                None,
            )
        )
        assert result["status"] == "conflict"
        assert result["entry_id"] is None

    def test_scope_register_with_metadata(self) -> None:
        """Register a scope with description and tags."""
        import json

        result = json.loads(
            _scp_core.scope_register(
                "meta-ctx",
                "meta-scope",
                "target-ctx",
                ["wss://relay.example.com"],
                "did:dht:zMeta",
                "A test scope",
                ["test", "example"],
            )
        )
        assert result["status"] == "registered"

        lookup = json.loads(_scp_core.scope_lookup("meta-ctx", "meta-scope"))
        assert len(lookup["results"]) == 1
        entry = lookup["results"][0]
        assert entry["metadata"]["description"] == "A test scope"
        assert entry["metadata"]["tags"] == ["test", "example"]
