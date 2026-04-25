"""Tests for SCP Python SDK dataclasses, exceptions, and types.

Covers:
- Exception hierarchy (ScpError and all subclasses)
- Message and Provenance dataclasses
- OutletDefinition and TestVector dataclasses (outlet module)
- Enums (MemoryScope, SourceType, DiscoveryMethod, ProvenanceQuality, Capability)
- Bridge error mapping

See ``.docs/standards/python.md`` for test naming conventions.
"""

from __future__ import annotations

import scp_sdk
from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    ContextError,
    CryptoError,
    IdentityError,
    OutletError,
    ScpError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.outlets import OutletDefinition, OutletKind, TestVector
from scp_sdk.types import (
    Capability,
    CeilingPolicy,
    ContextMode,
    DiscoveryMethod,
    MemoryScope,
    Message,
    PromotionPolicy,
    Provenance,
    ProvenanceQuality,
    SourceType,
)

# -----------------------------------------------------------------------
# Exception hierarchy tests
# -----------------------------------------------------------------------


class TestScpErrorBase:
    """Tests for the base ScpError class."""

    def test_scp_error_has_message_and_default_code(self) -> None:
        err = ScpError("something broke")
        assert err.message == "something broke"
        assert err.code == "SCP-UNKNOWN-0000"

    def test_scp_error_with_custom_code(self) -> None:
        err = ScpError("bad input", code="SCP-CTX-2999")
        assert err.message == "bad input"
        assert err.code == "SCP-CTX-2999"

    def test_scp_error_str_includes_code_and_message(self) -> None:
        err = ScpError("oops", code="SCP-IDENT-1234")
        assert str(err) == "[SCP-IDENT-1234] oops"

    def test_scp_error_repr(self) -> None:
        err = ScpError("fail")
        r = repr(err)
        assert "ScpError" in r
        assert "fail" in r
        assert "SCP-UNKNOWN-0000" in r

    def test_scp_error_is_exception(self) -> None:
        assert issubclass(ScpError, Exception)

    def test_scp_error_catchable_as_exception(self) -> None:
        try:
            raise ScpError("test")
        except Exception as exc:
            assert isinstance(exc, ScpError)


class TestExceptionSubclasses:
    """Tests for each ScpError subclass."""

    def test_identity_error_is_scp_error(self) -> None:
        err = IdentityError("DID resolution failed")
        assert isinstance(err, ScpError)
        assert isinstance(err, IdentityError)

    def test_identity_error_default_code(self) -> None:
        err = IdentityError("fail")
        assert err.code == "SCP-IDENT-1000"

    def test_identity_error_custom_code(self) -> None:
        err = IdentityError("key rotation failed", code="SCP-IDENT-1042")
        assert err.code == "SCP-IDENT-1042"

    def test_context_error_is_scp_error(self) -> None:
        err = ContextError("context already closed")
        assert isinstance(err, ScpError)

    def test_context_error_default_code(self) -> None:
        assert ContextError("x").code == "SCP-CTX-2000"

    def test_ucan_permission_error_is_scp_error(self) -> None:
        err = UcanPermissionError("capability denied")
        assert isinstance(err, ScpError)

    def test_ucan_permission_error_default_code(self) -> None:
        assert UcanPermissionError("x").code == "SCP-PERM-3000"

    def test_ucan_permission_error_does_not_shadow_builtin(self) -> None:
        """UcanPermissionError must NOT be the same as builtins.PermissionError."""
        assert UcanPermissionError is not PermissionError
        err = UcanPermissionError("denied")
        assert not isinstance(err, PermissionError)

    def test_crypto_error_is_scp_error(self) -> None:
        err = CryptoError("decryption failed")
        assert isinstance(err, ScpError)

    def test_crypto_error_default_code(self) -> None:
        assert CryptoError("x").code == "SCP-CRYPTO-4000"

    def test_transport_error_is_scp_error(self) -> None:
        err = TransportError("connection refused")
        assert isinstance(err, ScpError)

    def test_transport_error_default_code(self) -> None:
        assert TransportError("x").code == "SCP-TRANS-5000"

    def test_outlet_error_is_scp_error(self) -> None:
        err = OutletError("outlet not found")
        assert isinstance(err, ScpError)

    def test_outlet_error_default_code(self) -> None:
        assert OutletError("x").code == "SCP-TOOL-6000"

    def test_validation_error_is_scp_error(self) -> None:
        err = ValidationError("schema mismatch")
        assert isinstance(err, ScpError)

    def test_validation_error_default_code(self) -> None:
        assert ValidationError("x").code == "SCP-VALID-7000"

    def test_all_subclasses_are_catchable_as_scp_error(self) -> None:
        subclasses = [
            IdentityError,
            ContextError,
            UcanPermissionError,
            CryptoError,
            TransportError,
            OutletError,
            ValidationError,
        ]
        for cls in subclasses:
            try:
                raise cls("test")
            except ScpError as exc:
                assert isinstance(exc, cls)


class TestBridgeErrorMap:
    """Tests for the bridge error variant mapping."""

    def test_bridge_map_covers_all_variants(self) -> None:
        expected_keys = {
            "IdentityError",
            "ContextError",
            "UcanError",
            "CryptoError",
            "TransportError",
            "ToolError",
            "OutletError",
            "ValidationError",
        }
        assert set(BRIDGE_ERROR_MAP.keys()) == expected_keys

    def test_bridge_map_values_are_scp_error_subclasses(self) -> None:
        for cls in BRIDGE_ERROR_MAP.values():
            assert issubclass(cls, ScpError)

    def test_bridge_map_ucan_error_maps_to_ucan_permission_error(self) -> None:
        assert BRIDGE_ERROR_MAP["UcanError"] is UcanPermissionError


# -----------------------------------------------------------------------
# Message dataclass tests
# -----------------------------------------------------------------------


class TestMessage:
    """Tests for the Message dataclass."""

    def test_message_required_fields(self) -> None:
        msg = Message(
            sender_did="did:dht:z6MkAlice",
            content="hello",
            timestamp=1700000000.0,
            sequence=1,
            context_id="ctx-abc-123",
        )
        assert msg.sender_did == "did:dht:z6MkAlice"
        assert msg.content == "hello"
        assert msg.timestamp == 1700000000.0
        assert msg.sequence == 1
        assert msg.context_id == "ctx-abc-123"
        assert msg.provenance is None

    def test_message_with_bytes_content(self) -> None:
        msg = Message(
            sender_did="did:dht:z6MkBob",
            content=b"\x00\x01\x02",
            timestamp=1700000001.0,
            sequence=2,
            context_id="ctx-def-456",
        )
        assert isinstance(msg.content, bytes)
        assert msg.content == b"\x00\x01\x02"

    def test_message_with_provenance(self) -> None:
        prov = Provenance(
            source_context="ctx-origin",
            source_type=SourceType.PERSISTENT,
        )
        msg = Message(
            sender_did="did:dht:z6MkCharlie",
            content="cross-context data",
            timestamp=1700000002.0,
            sequence=3,
            context_id="ctx-target",
            provenance=prov,
        )
        assert msg.provenance is not None
        assert msg.provenance.source_context == "ctx-origin"

    def test_message_equality(self) -> None:
        kwargs = dict(
            sender_did="did:dht:z6MkAlice",
            content="hi",
            timestamp=1.0,
            sequence=0,
            context_id="ctx",
        )
        assert Message(**kwargs) == Message(**kwargs)


# -----------------------------------------------------------------------
# Provenance dataclass tests
# -----------------------------------------------------------------------


class TestProvenance:
    """Tests for the Provenance dataclass."""

    def test_provenance_minimal_construction(self) -> None:
        prov = Provenance(
            source_context="ctx-1",
            source_type=SourceType.PERSISTENT,
        )
        assert prov.source_context == "ctx-1"
        assert prov.source_type == SourceType.PERSISTENT
        assert prov.counterparties == []
        assert prov.purpose is None
        assert prov.discovery_method == DiscoveryMethod.OUT_OF_BAND
        assert prov.age_secs == 0.0
        assert prov.memory_scope == MemoryScope.FULL
        assert prov.chain_depth == 0
        assert prov.chain_path is None

    def test_provenance_full_construction(self) -> None:
        prov = Provenance(
            source_context="ctx-origin",
            source_type=SourceType.EPHEMERAL,
            counterparties=["did:dht:z6MkAlice", "did:dht:z6MkBob"],
            purpose="recipe sharing",
            discovery_method=DiscoveryMethod.SHARED_CONTEXT,
            age_secs=300.0,
            memory_scope=MemoryScope.EPHEMERAL,
            chain_depth=2,
            chain_path=["ctx-hop-1", "ctx-hop-2"],
        )
        assert prov.counterparties == ["did:dht:z6MkAlice", "did:dht:z6MkBob"]
        assert prov.purpose == "recipe sharing"
        assert prov.discovery_method == DiscoveryMethod.SHARED_CONTEXT
        assert prov.age_secs == 300.0
        assert prov.memory_scope == MemoryScope.EPHEMERAL
        assert prov.chain_depth == 2
        assert prov.chain_path is not None
        assert len(prov.chain_path) == 2


# -----------------------------------------------------------------------
# OutletDefinition and TestVector dataclass tests
# -----------------------------------------------------------------------


class TestTestVector:
    """Tests for the TestVector dataclass."""

    def test_test_vector_construction(self) -> None:
        tv = TestVector(
            input={"query": "butter substitute"},
            expected_output={"results": ["margarine", "oil"]},
            description="basic ingredient substitution",
        )
        assert tv.input == {"query": "butter substitute"}
        assert tv.expected_output == {"results": ["margarine", "oil"]}
        assert tv.description == "basic ingredient substitution"

    def test_test_vector_default_description(self) -> None:
        tv = TestVector(input={}, expected_output={})
        assert tv.description == ""


class TestOutletDefinition:
    """Tests for the OutletDefinition dataclass."""

    def test_tool_definition_required_fields(self) -> None:
        tool = OutletDefinition(
            name="recipe_search",
            description="Search recipes by ingredients",
            kind=OutletKind.Query,
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            operator="did:dht:z6MkOperator",
        )
        assert tool.name == "recipe_search"
        assert tool.description == "Search recipes by ingredients"
        assert tool.kind is OutletKind.Query
        assert tool.input_schema == {"type": "object"}
        assert tool.output_schema == {"type": "object"}
        assert tool.operator == "did:dht:z6MkOperator"
        assert tool.test_vectors is None
        assert tool.implementation_hash is None

    def test_tool_definition_with_test_vectors(self) -> None:
        tv = TestVector(
            input={"query": "cake"},
            expected_output={"results": ["chocolate cake"]},
        )
        tool = OutletDefinition(
            name="recipe_search",
            description="Search recipes",
            kind=OutletKind.Query,
            input_schema={},
            output_schema={},
            operator="did:dht:z6MkOp",
            test_vectors=[tv],
        )
        assert tool.test_vectors is not None
        assert len(tool.test_vectors) == 1
        assert tool.test_vectors[0].input == {"query": "cake"}

    def test_tool_definition_with_implementation_hash(self) -> None:
        tool = OutletDefinition(
            name="hasher",
            description="Hash tool",
            kind=OutletKind.Action,
            input_schema={},
            output_schema={},
            operator="did:dht:z6MkOp",
            implementation_hash=b"\xde\xad\xbe\xef",
        )
        assert tool.implementation_hash == b"\xde\xad\xbe\xef"

    def test_tool_definition_operator_can_be_string(self) -> None:
        tool = OutletDefinition(
            name="t",
            description="d",
            kind=OutletKind.Action,
            input_schema={},
            output_schema={},
            operator="did:dht:z6MkSomeone",
        )
        assert isinstance(tool.operator, str)


# -----------------------------------------------------------------------
# Enum tests
# -----------------------------------------------------------------------


class TestContextMode:
    """Tests for the ContextMode enum (spec section 5.1)."""

    def test_all_variants_exist(self) -> None:
        assert ContextMode.ENCRYPTED.value == "encrypted"
        assert ContextMode.BROADCAST.value == "broadcast"

    def test_variant_count(self) -> None:
        assert len(ContextMode) == 2


class TestCeilingPolicy:
    """Tests for the CeilingPolicy enum (spec section 5.3)."""

    def test_all_variants_exist(self) -> None:
        assert CeilingPolicy.IMMUTABLE.value == "immutable"
        assert CeilingPolicy.GOVERNED.value == "governed"

    def test_variant_count(self) -> None:
        assert len(CeilingPolicy) == 2


class TestPromotionPolicy:
    """Tests for the PromotionPolicy enum (spec section 5.10)."""

    def test_all_variants_exist(self) -> None:
        assert PromotionPolicy.NO_PROMOTION.value == "no_promotion"
        assert PromotionPolicy.PROMOTABLE.value == "promotable"

    def test_variant_count(self) -> None:
        assert len(PromotionPolicy) == 2


class TestMemoryScope:
    """Tests for the MemoryScope enum."""

    def test_all_variants_exist(self) -> None:
        assert MemoryScope.EPHEMERAL.value == "ephemeral"
        assert MemoryScope.SUMMARY.value == "summary"
        assert MemoryScope.FULL.value == "full"

    def test_variant_count(self) -> None:
        assert len(MemoryScope) == 3


class TestSourceType:
    """Tests for the SourceType enum."""

    def test_all_variants_exist(self) -> None:
        assert SourceType.PERSISTENT.value == "persistent"
        assert SourceType.EPHEMERAL.value == "ephemeral"
        assert SourceType.SUMMARY.value == "summary"


class TestDiscoveryMethod:
    """Tests for the DiscoveryMethod enum."""

    def test_all_variants_exist(self) -> None:
        assert DiscoveryMethod.SHARED_CONTEXT.value == "shared_context"
        assert DiscoveryMethod.REGISTRY.value == "registry"
        assert DiscoveryMethod.OUT_OF_BAND.value == "out_of_band"
        # Backward-compatible alias
        assert DiscoveryMethod.NONE.value == "none"


class TestProvenanceQuality:
    """Tests for the ProvenanceQuality enum."""

    def test_ordering_by_value(self) -> None:
        assert (
            ProvenanceQuality.NO_PROVENANCE.value < ProvenanceQuality.EPHEMERAL_KNOWN_PARTIES.value
        )
        assert (
            ProvenanceQuality.EPHEMERAL_KNOWN_PARTIES.value
            < ProvenanceQuality.SUMMARY_VERIFIED.value
        )
        assert (
            ProvenanceQuality.SUMMARY_VERIFIED.value < ProvenanceQuality.PERSISTENT_VERIFIABLE.value
        )

    def test_variant_count(self) -> None:
        assert len(ProvenanceQuality) == 4


class TestCapability:
    """Tests for the Capability enum."""

    def test_standard_capabilities(self) -> None:
        assert Capability.MESSAGES_READ.value == "messages:read"
        assert Capability.MESSAGES_WRITE.value == "messages:write"
        assert Capability.TOOL_INVOKE_ALL.value == "tool:invoke:*"
        assert Capability.TOOL_REGISTER.value == "tool:register"
        assert Capability.MEMBER_INVITE.value == "member:invite"
        assert Capability.MEMBER_REMOVE.value == "member:remove"
        assert Capability.ROLE_ASSIGN.value == "role:assign"
        assert Capability.GOVERNANCE_PROPOSE.value == "governance:propose"
        assert Capability.GOVERNANCE_VOTE.value == "governance:vote"
        assert Capability.CONTEXT_CLOSE.value == "context:close"
        assert Capability.CHILD_CONTEXT_CREATE.value == "context:child:create"
        assert Capability.TOOL_INTERFACE.value == "tool:interface"
        assert Capability.BRIDGING.value == "bridging"
        assert Capability.MEDIA_VOICE.value == "media:voice"
        assert Capability.MEDIA_VIDEO.value == "media:video"
        assert Capability.MEDIA_SCREEN_SHARE.value == "media:screen_share"
        assert Capability.MEMBER_BAN.value == "member:ban"
        assert Capability.METADATA_EDIT.value == "metadata:edit"

    def test_variant_count(self) -> None:
        assert len(Capability) == 18

    def test_tool_invoke_parameterised(self) -> None:
        cap = Capability.tool_invoke("my-tool-id")
        assert cap == "tool:invoke:my-tool-id"

    def test_custom_parameterised(self) -> None:
        cap = Capability.custom("my-custom-cap")
        assert cap == "my-custom-cap"


# -----------------------------------------------------------------------
# Package-level re-export tests
# -----------------------------------------------------------------------


class TestPackageReExports:
    """Tests that the top-level package re-exports key types."""

    def test_version(self) -> None:
        assert hasattr(scp_sdk, "__version__")
        assert scp_sdk.__version__ == "0.1.0"

    def test_errors_accessible_from_top_level(self) -> None:
        assert scp_sdk.ScpError is ScpError
        assert scp_sdk.IdentityError is IdentityError
        assert scp_sdk.ContextError is ContextError
        assert scp_sdk.UcanPermissionError is UcanPermissionError
        assert scp_sdk.CryptoError is CryptoError
        assert scp_sdk.TransportError is TransportError
        assert scp_sdk.OutletError is OutletError
        assert scp_sdk.ValidationError is ValidationError

    def test_types_accessible_from_top_level(self) -> None:
        assert scp_sdk.Message is Message
        assert scp_sdk.Provenance is Provenance
        assert scp_sdk.Capability is Capability
        assert scp_sdk.MemoryScope is MemoryScope
        assert scp_sdk.SourceType is SourceType

    def test_tools_accessible_from_top_level(self) -> None:
        assert scp_sdk.OutletDefinition is OutletDefinition
        assert scp_sdk.TestVector is TestVector

    def test_site_config_accessible_from_top_level(self) -> None:
        from scp_sdk.context import SiteConfig

        assert scp_sdk.SiteConfig is SiteConfig


# -----------------------------------------------------------------------
# SiteConfig tests (SCP-293, spec §18.11.12)
# -----------------------------------------------------------------------


class TestSiteConfig:
    """Tests for the SiteConfig dataclass."""

    def test_construction_with_defaults(self) -> None:
        from scp_sdk.context import SiteConfig

        config = SiteConfig(hostname="example.com")
        assert config.hostname == "example.com"
        assert config.index_path == "/index.html"
        assert config.max_assets_per_deploy == 10_000
        assert config.max_deploy_size_bytes == 536_870_912
        assert config.deploy_retention_count == 2
        assert config.csp_override is None

    def test_construction_with_all_fields(self) -> None:
        from scp_sdk.context import SiteConfig

        config = SiteConfig(
            hostname="cdn.example.com",
            index_path="/home.html",
            max_assets_per_deploy=5_000,
            max_deploy_size_bytes=268_435_456,
            deploy_retention_count=4,
            csp_override="default-src 'self'",
        )
        assert config.hostname == "cdn.example.com"
        assert config.index_path == "/home.html"
        assert config.max_assets_per_deploy == 5_000
        assert config.max_deploy_size_bytes == 268_435_456
        assert config.deploy_retention_count == 4
        assert config.csp_override == "default-src 'self'"

    def test_frozen(self) -> None:
        import dataclasses

        from scp_sdk.context import SiteConfig

        config = SiteConfig(hostname="example.com")
        with __import__("pytest").raises(dataclasses.FrozenInstanceError):
            config.hostname = "other.com"  # type: ignore[misc]


class TestSiteConfigHostnameValidation:
    """Tests for hostname validation in SiteConfig."""

    def test_valid_hostname(self) -> None:
        from scp_sdk.context import SiteConfig

        SiteConfig(hostname="example.com")
        SiteConfig(hostname="my-site.example.com")
        SiteConfig(hostname="localhost")
        SiteConfig(hostname="a.b.c.d")

    def test_empty_hostname(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="hostname must not be empty"):
            SiteConfig(hostname="")

    def test_hostname_exceeds_253_chars(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        long = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".e"
        with pytest.raises(ValueError, match="hostname exceeds 253 characters"):
            SiteConfig(hostname=long)

    def test_hostname_invalid_chars(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="hostname label contains invalid characters"):
            SiteConfig(hostname="bad_host.com")

    def test_hostname_label_leading_hyphen(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="hostname label contains invalid characters"):
            SiteConfig(hostname="-bad.com")

    def test_hostname_label_trailing_hyphen(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="hostname label contains invalid characters"):
            SiteConfig(hostname="bad-.com")


class TestSiteConfigRetentionCountValidation:
    """Tests for deploy_retention_count bounds in SiteConfig."""

    def test_retention_count_1(self) -> None:
        from scp_sdk.context import SiteConfig

        config = SiteConfig(hostname="example.com", deploy_retention_count=1)
        assert config.deploy_retention_count == 1

    def test_retention_count_8(self) -> None:
        from scp_sdk.context import SiteConfig

        config = SiteConfig(hostname="example.com", deploy_retention_count=8)
        assert config.deploy_retention_count == 8

    def test_retention_count_0_rejected(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(
            ValueError,
            match="deploy_retention_count must be an integer between 1 and 8",
        ):
            SiteConfig(hostname="example.com", deploy_retention_count=0)

    def test_retention_count_9_rejected(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(
            ValueError,
            match="deploy_retention_count must be an integer between 1 and 8",
        ):
            SiteConfig(hostname="example.com", deploy_retention_count=9)


class TestSiteConfigCspValidation:
    """Tests for CSP validation in SiteConfig."""

    def test_valid_csp(self) -> None:
        from scp_sdk.context import SiteConfig

        SiteConfig(hostname="example.com", csp_override="default-src 'self'")

    def test_csp_unsafe_eval(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="CSP must not contain 'unsafe-eval'"):
            SiteConfig(
                hostname="example.com",
                csp_override="script-src 'unsafe-eval'",
            )

    def test_csp_unsafe_inline(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="CSP must not contain 'unsafe-inline'"):
            SiteConfig(
                hostname="example.com",
                csp_override="style-src 'unsafe-inline'",
            )

    def test_csp_unsafe_hashes(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="CSP must not contain 'unsafe-hashes'"):
            SiteConfig(
                hostname="example.com",
                csp_override="script-src 'unsafe-hashes'",
            )

    def test_csp_bare_wildcard(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match=r"CSP must not contain bare wildcard '\*'"):
            SiteConfig(hostname="example.com", csp_override="default-src *")

    def test_csp_subdomain_wildcard_allowed(self) -> None:
        from scp_sdk.context import SiteConfig

        SiteConfig(
            hostname="example.com",
            csp_override="default-src *.example.com",
        )

    def test_csp_data_source(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="CSP must not contain 'data:' source"):
            SiteConfig(hostname="example.com", csp_override="img-src data:")

    def test_csp_blob_source(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="CSP must not contain 'blob:' source"):
            SiteConfig(hostname="example.com", csp_override="worker-src blob:")

    def test_csp_case_insensitive(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="CSP must not contain 'unsafe-eval'"):
            SiteConfig(
                hostname="example.com",
                csp_override="script-src 'Unsafe-Eval'",
            )


class TestSiteConfigDeployLimitsValidation:
    """Tests for max_assets_per_deploy and max_deploy_size_bytes bounds."""

    def test_max_assets_per_deploy_zero_rejected(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="max_assets_per_deploy must be >= 1"):
            SiteConfig(hostname="example.com", max_assets_per_deploy=0)

    def test_max_deploy_size_bytes_negative_rejected(self) -> None:
        import pytest

        from scp_sdk.context import SiteConfig

        with pytest.raises(ValueError, match="max_deploy_size_bytes must be >= 1"):
            SiteConfig(hostname="example.com", max_deploy_size_bytes=-1)

    def test_max_assets_per_deploy_one_accepted(self) -> None:
        from scp_sdk.context import SiteConfig

        config = SiteConfig(hostname="example.com", max_assets_per_deploy=1)
        assert config.max_assets_per_deploy == 1

    def test_max_deploy_size_bytes_one_accepted(self) -> None:
        from scp_sdk.context import SiteConfig

        config = SiteConfig(hostname="example.com", max_deploy_size_bytes=1)
        assert config.max_deploy_size_bytes == 1


# -----------------------------------------------------------------------
# Admission validation tests (SCP-296 post-merge audit)
# -----------------------------------------------------------------------


class TestAdmissionValidation:
    """Tests for validate_admission."""

    def test_open_accepted(self) -> None:
        from scp_sdk.context import validate_admission

        validate_admission("open")

    def test_gated_accepted(self) -> None:
        from scp_sdk.context import validate_admission

        validate_admission("gated")

    def test_open_title_case_accepted(self) -> None:
        from scp_sdk.context import validate_admission

        validate_admission("Open")

    def test_gated_title_case_accepted(self) -> None:
        from scp_sdk.context import validate_admission

        validate_admission("Gated")

    def test_invalid_rejected(self) -> None:
        import pytest

        from scp_sdk.context import validate_admission

        with pytest.raises(ValueError, match="admission must be"):
            validate_admission("closed")

    def test_empty_rejected(self) -> None:
        import pytest

        from scp_sdk.context import validate_admission

        with pytest.raises(ValueError, match="admission must be"):
            validate_admission("")


# -----------------------------------------------------------------------
# BroadcastKeyHex validation tests (SCP-296 post-merge audit)
# -----------------------------------------------------------------------


class TestBroadcastKeyHexValidation:
    """Tests for validate_broadcast_key_hex."""

    def test_valid_64_char_hex(self) -> None:
        from scp_sdk.context import validate_broadcast_key_hex

        validate_broadcast_key_hex("ab" * 32)

    def test_uppercase_hex(self) -> None:
        from scp_sdk.context import validate_broadcast_key_hex

        validate_broadcast_key_hex("AB" * 32)

    def test_too_short_rejected(self) -> None:
        import pytest

        from scp_sdk.context import validate_broadcast_key_hex

        with pytest.raises(ValueError, match="broadcast_key_hex must be exactly 64 hex characters"):
            validate_broadcast_key_hex("abcd")

    def test_too_long_rejected(self) -> None:
        import pytest

        from scp_sdk.context import validate_broadcast_key_hex

        with pytest.raises(ValueError, match="broadcast_key_hex must be exactly 64 hex characters"):
            validate_broadcast_key_hex("ab" * 33)

    def test_invalid_chars_rejected(self) -> None:
        import pytest

        from scp_sdk.context import validate_broadcast_key_hex

        with pytest.raises(ValueError, match="broadcast_key_hex must be exactly 64 hex characters"):
            validate_broadcast_key_hex("zz" * 32)

    def test_empty_rejected(self) -> None:
        import pytest

        from scp_sdk.context import validate_broadcast_key_hex

        with pytest.raises(ValueError, match="broadcast_key_hex must be exactly 64 hex characters"):
            validate_broadcast_key_hex("")
