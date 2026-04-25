"""SCP Python SDK -- Shared Context Protocol.

This package provides Pythonic wrappers around the ``_scp_core`` PyO3
extension module, offering typed dataclasses, an exception hierarchy,
and shared enums for building agents and applications on top of SCP.

Usage::

    import scp_sdk
    from scp_sdk import SCP
    from scp_sdk.types import CustodyType

    # Caller-owned instance — every operation routes through scp.*
    with SCP() as scp:
        identity = await scp.identity_create(CustodyType.IN_MEMORY)

See ``.docs/adrs/phase-3.md`` ADR-014 and ADR-048 for the full SDK design.

Phase 4 PR 5 (#1549) collapsed the module-level namespace classes onto
:class:`SCP` methods. :class:`Identity`, :class:`Context`,
:class:`Relay`, :class:`Node`, :class:`McpServer`, :class:`McpClient`,
and :class:`UcanToken` are now pure handle / data wrappers. Every
operation that previously lived as a namespace static or instance method
is a method on the :class:`SCP` instance — pass ``obj._raw_handle`` (or
the handle-holding wrapper directly) where the bridge expects an opaque
handle.
"""

from __future__ import annotations

import sys

# Register the native extension under its bare name so that function-scoped
# ``import _scp_core`` (used throughout the SDK) resolves correctly.  Maturin
# installs the extension as ``scp_sdk._scp_core`` (see pyproject.toml
# module-name), but every call-site does a bare ``import _scp_core``.
try:
    from scp_sdk import _scp_core

    sys.modules["_scp_core"] = _scp_core
except ImportError:
    pass  # Native extension not available (pure-Python / mocked tests)

from scp_sdk.auth import (
    ScpIdAuthentication,
    ScpIdChallenge,
    ScpIdResponse,
)
from scp_sdk.bridge import (
    evaluate_trust as bridge_evaluate_trust,
)
from scp_sdk.bridge import (
    register as bridge_register,
)
from scp_sdk.context import (
    AssetEntry,
    BatchPublishResult,
    Context,
    Membership,
    PublishResult,
    SiteConfig,
    validate_admission,
    validate_broadcast_key_hex,
)
from scp_sdk.discovery import create_query, normalize_address, parse_address
from scp_sdk.economy import (
    auto_accept_blocked,
    check_policy_lock,
    estimate_cost,
    evaluate_formula,
    policy_requires_payment,
    validate_policy_change,
)
from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    ContextError,
    CryptoError,
    IdentityError,
    ScpError,
    ToolError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.event_log import Checkpoint, Event, Proof, SignedCheckpoint
from scp_sdk.governance import GovernanceActionResult
from scp_sdk.identity import DIDDocument, Identity, IdentityAttestation, RevocationStatus
from scp_sdk.mcp import (
    McpClient,
    McpProvenance,
    McpServer,
    McpToolDefinition,
    McpToolResult,
    configure_stdio_allowlist,
    disable_stdio_allowlist,
    get_stdio_allowlist,
    reset_stdio_allowlist,
)
from scp_sdk.media import (
    activate_session as media_activate_session,
)
from scp_sdk.media import (
    check_media_capability,
)
from scp_sdk.media import (
    create_answer as media_create_answer,
)
from scp_sdk.media import (
    create_ice_candidate as media_create_ice_candidate,
)
from scp_sdk.media import (
    create_offer as media_create_offer,
)
from scp_sdk.media import (
    create_session_end as media_create_session_end,
)
from scp_sdk.media import (
    end_session as media_end_session,
)
from scp_sdk.media import (
    initiate_session as media_initiate_session,
)
from scp_sdk.media import (
    join_session as media_join_session,
)
from scp_sdk.media import (
    send_signaling as media_send_signaling,
)
from scp_sdk.media import (
    verify_sender_attribution as media_verify_sender_attribution,
)
from scp_sdk.scp import SCP, InMemoryStorage, SqliteStorage, StorageConfig
from scp_sdk.server import Node, Relay
from scp_sdk.sync import classify_offline, get_policy, run_sync
from scp_sdk.tools import (
    TestVector,
    ToolCost,
    ToolDefinition,
)
from scp_sdk.transport import TransportConfig, TransportStatus
from scp_sdk.trust import (
    PARTICIPATION_FACT_VARIANTS,
    PARTICIPATION_THRESHOLD_OPERATORS,
    Attestation,
    BehavioralRecord,
    CapabilityValidation,
    ChallengeResult,
    Endorsement,
    ParticipationFact,
    ParticipationProfile,
    ParticipationThreshold,
    RequireParticipation,
    TrustEvaluation,
    verify_participation_requirements,
)
from scp_sdk.types import (
    BridgeMode,
    Capability,
    CeilingPolicy,
    ContextMode,
    CustodyType,
    DiscoveryMethod,
    MemberRole,
    MemoryScope,
    Message,
    PromotionPolicy,
    Provenance,
    ProvenanceQuality,
    ShadowStatus,
    SourceType,
)
from scp_sdk.ucan import UcanToken

__version__ = "0.1.0"

__all__ = [
    "BRIDGE_ERROR_MAP",
    "PARTICIPATION_FACT_VARIANTS",
    "PARTICIPATION_THRESHOLD_OPERATORS",
    "SCP",
    "AssetEntry",
    "Attestation",
    "BatchPublishResult",
    "BehavioralRecord",
    "BridgeMode",
    "Capability",
    "CapabilityValidation",
    "CeilingPolicy",
    "ChallengeResult",
    "Checkpoint",
    "Context",
    "ContextError",
    "ContextMode",
    "CryptoError",
    "CustodyType",
    "DIDDocument",
    "DiscoveryMethod",
    "Endorsement",
    "Event",
    "GovernanceActionResult",
    "Identity",
    "IdentityAttestation",
    "IdentityError",
    "InMemoryStorage",
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "MemberRole",
    "Membership",
    "MemoryScope",
    "Message",
    "Node",
    "ParticipationFact",
    "ParticipationProfile",
    "ParticipationThreshold",
    "PromotionPolicy",
    "Proof",
    "Provenance",
    "ProvenanceQuality",
    "PublishResult",
    "Relay",
    "RequireParticipation",
    "RevocationStatus",
    "ScpError",
    "ScpIdAuthentication",
    "ScpIdChallenge",
    "ScpIdResponse",
    "ShadowStatus",
    "SignedCheckpoint",
    "SiteConfig",
    "SourceType",
    "SqliteStorage",
    "StorageConfig",
    "TestVector",
    "ToolCost",
    "ToolDefinition",
    "ToolError",
    "TransportConfig",
    "TransportError",
    "TransportStatus",
    "TrustEvaluation",
    "UcanPermissionError",
    "UcanToken",
    "ValidationError",
    "__version__",
    "auto_accept_blocked",
    "bridge_evaluate_trust",
    "bridge_register",
    "check_media_capability",
    "check_policy_lock",
    "classify_offline",
    "configure_stdio_allowlist",
    "create_query",
    "disable_stdio_allowlist",
    "estimate_cost",
    "evaluate_formula",
    "get_policy",
    "get_stdio_allowlist",
    "media_activate_session",
    "media_create_answer",
    "media_create_ice_candidate",
    "media_create_offer",
    "media_create_session_end",
    "media_end_session",
    "media_initiate_session",
    "media_join_session",
    "media_send_signaling",
    "media_verify_sender_attribution",
    "normalize_address",
    "parse_address",
    "policy_requires_payment",
    "reset_stdio_allowlist",
    "run_sync",
    "validate_admission",
    "validate_broadcast_key_hex",
    "validate_policy_change",
    "verify_participation_requirements",
]
