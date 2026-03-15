"""SCP Python SDK -- Shared Context Protocol.

This package provides Pythonic wrappers around the ``_scp_core`` PyO3
extension module, offering typed dataclasses, an exception hierarchy,
and shared enums for building agents and applications on top of SCP.

Usage::

    import scp_sdk
    from scp_sdk import Identity, Context, ToolDefinition, evaluate_trust

    # Or via namespace alias:
    import scp_sdk as scp
    identity = await scp.Identity.create()

See ``.docs/adrs/phase-3.md`` ADR-014 for the full SDK design.
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
    scpid_challenge,
    scpid_sign,
    scpid_verify,
)
from scp_sdk.bridge import (
    create_shadow,
)
from scp_sdk.bridge import (
    evaluate_trust as bridge_evaluate_trust,
)
from scp_sdk.bridge import (
    register as bridge_register,
)
from scp_sdk.context import Context, Membership
from scp_sdk.discovery import create_query, discover, normalize_address, parse_address
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
from scp_sdk.event_log import Checkpoint, Event, EventLog, Proof
from scp_sdk.governance import (
    GovernanceActionResult,
    approve_governance_proposal,
    execute_governance_action,
    get_governance_proposal,
    handle_ttl_expiry,
    list_governance_proposals,
    propose_governance_action,
    propose_ttl_extension,
    reject_governance_proposal,
    reset_ttl_timer,
    withdraw_governance_vote,
)
from scp_sdk.identity import DIDDocument, Identity
from scp_sdk.mcp import (
    McpClient,
    McpProvenance,
    McpServer,
    McpToolDefinition,
    McpToolResult,
    configure_stdio_allowlist,
    disable_stdio_allowlist,
    get_stdio_allowlist,
    register_tool_handler,
    registry_cleanup,
    registry_stats,
    reset_stdio_allowlist,
    serve_mcp,
)
from scp_sdk.media import (
    activate_session as media_activate_session,
    check_media_capability,
    create_answer as media_create_answer,
    create_ice_candidate as media_create_ice_candidate,
    create_offer as media_create_offer,
    create_session_end as media_create_session_end,
    end_session as media_end_session,
    initiate_session as media_initiate_session,
    join_session as media_join_session,
    send_signaling as media_send_signaling,
    verify_sender_attribution as media_verify_sender_attribution,
)
from scp_sdk.provenance import (
    attach as provenance_attach,
)
from scp_sdk.provenance import (
    check_chain_depth,
    evaluate_provenance_quality,
)
from scp_sdk.sync import classify_offline, get_policy, run_sync
from scp_sdk.tools import (
    TestVector,
    ToolDefinition,
    invoke_cross_context,
    session_close,
    session_create,
    session_invoke,
)
from scp_sdk.transport import TransportConfig, TransportStatus, connect_relay, relay_status
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
    evaluate_trust,
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
from scp_sdk.ucan import UcanToken, delegate, mint, revoke, validate

__version__ = "0.1.0"

__all__ = [
    "BRIDGE_ERROR_MAP",
    "PARTICIPATION_FACT_VARIANTS",
    "PARTICIPATION_THRESHOLD_OPERATORS",
    "Attestation",
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
    "EventLog",
    "GovernanceActionResult",
    "Identity",
    "IdentityError",
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "MemberRole",
    "Membership",
    "MemoryScope",
    "Message",
    "ParticipationFact",
    "ParticipationProfile",
    "ParticipationThreshold",
    "PromotionPolicy",
    "Proof",
    "Provenance",
    "ProvenanceQuality",
    "RequireParticipation",
    "ScpError",
    "ScpIdAuthentication",
    "ScpIdChallenge",
    "ScpIdResponse",
    "ShadowStatus",
    "SourceType",
    "TestVector",
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
    "approve_governance_proposal",
    "bridge_evaluate_trust",
    "bridge_register",
    "check_chain_depth",
    "check_media_capability",
    "classify_offline",
    "configure_stdio_allowlist",
    "connect_relay",
    "create_query",
    "create_shadow",
    "delegate",
    "disable_stdio_allowlist",
    "discover",
    "evaluate_provenance_quality",
    "evaluate_trust",
    "execute_governance_action",
    "get_governance_proposal",
    "get_policy",
    "get_stdio_allowlist",
    "handle_ttl_expiry",
    "invoke_cross_context",
    "list_governance_proposals",
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
    "mint",
    "normalize_address",
    "parse_address",
    "propose_governance_action",
    "propose_ttl_extension",
    "provenance_attach",
    "register_tool_handler",
    "registry_cleanup",
    "registry_stats",
    "reject_governance_proposal",
    "relay_status",
    "reset_stdio_allowlist",
    "reset_ttl_timer",
    "revoke",
    "run_sync",
    "scpid_challenge",
    "scpid_sign",
    "scpid_verify",
    "serve_mcp",
    "session_close",
    "session_create",
    "session_invoke",
    "validate",
    "verify_participation_requirements",
    "withdraw_governance_vote",
]
