"""SCP Python SDK -- Shared Context Protocol.

This package provides Pythonic wrappers around the ``_scp_core`` PyO3
extension module, offering typed dataclasses, an exception hierarchy,
and shared enums for building agents and applications on top of SCP.

Usage::

    import scp_sdk
    from scp_sdk import SCP
    from scp_sdk.types import CustodyType

    # Caller-owned instance — every operation routes through scp.*
    with SCP(storage={"type": "in_memory"}) as scp:
        identity = await scp.identity_create(CustodyType.ENCRYPTED_FILE)

See ``.docs/adrs/phase-3.md`` ADR-014 and ADR-048 for the full SDK design.

Phase 4 PR 5 (#1549) collapsed the module-level namespace classes onto
:class:`SCP` methods. :class:`Identity`, :class:`Context`,
:class:`Relay`, :class:`Node`, :class:`McpServer`, :class:`McpClient`,
and :class:`UcanToken` are now pure handle / data wrappers. Every
operation that previously lived as a namespace static or instance method
is a method on the :class:`SCP` instance, and it takes the wrapper object
itself; a raw native handle raises ``ValidationError`` (SCP-VALID-7005).
"""

from __future__ import annotations

from scp_sdk._extension import reject_load_failure as _reject_load_failure

# Import the native extension while the package loads, so that a broken build
# fails here. Maturin installs the extension as ``scp_sdk._scp_core`` (see
# pyproject.toml module-name), and every SDK accessor reaches it by that name
# through ``scp_sdk._extension.native_module``. The package registers no
# bare-name ``_scp_core`` alias in ``sys.modules``, because no code in this
# repository imports the bare name:
# ``test_no_sdk_or_test_file_imports_the_extension_by_its_bare_name`` in
# ``bindings/python/tests/test_extension_loading.py`` scans ``scp_sdk/``, the
# SDK's ``tests/``, and the repository-root ``tests/`` for one.
#
# An absent extension is swallowed, so a pure-Python or mocked environment
# still imports the package. A present extension that failed to load raises
# ``SCP-VALID-7082`` from here, because ``ImportError`` carries both causes
# and reporting a load failure as absence lets every
# ``except ImportError: pytest.skip(...)`` guard under ``bindings/python/tests``
# skip the whole real-FFI suite over a broken artifact. The error raised is a
# ``ValidationError``, not an ``ImportError``, so no such guard catches it.
try:
    from scp_sdk import _scp_core  # noqa: F401
except ImportError as _exc:
    _reject_load_failure(_exc)

from scp_sdk.auth import (
    ScpIdAuthentication,
    ScpIdChallenge,
    ScpIdResponse,
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
from scp_sdk.discovery import (
    create_query,
    discover,
    discover_contexts,
    normalize_address,
    parse_address,
)
from scp_sdk.economy import (
    PaymentReceiptVerificationEntry,
    PaymentReceiptVerificationResult,
    auto_accept_blocked,
    check_policy_lock,
    estimate_cost,
    evaluate_formula,
    format_amount,
    policy_requires_payment,
    validate_policy_change,
    verify_payment_receipts,
)
from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    AttestationError,
    ContextError,
    CryptoError,
    EconomyError,
    GovernanceError,
    IdentityError,
    InvalidGrant,
    KeyNotFoundError,
    McpError,
    OutletError,
    ProtocolError,
    SagaAbortedError,
    SagaBusyError,
    SagaNeedsRepairError,
    ScpError,
    StorageError,
    StreamAlreadyClosed,
    StreamGap,
    TransportError,
    UcanPermissionError,
    UnknownGovernanceOutcomeError,
    ValidationError,
)
from scp_sdk.event_log import Checkpoint, Event, Proof, SignedCheckpoint
from scp_sdk.fullstack import FullStackNode
from scp_sdk.governance import GovernanceActionResult, ProposalStatus, RejectionReason
from scp_sdk.identity import DIDDocument, Identity, IdentityAttestation, RevocationStatus
from scp_sdk.mcp import (
    McpClient,
    McpProvenance,
    McpServer,
    McpToolDefinition,
    McpToolResult,
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
from scp_sdk.outlets import (
    Aggregate,
    Credit,
    InvocationHandle,
    OutletCost,
    OutletDefinition,
    OutletKind,
    Outlets,
    OutletStreamChunk,
    SagaResult,
    StreamingSagaHandle,
    TestVector,
)
from scp_sdk.scp import (
    SCP,
    SHUTDOWN_FLUSH_FAILED_CODE,
    SUSPEND_FLUSH_FAILED_CODE,
    CustodyKeyRole,
    CustodyKeyType,
    CustodyPublicKey,
    InMemoryStorage,
    InviteMemberOutcome,
    KeyCustodyProvider,
    McpAllowlistState,
    Sealed,
    SealedInvitation,
    SqlitePassphraseStorage,
    SqliteStorage,
    StorageConfig,
    p256_pseudonym_point,
    p256_software_pseudonym_point,
)
from scp_sdk.server import (
    BlobBackend,
    BlobInMemory,
    BlobRedb,
    BlobSqlite,
    CorsAllowlist,
    CorsAnyOrigin,
    CorsOrigins,
    DhtDisabled,
    DhtMode,
    Nat,
    NatAuto,
    Node,
    NodeStartConfig,
    Reach,
    ReachDomain,
    ReachLocal,
    ReachNatTraversal,
    Relay,
    TlsAcme,
    TlsMode,
    TlsPlaintext,
    TlsSelfSigned,
    TlsTerminated,
)
from scp_sdk.sync import classify_offline, get_policy, run_sync
from scp_sdk.transport import TransportConfig, TransportStatus
from scp_sdk.trust import (
    ADMISSION_REQUIREMENT_UNMET_CODE,
    ATTEMPT_OUT_OF_ORDER_CODE,
    ATTESTATION_TYPES,
    CAPABILITY_DEFINITION_UNAVAILABLE_CODE,
    CHALLENGE_CLOSED_CODE,
    CHALLENGE_EXPIRED_CODE,
    CHALLENGE_NOT_OPEN_CODE,
    CHALLENGE_NOT_YET_GRADABLE_CODE,
    CHALLENGE_SUITE_BELOW_MINIMUM_CODE,
    CHALLENGE_WINDOW_OPEN_CODE,
    COOLDOWN_ACTIVE_CODE,
    DEFINITION_EQUIVOCATION_CODE,
    DID_RESOLUTION_FAILED_CODE,
    EMPTY_SUBJECT_DID_CODE,
    EVALUATOR_UNAVAILABLE_CODE,
    GRADING_CAPACITY_EXHAUSTED_CODE,
    GRADING_IN_PROGRESS_CODE,
    GRADING_LEASE_LOST_CODE,
    INVALID_REQUIREMENT_CODE,
    JSON_SCHEMA_VALIDATION_FAILED_CODE,
    MALFORMED_AGENT_CAPABILITIES_CODE,
    MALFORMED_CHALLENGE_VERIFICATIONS_CODE,
    NON_CANONICAL_IDENTIFIER_CODE,
    OUTPUTS_MISMATCH_CODE,
    PARTICIPATION_FACT_VARIANTS,
    PARTICIPATION_THRESHOLD_OPERATORS,
    POLICY_OUTSIDE_DEFINITION_CODE,
    RESPONSE_TOO_LARGE_CODE,
    RETRIES_EXHAUSTED_CODE,
    SCHEMA_REJECTED_CODE,
    SELF_CHALLENGE_CODE,
    STANDARD_NOT_GRADABLE_CODE,
    TOO_MANY_CAPABILITY_REQUIREMENTS_CODE,
    UNKNOWN_CHALLENGE_CODE,
    UNTRUSTED_VERIFIER_CODE,
    AttestationSummary,
    AttestorInfo,
    BehavioralRecord,
    CachedAttestation,
    CachedAttestationEnvelope,
    CapabilityRequirement,
    CapabilityValidation,
    CaseResult,
    ChallengeCase,
    ChallengePolicy,
    ChallengeRequest,
    ChallengeResponse,
    ChallengeVerification,
    ChallengeVerified,
    ContainsAll,
    ContainsNone,
    CreateChallengeConfig,
    CustomEval,
    EventLogEntry,
    EventLogEntryPayload,
    ExactMatch,
    ExpectedOutput,
    GradedChallenge,
    ParticipationFact,
    ParticipationProfile,
    ParticipationThreshold,
    RequireParticipation,
    RetryCap,
    SchemaMatch,
    SelfAttested,
    TestCase,
    TestOutput,
    ThresholdRequirement,
    TrustEvaluation,
    evaluate_trust,
    is_retryable,
    retry_after,
    trust_verify_attestation,
    verify_participation_requirements,
)
from scp_sdk.types import (
    Capability,
    CeilingPolicy,
    ContextMode,
    CustodyType,
    CustomRole,
    DiscoveryMethod,
    MemberRole,
    MemoryScope,
    Message,
    PromotionPolicy,
    Provenance,
    ProvenanceQuality,
    SourceType,
)
from scp_sdk.ucan import UcanToken

__version__ = "0.1.0"

__all__ = [
    "ADMISSION_REQUIREMENT_UNMET_CODE",
    "ATTEMPT_OUT_OF_ORDER_CODE",
    "ATTESTATION_TYPES",
    "BRIDGE_ERROR_MAP",
    "CAPABILITY_DEFINITION_UNAVAILABLE_CODE",
    "CHALLENGE_CLOSED_CODE",
    "CHALLENGE_EXPIRED_CODE",
    "CHALLENGE_NOT_OPEN_CODE",
    "CHALLENGE_NOT_YET_GRADABLE_CODE",
    "CHALLENGE_SUITE_BELOW_MINIMUM_CODE",
    "CHALLENGE_WINDOW_OPEN_CODE",
    "COOLDOWN_ACTIVE_CODE",
    "DEFINITION_EQUIVOCATION_CODE",
    "DID_RESOLUTION_FAILED_CODE",
    "EMPTY_SUBJECT_DID_CODE",
    "EVALUATOR_UNAVAILABLE_CODE",
    "GRADING_CAPACITY_EXHAUSTED_CODE",
    "GRADING_IN_PROGRESS_CODE",
    "GRADING_LEASE_LOST_CODE",
    "INVALID_REQUIREMENT_CODE",
    "JSON_SCHEMA_VALIDATION_FAILED_CODE",
    "MALFORMED_AGENT_CAPABILITIES_CODE",
    "MALFORMED_CHALLENGE_VERIFICATIONS_CODE",
    "NON_CANONICAL_IDENTIFIER_CODE",
    "OUTPUTS_MISMATCH_CODE",
    "PARTICIPATION_FACT_VARIANTS",
    "PARTICIPATION_THRESHOLD_OPERATORS",
    "POLICY_OUTSIDE_DEFINITION_CODE",
    "RESPONSE_TOO_LARGE_CODE",
    "RETRIES_EXHAUSTED_CODE",
    "SCHEMA_REJECTED_CODE",
    "SCP",
    "SELF_CHALLENGE_CODE",
    "SHUTDOWN_FLUSH_FAILED_CODE",
    "STANDARD_NOT_GRADABLE_CODE",
    "SUSPEND_FLUSH_FAILED_CODE",
    "TOO_MANY_CAPABILITY_REQUIREMENTS_CODE",
    "UNKNOWN_CHALLENGE_CODE",
    "UNTRUSTED_VERIFIER_CODE",
    "Aggregate",
    "AssetEntry",
    "AttestationError",
    "AttestationSummary",
    "AttestorInfo",
    "BatchPublishResult",
    "BehavioralRecord",
    "BlobBackend",
    "BlobInMemory",
    "BlobRedb",
    "BlobSqlite",
    "CachedAttestation",
    "CachedAttestationEnvelope",
    "Capability",
    "CapabilityRequirement",
    "CapabilityValidation",
    "CaseResult",
    "CeilingPolicy",
    "ChallengeCase",
    "ChallengePolicy",
    "ChallengeRequest",
    "ChallengeResponse",
    "ChallengeVerification",
    "ChallengeVerified",
    "Checkpoint",
    "ContainsAll",
    "ContainsNone",
    "Context",
    "ContextError",
    "ContextMode",
    "CorsAllowlist",
    "CorsAnyOrigin",
    "CorsOrigins",
    "CreateChallengeConfig",
    "Credit",
    "CryptoError",
    "CustodyKeyRole",
    "CustodyKeyType",
    "CustodyPublicKey",
    "CustodyType",
    "CustomEval",
    "CustomRole",
    "DIDDocument",
    "DhtDisabled",
    "DhtMode",
    "DiscoveryMethod",
    "EconomyError",
    "Event",
    "EventLogEntry",
    "EventLogEntryPayload",
    "ExactMatch",
    "ExpectedOutput",
    "FullStackNode",
    "GovernanceActionResult",
    "GovernanceError",
    "GradedChallenge",
    "Identity",
    "IdentityAttestation",
    "IdentityError",
    "InMemoryStorage",
    "InvalidGrant",
    "InviteMemberOutcome",
    "InvocationHandle",
    "KeyCustodyProvider",
    "KeyNotFoundError",
    "McpAllowlistState",
    "McpClient",
    "McpError",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "MemberRole",
    "Membership",
    "MemoryScope",
    "Message",
    "Nat",
    "NatAuto",
    "Node",
    "NodeStartConfig",
    "OutletCost",
    "OutletDefinition",
    "OutletError",
    "OutletKind",
    "OutletStreamChunk",
    "Outlets",
    "ParticipationFact",
    "ParticipationProfile",
    "ParticipationThreshold",
    "PaymentReceiptVerificationEntry",
    "PaymentReceiptVerificationResult",
    "PromotionPolicy",
    "Proof",
    "ProposalStatus",
    "ProtocolError",
    "Provenance",
    "ProvenanceQuality",
    "PublishResult",
    "Reach",
    "ReachDomain",
    "ReachLocal",
    "ReachNatTraversal",
    "RejectionReason",
    "Relay",
    "RequireParticipation",
    "RetryCap",
    "RevocationStatus",
    "SagaAbortedError",
    "SagaBusyError",
    "SagaNeedsRepairError",
    "SagaResult",
    "SchemaMatch",
    "ScpError",
    "ScpIdAuthentication",
    "ScpIdChallenge",
    "ScpIdResponse",
    "Sealed",
    "SealedInvitation",
    "SelfAttested",
    "SignedCheckpoint",
    "SiteConfig",
    "SourceType",
    "SqlitePassphraseStorage",
    "SqliteStorage",
    "StorageConfig",
    "StorageError",
    "StreamAlreadyClosed",
    "StreamGap",
    "StreamingSagaHandle",
    "TestCase",
    "TestOutput",
    "TestVector",
    "ThresholdRequirement",
    "TlsAcme",
    "TlsMode",
    "TlsPlaintext",
    "TlsSelfSigned",
    "TlsTerminated",
    "TransportConfig",
    "TransportError",
    "TransportStatus",
    "TrustEvaluation",
    "UcanPermissionError",
    "UcanToken",
    "UnknownGovernanceOutcomeError",
    "ValidationError",
    "__version__",
    "auto_accept_blocked",
    "check_media_capability",
    "check_policy_lock",
    "classify_offline",
    "create_query",
    "discover",
    "discover_contexts",
    "estimate_cost",
    "evaluate_formula",
    "evaluate_trust",
    "format_amount",
    "get_policy",
    "is_retryable",
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
    "p256_pseudonym_point",
    "p256_software_pseudonym_point",
    "parse_address",
    "policy_requires_payment",
    "retry_after",
    "run_sync",
    "trust_verify_attestation",
    "validate_admission",
    "validate_broadcast_key_hex",
    "validate_policy_change",
    "verify_participation_requirements",
    "verify_payment_receipts",
]
