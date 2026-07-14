#!/usr/bin/env python3
"""check-sdk-coverage.py -- CI gate enforcing SDK capability matrix conformance.

Reads `.docs/standards/sdk-capability-matrix.json` and validates:
  1. Every entry marked `true` has a symbol of the expected name in the SDK
     source. This is a NAME-EXISTENCE check only: it confirms a symbol with the
     expected (or aliased) name exists — NOT that the symbol implements the
     operation. Several aliases deliberately map multiple matrix operations to
     one shared dispatcher symbol (e.g. governance `execute_*` ->
     `executeGovernanceAction`), so a single symbol can satisfy many cells.
     Semantic correctness — that the symbol implements the capability — is a
     human-review invariant enforced by code review of the enforcement-labeled
     files, not by this gate.
  2. Every entry marked `false` has an `exemptions` entry with a reason.

Detection strategy per SDK (AST-based via tree-sitter):
  - Python:     function_definition / class_definition in bindings/python/scp_sdk/*.py
  - TypeScript:  exported declarations in bindings/typescript/src/*.ts
  - Kotlin:      public class/function declarations in bindings/kotlin/scp-kt/src/main/kotlin/**/*.kt
  - Swift:       public func/class/struct/actor/extension in bindings/swift/Sources/SCP/**/*.swift

Exit 0 if all checks pass. Exit 1 if any of: required tree-sitter
grammar is not installed (ImportError at startup), matrix file not
found, `true` entry has no matching symbol and no coverage exemption,
`false` entry lacks an exemption or has an empty exemption reason, a
coverage_exemptions entry has a blank reason, a cell value is not
true/false/null, an expected SDK key is absent from an operation entry,
or every SDK claiming coverage for an operation is coverage-exempted
with no statically-verified implementation.

Usage: python3.12 scripts/check-sdk-coverage.py

Dependencies: pip install tree-sitter tree-sitter-python tree-sitter-typescript \
              tree-sitter-kotlin tree-sitter-swift
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

try:
    import tree_sitter_kotlin as tskotlin
    import tree_sitter_python as tspython
    import tree_sitter_swift as tsswift
    import tree_sitter_typescript as tstypescript
    from tree_sitter import Language, Node, Parser
except ImportError as e:
    print(
        f"Missing dependency: {e}\n\n"
        "Install required packages:\n"
        "  pip install tree-sitter tree-sitter-python tree-sitter-typescript "
        "tree-sitter-kotlin tree-sitter-swift",
        file=sys.stderr,
    )
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = REPO_ROOT / ".docs" / "standards" / "sdk-capability-matrix.json"

# SDK source directories
SDK_PATHS: dict[str, Path] = {
    "python": REPO_ROOT / "bindings" / "python" / "scp_sdk",
    "typescript": REPO_ROOT / "bindings" / "typescript" / "src",
    "kotlin": (
        REPO_ROOT
        / "bindings"
        / "kotlin"
        / "scp-kt"
        / "src"
        / "main"
        / "kotlin"
        / "works"
        / "limn"
        / "scp"
    ),
    "swift": REPO_ROOT / "bindings" / "swift" / "Sources" / "SCP",
}

# File extensions per SDK
SDK_EXTENSIONS: dict[str, str] = {
    "python": "*.py",
    "typescript": "*.ts",
    "kotlin": "*.kt",
    "swift": "*.swift",
}

# Explicit alias table: (domain, operation) -> {sdk: [search_strings]}
# Only needed when the auto-generated patterns fail to match the actual code.
# Every entry has been verified against actual SDK source: the named symbol
# exists (name-existence check). Semantic correctness is a human-review
# invariant; the gate cannot verify that a symbol implements the capability.
#
# Why bare-named ops (no domain prefix in the matrix name) need explicit
# entries: the matcher intentionally dropped the bare-`op_name` candidate to
# close the suffix-collision hole (an unrelated `migrate` helper anywhere in
# the codebase used to satisfy `Identity/migrate`). It now only auto-generates
# DOMAIN-PREFIXED candidates. So any op whose real SDK symbol equals its bare
# matrix name — or already carries its own sub-domain prefix in the matrix name
# (e.g. `scpid_*`, `identity_remove`, `relay_start_in_memory`) — has no
# auto-generated candidate that matches and MUST have an explicit alias here.
# Do NOT "simplify" by deleting these entries: removing one re-opens a
# fail-closed gap for that op.
ALIASES: dict[tuple[str, str], dict[str, list[str]]] = {
    # Identity attestations carry the "Link" infix across all SDKs.
    ("Identity", "create_attestation"): {
        "python": ["create_identity_link_attestation"],
        "typescript": ["identityCreateLinkAttestation"],
        "kotlin": ["createLinkAttestation"],
        "swift": ["identityCreateLinkAttestation", "createLinkAttestation"],
    },
    ("Identity", "list_attestations"): {
        "python": ["identity_link_attestations"],
        "typescript": ["identityLinkAttestations"],
        "kotlin": ["linkAttestations"],
        "swift": ["identityLinkAttestations", "listLinkAttestations"],
    },
    ("Identity", "remove_attestation"): {
        "python": ["remove_identity_link_attestation"],
        "typescript": ["identityRemoveLinkAttestation"],
        "kotlin": ["removeLinkAttestation"],
        "swift": ["identityRemoveLinkAttestation"],
    },
    ("Identity", "verify_attestation"): {
        "kotlin": ["verifyLinkAttestation"],
    },
    # Outlets streaming control plane (SCP-OUT-038): the grant/cancel methods
    # live on the InvocationHandle returned by the single public invoke() verb,
    # so their SDK symbols are the bare method names (grant_credit / cancel),
    # not a domain-prefixed free function. All four SDKs are wired: Python
    # (C11a reference) plus the TS/Swift/Kotlin mirrors (C11b).
    ("Outlets", "stream_grant_credit"): {
        "python": ["grant_credit", "InvocationHandle.grant_credit"],
        "typescript": ["grantCredit"],
        "kotlin": ["grantCredit"],
        "swift": ["grantCredit"],
    },
    ("Outlets", "stream_cancel"): {
        "python": ["cancel", "InvocationHandle.cancel"],
        "typescript": ["cancel"],
        "kotlin": ["cancel"],
        "swift": ["cancel"],
    },
    # Context validation helpers
    ("Context", "metadata_record_serialize"): {
        "python": ["metadata_record_to_json"],
        "typescript": ["metadataRecordToJson"],
        "kotlin": ["metadataRecordToJson"],
        "swift": ["serializeMetadataRecord"],
    },
    ("Context", "metadata_record_deserialize"): {
        "python": ["metadata_record_from_json"],
        "typescript": ["metadataRecordFromJson"],
        "kotlin": ["metadataRecordFromJson"],
        "swift": ["deserializeMetadataRecord"],
    },
    # Messaging -- send_message maps to send() or contextSend() depending on SDK
    ("Messaging", "send_message"): {
        "python": ["send", "context_send"],
        "typescript": ["send", "contextSend"],
        "kotlin": ["contextSend"],
        "swift": ["send"],
    },
    # Messaging -- subscribe maps to receive() or contextSubscribe()
    ("Messaging", "subscribe"): {
        "python": ["receive", "context_receive"],
        "typescript": ["receive", "contextSubscribe"],
        "kotlin": ["subscribe"],
    },
    # Messaging -- validate_broadcast_key has _hex suffix in some SDKs
    ("Messaging", "validate_broadcast_key"): {
        "python": ["validate_broadcast_key_hex"],
        "typescript": ["validateBroadcastKeyHex"],
        "kotlin": ["validateBroadcastKeyHex"],
        "swift": ["validateBroadcastKeyHex"],
    },
    # Governance -- uses different naming in all SDKs.
    # Per-action variants dispatch through one generic method; there is no
    # per-variant symbol in any SDK (Python reference included).
    ("Governance", "execute_action"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "propose_action"): {
        "python": ["propose_governance_action", "governance_propose"],
        "typescript": ["proposeGovernanceAction", "contextGovernancePropose"],
        "kotlin": ["governancePropose"],
        "swift": ["proposeGovernanceAction"],
    },
    ("Governance", "approve_proposal"): {
        "python": ["approve_governance_proposal", "governance_approve"],
        "typescript": ["approveGovernanceProposal", "contextGovernanceApprove"],
        "kotlin": ["governanceApprove"],
        "swift": ["approveGovernanceProposal"],
    },
    ("Governance", "reject_proposal"): {
        "python": ["reject_governance_proposal", "governance_reject"],
        "typescript": ["rejectGovernanceProposal", "contextGovernanceReject"],
        "kotlin": ["governanceReject"],
        "swift": ["rejectGovernanceProposal"],
    },
    ("Governance", "withdraw_vote"): {
        "python": ["withdraw_governance_vote", "governance_withdraw"],
        "typescript": ["withdrawGovernanceVote", "contextGovernanceWithdraw"],
        "kotlin": ["governanceWithdraw"],
        "swift": ["withdrawGovernanceVote"],
    },
    ("Governance", "get_proposal"): {
        "python": ["get_governance_proposal"],
        "typescript": ["contextGovernanceGetProposal"],
    },
    ("Governance", "list_proposals"): {
        "python": ["list_governance_proposals"],
        "typescript": ["contextGovernanceListProposals"],
    },
    ("Governance", "apply_pending_ceiling_modification"): {
        "python": ["apply_pending_ceiling_modification"],
        "typescript": ["contextApplyPendingCeilingModification"],
        "kotlin": ["applyPendingCeilingModification"],
        "swift": ["applyPendingCeilingModification"],
    },
    ("Governance", "finalize_close"): {
        "python": ["finalize_close"],
        "typescript": ["contextFinalizeClose"],
        "kotlin": ["finalizeClose"],
        "swift": ["finalizeClose"],
    },
    ("Governance", "create_governance_checkpoint"): {
        "python": ["create_governance_checkpoint"],
        "typescript": ["contextCreateGovernanceCheckpoint"],
        "kotlin": ["createGovernanceCheckpoint"],
        "swift": ["createGovernanceCheckpoint"],
    },
    ("Governance", "add_checkpoint_cosignature"): {
        "python": ["add_checkpoint_cosignature"],
        "typescript": ["contextAddCheckpointCosignature"],
        "kotlin": ["addCheckpointCosignature"],
        "swift": ["addCheckpointCosignature"],
    },
    ("Governance", "member_count"): {
        "python": ["member_count", "context_member_count"],
        "typescript": ["contextMemberCount"],
        "kotlin": ["memberCount"],
        "swift": ["memberCount"],
    },
    ("Governance", "is_member"): {
        "python": ["is_member", "context_is_member"],
        "typescript": ["contextIsMember"],
        "kotlin": ["isMember"],
        "swift": ["isMember"],
    },
    ("Governance", "member_role"): {
        "python": ["context_member_role"],
        "typescript": ["contextMemberRole"],
        "kotlin": ["memberRole"],
        "swift": ["memberRole"],
    },
    # Governance rows whose method lives under context_* in Python / TypeScript.
    ("Governance", "handle_ttl_expiry"): {
        "python": ["context_handle_ttl_expiry"],
        "typescript": ["contextHandleTtlExpiry"],
        "swift": ["handleTtlExpiry"],
    },
    ("Governance", "propose_ttl_extension"): {
        "python": ["context_propose_ttl_extension"],
        "typescript": ["contextProposeTtlExtension"],
        "swift": ["proposeTtlExtension"],
    },
    # Governance -- new GovernanceAction variants dispatched via the existing
    # execute_action / propose_action entry points.
    ("Governance", "execute_suspend_capability"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "execute_suspend_access"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "execute_revoke_access"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "execute_restore_access"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "execute_remove_member"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "execute_rotate_content_keys"): {
        "python": ["execute_governance_action", "governance_execute"],
        "typescript": ["executeGovernanceAction", "contextExecuteGovernanceAction"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "propose_governance_action_checked"): {
        "python": ["propose_governance_action", "governance_propose"],
        "typescript": ["proposeGovernanceAction", "contextGovernancePropose"],
        "kotlin": ["governancePropose"],
        "swift": ["proposeGovernanceAction"],
    },
    # EventLog — all operations live on the SCP class under eventLog* prefix in TS
    ("EventLog", "query"): {
        "python": ["event_log_query"],
        "typescript": ["eventLogQuery"],
        "kotlin": ["eventLogQuery"],
    },
    ("EventLog", "verify"): {
        "python": ["event_log_verify"],
        "typescript": ["eventLogVerify"],
        "kotlin": ["verify"],
        "swift": ["verify"],
    },
    ("EventLog", "checkpoint"): {
        "python": ["Checkpoint"],
        "typescript": ["eventLogCheckpoint"],
        "kotlin": ["eventLogCheckpoint"],
        "swift": ["Checkpoint"],
    },
    ("EventLog", "checkpoint_by_did"): {
        "python": ["event_log_checkpoint_by_did"],
        "typescript": ["eventLogCheckpointByDid"],
        "kotlin": ["eventLogCheckpointByDid"],
        "swift": ["eventLogCheckpointByDid"],
    },
    ("EventLog", "signed_checkpoint"): {
        "python": ["SignedCheckpoint"],
        "typescript": ["eventLogCheckpoint"],
        "kotlin": ["eventLogCheckpoint"],
        "swift": ["generateEventLogCheckpoint"],
    },
    # Transport
    ("Transport", "connect"): {
        "python": ["connect_relay"],
    },
    ("Transport", "status"): {
        "python": ["relay_status"],
    },
    # configure_local_transport already carries partial domain prefix in the op
    # name; the auto-generated domain_snake 'transport_configure_local_transport'
    # is not what the SDKs expose.
    ("Transport", "configure_local_transport"): {
        "python": ["configure_local_transport"],
        "typescript": ["configureLocalTransport"],
        "kotlin": ["configureLocalTransport"],
        "swift": ["configureLocalTransport"],
    },
    # Media
    ("Media", "check_capability"): {
        "python": ["check_media_capability"],
    },
    # Discovery -- discover is `discoverContexts` in TS, `discover` in Kotlin,
    # and `contextDiscover` in Swift (generated UniFFI binding)
    ("Discovery", "discover"): {
        "python": ["discover", "discover_contexts"],
        "typescript": ["discoverContexts"],
        "kotlin": ["discover", "contextDiscover"],
        "swift": ["contextDiscover"],
    },
    ("Discovery", "scope_register"): {
        "python": ["scope_register"],
        "typescript": ["scopeRegister"],
        "kotlin": ["scopeRegister"],
        "swift": ["scopeRegister"],
    },
    ("Discovery", "scope_lookup"): {
        "python": ["scope_lookup"],
        "typescript": ["scopeLookup"],
        "kotlin": ["scopeLookup"],
        "swift": ["scopeLookup"],
    },
    ("Discovery", "scope_deregister"): {
        "python": ["scope_deregister"],
        "typescript": ["scopeDeregister"],
        "kotlin": ["scopeDeregister"],
        "swift": ["scopeDeregister"],
    },
    # Sync
    ("Sync", "get_policy"): {
        "python": ["get_policy"],
        "typescript": ["getSyncPolicy"],
    },
    ("Sync", "classify_offline"): {
        "python": ["classify_offline"],
    },
    # UCAN -- TypeScript uses validateUcan/mintUcan/revokeUcan/delegateUcan
    ("UCAN", "validate"): {
        "typescript": ["validateUcan"],
    },
    ("UCAN", "mint"): {
        "typescript": ["mintUcan"],
    },
    ("UCAN", "revoke"): {
        "typescript": ["revokeUcan"],
    },
    ("UCAN", "delegate"): {
        "typescript": ["delegateUcan"],
    },
    # UCAN.evaluate -- the structured read-only diagnostic (ADR-059, §7.2.4).
    # All four bindings expose an idiomatic wrapper over the typed
    # CapabilityValidationRecord and consume it inside their evaluate_trust /
    # evaluateTrust trust-signal wrapper (Python SCP.ucan_evaluate, TypeScript
    # SCP.ucanEvaluate, Kotlin SCP.ucanEvaluate (Scp.kt), Swift SCP.ucanEvaluate
    # (Trust.swift)).
    ("UCAN", "evaluate"): {
        "python": ["ucan_evaluate", "evaluate_trust"],
        "typescript": ["ucanEvaluate", "evaluateTrust"],
        "kotlin": ["ucanEvaluate", "evaluateTrust"],
        "swift": ["ucanEvaluate", "evaluateTrust"],
    },
    # MCP
    ("MCP", "serve"): {
        "python": ["serve_mcp", "McpServer"],
        "typescript": ["serve"],
        "swift": ["serve"],
    },
    ("MCP", "connect_client"): {
        "python": ["McpClient"],
        "typescript": ["mcpClientConnectStdio", "mcpClientConnectSse"],
        "swift": ["McpClient", "connect"],
    },
    # Identity -- Swift uses bare method names without domain prefix
    ("Identity", "add_agent_key"): {
        "swift": ["addAgentKey"],
    },
    ("Identity", "rotate_agent_key"): {
        "swift": ["rotateAgentKey"],
    },
    ("Identity", "remove_agent_key"): {
        "swift": ["removeAgentKey"],
    },
    # Identity -- identity_remove / identity_remove_if_present already carry the
    # domain prefix in the op name itself; the auto-generated domain_snake form
    # would be 'identity_identity_remove' (double-prefix), so explicit aliases
    # are required.
    ("Identity", "identity_remove"): {
        "python": ["identity_remove"],
        "typescript": ["identityRemove"],
        "kotlin": ["identityRemove"],
        "swift": ["identityRemove"],
    },
    ("Identity", "identity_remove_if_present"): {
        "python": ["identity_remove_if_present"],
        "typescript": ["identityRemoveIfPresent"],
        "kotlin": ["identityRemoveIfPresent"],
        "swift": ["identityRemoveIfPresent"],
    },
    # Context -- bare method names used across SDKs
    ("Context", "reconnect"): {
        "python": ["reconnect"],
        "typescript": ["reconnect"],
        "kotlin": ["reconnect"],
    },
    # Context -- ADR-049 Phase 2J joiner handshake.
    #
    # reserve_key_package NEEDS an explicit mapping: its auto-generated
    # domain-prefixed candidate is context_reserve_key_package, which does not
    # match the real SDK symbols (reserve_key_package / reserveKeyPackage).
    #
    # join_from_welcome needs NO entry: the auto-generated domain_snake for
    # ("Context", "join_from_welcome") is already context_join_from_welcome
    # (single prefix), so it matches the real symbols with no alias required.
    ("Context", "reserve_key_package"): {
        "python": ["reserve_key_package"],
        "typescript": ["reserveKeyPackage"],
        "kotlin": ["reserveKeyPackage"],
        "swift": ["reserveKeyPackage"],
    },
    # invite_member (ADR-049 Phase 2J / FFI-02 Option A) NEEDS an explicit
    # mapping: its auto-generated domain-prefixed candidate is
    # context_invite_member, which does not match the real SDK symbols
    # (invite_member / inviteMember). Peer of reserve_key_package above.
    ("Context", "invite_member"): {
        "python": ["invite_member"],
        "typescript": ["inviteMember"],
        "kotlin": ["inviteMember"],
        "swift": ["inviteMember"],
    },
    ("Context", "set_economic_policy"): {
        "python": ["set_economic_policy"],
    },
    ("Context", "get_economic_policy"): {
        "python": ["get_economic_policy"],
    },
    ("Context", "validate_params"): {
        "python": ["validate_context_params"],
        "typescript": ["validateContextParams"],
        "kotlin": ["validateContextParams"],
        "swift": ["validateParams"],
    },
    ("Context", "validate_admission"): {
        "python": ["validate_admission"],
        "typescript": ["validateAdmission"],
        "kotlin": ["validateAdmission"],
        "swift": ["validateAdmission"],
    },
    ("Context", "evaluate_invitation"): {
        "python": ["evaluate_invitation"],
        "typescript": ["evaluateInvitation"],
        "kotlin": ["evaluateInvitation"],
        "swift": ["evaluateInvitation"],
    },
    ("Context", "validate_capability_declaration"): {
        "python": ["validate_capability_declaration"],
        "typescript": ["validateCapabilityDeclaration"],
        "swift": ["validateCapabilityDeclaration"],
    },
    ("Context", "template_get_params"): {
        "python": ["template_get_params"],
        "typescript": ["templateGetParams"],
        "kotlin": ["templateGetParams"],
        "swift": ["templateGetParams"],
    },
    ("Context", "validate_against_template"): {
        "python": ["validate_against_template"],
        "typescript": ["validateAgainstTemplate"],
        "kotlin": ["validateAgainstTemplate"],
        "swift": ["validateAgainstTemplate"],
    },
    # Messaging -- broadcast operations use bare names in all SDKs
    ("Messaging", "broadcast_subscribe"): {
        "python": ["broadcast_subscribe"],
        "typescript": ["broadcastSubscribe"],
        "kotlin": ["broadcastSubscribe"],
        "swift": ["broadcastSubscribe"],
    },
    ("Messaging", "broadcast_publish"): {
        "python": ["broadcast_publish"],
        "typescript": ["broadcastPublish"],
        "kotlin": ["broadcastPublish"],
        "swift": ["broadcastPublish"],
    },
    ("Messaging", "broadcast_publish_asset"): {
        "python": ["broadcast_publish_asset"],
        "typescript": ["broadcastPublishAsset"],
        "kotlin": ["broadcastPublishAsset"],
        "swift": ["broadcastPublishAsset"],
    },
    ("Messaging", "broadcast_publish_assets"): {
        "python": ["broadcast_publish_assets"],
        "typescript": ["broadcastPublishAssets"],
        "kotlin": ["broadcastPublishAssets"],
        "swift": ["broadcastPublishAssets"],
    },
    ("Messaging", "broadcast_block_subscriber"): {
        "python": ["broadcast_block_subscriber"],
        "typescript": ["broadcastBlockSubscriber"],
        "kotlin": ["broadcastBlockSubscriber"],
        "swift": ["broadcastBlockSubscriber"],
    },
    ("Messaging", "broadcast_unblock_subscriber"): {
        "python": ["broadcast_unblock_subscriber"],
        "typescript": ["broadcastUnblockSubscriber"],
        "kotlin": ["broadcastUnblockSubscriber"],
        "swift": ["broadcastUnblockSubscriber"],
    },
    ("Messaging", "broadcast_handle_key_request"): {
        "python": ["broadcast_handle_key_request"],
        "typescript": ["broadcastHandleKeyRequest"],
        "kotlin": ["broadcastHandleKeyRequest"],
        "swift": ["broadcastHandleKeyRequest"],
    },
    ("Messaging", "broadcast_open_key"): {
        "python": ["broadcast_open_key"],
        "typescript": ["broadcastOpenKey"],
        "kotlin": ["broadcastOpenKey"],
        "swift": ["broadcastOpenKey"],
    },
    # Outlets -- all SDKs use the outlet-prefixed method name for the renamed
    # outlet domain (outlet_register / outletRegister / ...).
    ("Outlets", "register"): {
        "python": ["outlet_register"],
        "typescript": ["outletRegister"],
        "kotlin": ["outletRegister"],
        "swift": ["outletRegister"],
    },
    ("Outlets", "invoke"): {
        "python": ["outlet_invoke"],
        "typescript": ["outletInvoke"],
        "kotlin": ["outletInvoke"],
        "swift": ["outletInvoke"],
    },
    ("Outlets", "verify"): {
        "python": ["outlet_verify"],
        "typescript": ["outletVerify"],
        "kotlin": ["outletVerify"],
        "swift": ["outletVerify"],
    },
    ("Outlets", "invoke_cross_context"): {
        "python": ["outlet_invoke_cross_context"],
        "typescript": ["outletInvokeCrossContext"],
        "kotlin": ["outletInvokeCrossContext"],
        "swift": ["outletInvokeCrossContext"],
    },
    ("Outlets", "invoke_cross_context_saga"): {
        "python": ["outlet_invoke_cross_context_saga"],
        "typescript": ["outletInvokeCrossContextSaga"],
        "kotlin": ["outletInvokeCrossContextSaga"],
        "swift": ["outletInvokeCrossContextSaga"],
    },
    ("Outlets", "session_create"): {
        "python": ["outlet_session_create"],
        "typescript": ["outletSessionCreate"],
        "kotlin": ["outletSessionCreate"],
        "swift": ["outletSessionCreate"],
    },
    ("Outlets", "session_invoke"): {
        "python": ["outlet_session_invoke"],
        "typescript": ["outletSessionInvoke"],
        "kotlin": ["outletSessionInvoke"],
        "swift": ["outletSessionInvoke"],
    },
    ("Outlets", "session_close"): {
        "python": ["outlet_session_close"],
        "typescript": ["outletSessionClose"],
        "kotlin": ["outletSessionClose"],
        "swift": ["outletSessionClose"],
    },
    ("Outlets", "interface_expose"): {
        "python": ["outlet_interface_expose"],
        "typescript": ["outletInterfaceExpose"],
        "kotlin": ["outletInterfaceExpose"],
        "swift": ["outletInterfaceExpose"],
    },
    ("Outlets", "interface_accept"): {
        "python": ["outlet_interface_accept"],
        "typescript": ["outletInterfaceAccept"],
        "kotlin": ["outletInterfaceAccept"],
        "swift": ["outletInterfaceAccept"],
    },
    ("Outlets", "interface_revoke"): {
        "python": ["outlet_interface_revoke"],
        "typescript": ["outletInterfaceRevoke"],
        "kotlin": ["outletInterfaceRevoke"],
        "swift": ["outletInterfaceRevoke"],
    },
    # Trust -- bare names in all SDKs
    ("Trust", "evaluate_trust"): {
        "python": ["evaluate_trust"],
        "typescript": ["evaluateTrust"],
        "kotlin": ["evaluateTrust"],
        "swift": ["evaluateTrust"],
    },
    ("Trust", "aggregate_trust_input"): {
        "python": ["aggregate_trust_input"],
        "typescript": ["aggregateTrustInput"],
        "kotlin": ["aggregateTrustInput"],
        "swift": ["aggregateTrustInput"],
    },
    ("Trust", "verify_participation_requirements"): {
        "python": ["verify_participation_requirements"],
        "typescript": ["verifyParticipationRequirements"],
        "kotlin": ["verifyParticipationRequirements"],
        "swift": ["verifyParticipationRequirements"],
    },
    ("Trust", "check_capability_requirements"): {
        "python": ["check_capability_requirements"],
        "typescript": ["checkCapabilityRequirements"],
        "kotlin": ["checkCapabilityRequirements"],
        "swift": ["checkCapabilityRequirements"],
    },
    ("Trust", "participation_record"): {
        "python": ["participation_record"],
        "typescript": ["participationRecord"],
        "kotlin": ["participationRecord"],
        "swift": ["participationRecord"],
    },
    ("Trust", "trust_create_challenge"): {
        "python": ["trust_create_challenge"],
        "typescript": ["trustCreateChallenge"],
        "kotlin": ["trustCreateChallenge"],
        "swift": ["trustCreateChallenge"],
    },
    ("Trust", "trust_verify_attestation"): {
        "python": ["trust_verify_attestation"],
        "typescript": ["trustVerifyAttestation"],
        "kotlin": ["trustVerifyAttestation"],
        "swift": ["trustVerifyAttestation"],
    },
    ("Trust", "trust_verify_response"): {
        "python": ["trust_verify_response"],
        "typescript": ["trustVerifyResponse"],
        "kotlin": ["trustVerifyResponse"],
        "swift": ["trustVerifyResponse"],
    },
    # Discovery -- bare/different names across SDKs
    ("Discovery", "parse_address"): {
        "python": ["parse_address"],
        "typescript": ["parseAddress"],
    },
    ("Discovery", "create_query"): {
        "python": ["create_query"],
        "typescript": ["createQuery"],
    },
    ("Discovery", "normalize_address"): {
        "python": ["normalize_address"],
        "typescript": ["normalizeAddress"],
    },
    ("Discovery", "address_resolve"): {
        "python": ["address_resolve"],
        "typescript": ["addressResolve"],
        "kotlin": ["addressResolve"],
        "swift": ["addressResolve"],
    },
    ("Discovery", "petname_set"): {
        "python": ["petname_set"],
        "typescript": ["petnameSet"],
        "kotlin": ["petnameSet"],
        "swift": ["petnameSet"],
    },
    ("Discovery", "petname_remove"): {
        "python": ["petname_remove"],
        "typescript": ["petnameRemove"],
        "kotlin": ["petnameRemove"],
        "swift": ["petnameRemove"],
    },
    ("Discovery", "petname_set_context"): {
        "python": ["petname_set_context"],
        "typescript": ["petnameSetContext"],
        "kotlin": ["petnameSetContext"],
        "swift": ["petnameSetContext"],
    },
    ("Discovery", "petname_remove_context"): {
        "python": ["petname_remove_context"],
        "typescript": ["petnameRemoveContext"],
        "kotlin": ["petnameRemoveContext"],
        "swift": ["petnameRemoveContext"],
    },
    ("Discovery", "petname_resolve_did"): {
        "python": ["petname_resolve_did"],
        "typescript": ["petnameResolveDid"],
        "kotlin": ["petnameResolveDid"],
        "swift": ["petnameResolveDid"],
    },
    ("Discovery", "petname_resolve_context"): {
        "python": ["petname_resolve_context"],
        "typescript": ["petnameResolveContext"],
        "kotlin": ["petnameResolveContext"],
        "swift": ["petnameResolveContext"],
    },
    ("Discovery", "petname_get_for_did"): {
        "python": ["petname_get_for_did"],
        "typescript": ["petnameGetForDid"],
        "kotlin": ["petnameGetForDid"],
        "swift": ["petnameGetForDid"],
    },
    ("Discovery", "petname_get_for_context"): {
        "python": ["petname_get_for_context"],
        "typescript": ["petnameGetForContext"],
        "kotlin": ["petnameGetForContext"],
        "swift": ["petnameGetForContext"],
    },
    ("Discovery", "petname_apply_event"): {
        "python": ["petname_apply_event"],
        "typescript": ["petnameApplyEvent"],
        "kotlin": ["petnameApplyEvent"],
        "swift": ["petnameApplyEvent"],
    },
    ("Discovery", "petname_did_count"): {
        "python": ["petname_did_count"],
        "typescript": ["petnameDidCount"],
        "kotlin": ["petnameDidCount"],
        "swift": ["petnameDidCount"],
    },
    ("Discovery", "petname_context_count"): {
        "python": ["petname_context_count"],
        "typescript": ["petnameContextCount"],
        "kotlin": ["petnameContextCount"],
        "swift": ["petnameContextCount"],
    },
    ("Discovery", "handle_register"): {
        "python": ["handle_register"],
        "typescript": ["handleRegister"],
        "kotlin": ["handleRegister"],
        "swift": ["handleRegister"],
    },
    ("Discovery", "handle_lookup"): {
        "python": ["handle_lookup"],
        "typescript": ["handleLookup"],
        "kotlin": ["handleLookup"],
        "swift": ["handleLookup"],
    },
    ("Discovery", "handle_deregister"): {
        "python": ["handle_deregister"],
        "typescript": ["handleDeregister"],
        "kotlin": ["handleDeregister"],
        "swift": ["handleDeregister"],
    },
    # Economy -- Python SDK uses bare names (no domain prefix)
    ("Economy", "estimate_cost"): {
        "python": ["estimate_cost"],
    },
    ("Economy", "policy_requires_payment"): {
        "python": ["policy_requires_payment"],
    },
    ("Economy", "auto_accept_blocked"): {
        "python": ["auto_accept_blocked"],
    },
    ("Economy", "check_policy_lock"): {
        "python": ["check_policy_lock"],
    },
    ("Economy", "validate_policy_change"): {
        "python": ["validate_policy_change"],
    },
    ("Economy", "evaluate_formula"): {
        "python": ["evaluate_formula"],
    },
    # Python uses the bare verify_payment_receipts function (no domain prefix);
    # the auto-generated domain_snake form would be 'economy_verify_payment_receipts'.
    ("Economy", "verify_payment_receipts"): {
        "python": ["verify_payment_receipts"],
    },
    # Sync -- Python uses bare get_policy (no domain prefix)
    # (TypeScript getSyncPolicy is already in the entry above)
    # Provenance -- Kotlin uses bare evaluateQuality
    ("Provenance", "evaluate_quality"): {
        "python": ["evaluate_provenance_quality"],
        "typescript": ["evaluateProvenanceQuality"],
        "kotlin": ["evaluateQuality"],
        "swift": ["evaluateProvenanceQuality"],
    },
    # Media -- Python SDK uses bare names without domain prefix
    ("Media", "initiate_session"): {
        "python": ["initiate_session"],
    },
    ("Media", "activate_session"): {
        "python": ["activate_session"],
    },
    ("Media", "join_session"): {
        "python": ["join_session"],
    },
    ("Media", "end_session"): {
        "python": ["end_session"],
    },
    ("Media", "create_offer"): {
        "python": ["create_offer"],
    },
    ("Media", "create_answer"): {
        "python": ["create_answer"],
    },
    ("Media", "create_ice_candidate"): {
        "python": ["create_ice_candidate"],
    },
    ("Media", "create_session_end"): {
        "python": ["create_session_end"],
    },
    ("Media", "send_signaling"): {
        "python": ["send_signaling"],
    },
    ("Media", "verify_sender_attribution"): {
        "python": ["verify_sender_attribution"],
    },
    # Auth -- scpid_* ops already carry the domain prefix in the op name;
    # the auto-generated domain_snake form would be 'auth_scpid_*' (wrong).
    ("Auth", "scpid_challenge"): {
        "python": ["scpid_challenge"],
        "typescript": ["scpidChallenge"],
        "kotlin": ["scpidChallenge"],
        "swift": ["scpidChallenge"],
    },
    ("Auth", "scpid_sign"): {
        "python": ["scpid_sign"],
        "typescript": ["scpidSign"],
        "kotlin": ["scpidSign"],
        "swift": ["scpidSign"],
    },
    ("Auth", "scpid_verify"): {
        "python": ["scpid_verify"],
        "typescript": ["scpidVerify"],
        "kotlin": ["scpidVerify"],
        "swift": ["scpidVerify"],
    },
    # Lifecycle -- suspend/resume use bare names in all SDKs
    ("Lifecycle", "suspend"): {
        "python": ["suspend"],
        "typescript": ["suspend"],
        "kotlin": ["suspendInstance"],
        "swift": ["suspend"],
    },
    ("Lifecycle", "resume"): {
        "python": ["resume"],
        "typescript": ["resume"],
        "kotlin": ["resume"],
        "swift": ["resume"],
    },
    # Bridge -- Python uses bare 'register' and 'evaluate_trust'.
    # TypeScript does not expose bridge_register as a named public SDK function
    # (matrix: typescript=false); the entry below covers only the SDKs that do.
    ("Bridge", "register"): {
        "python": ["register"],
    },
    ("Bridge", "evaluate_trust"): {
        "python": ["evaluate_trust"],
    },
    # Server -- Kotlin uses domain-prefixed bare names (e.g. relayStartInMemory);
    # Python uses domain-prefixed snake_case (relay_start_in_memory);
    # TypeScript uses domain-prefixed camelCase (relayStartInMemory).
    # The op names already carry the sub-domain prefix (relay_/node_) so
    # auto-generated domain_snake would be 'server_relay_start_in_memory' (wrong).
    ("Server", "relay_start_in_memory"): {
        "python": ["relay_start_in_memory", "start_in_memory"],
        "typescript": ["relayStartInMemory", "startInMemory"],
        "kotlin": ["relayStartInMemory"],
        "swift": ["startInMemory"],
    },
    ("Server", "relay_start_local"): {
        "python": ["relay_start_local", "start_local"],
        "typescript": ["relayStartLocal", "startLocal"],
        "kotlin": ["relayStartLocal"],
        "swift": ["startLocal"],
    },
    ("Server", "relay_shutdown"): {
        "python": ["shutdown"],
        "typescript": ["shutdown"],
        "kotlin": ["relayShutdown"],
        "swift": ["shutdown"],
    },
    ("Server", "node_start_in_memory"): {
        "python": ["node_start_in_memory", "start_in_memory"],
        "typescript": ["nodeStartInMemory", "startInMemory"],
        "kotlin": ["nodeStartInMemory"],
        "swift": ["startInMemory"],
    },
    ("Server", "node_start_local"): {
        "python": ["node_start_local", "start_local"],
        "typescript": ["nodeStartLocal", "startLocal"],
        "kotlin": ["nodeStartLocal"],
        "swift": ["startLocal"],
    },
    ("Server", "node_shutdown"): {
        "python": ["shutdown"],
        "typescript": ["shutdown"],
        "kotlin": ["nodeShutdown"],
        "swift": ["shutdown"],
    },
    ("Server", "node_enable_site_projection"): {
        "python": ["enable_site_projection"],
        "typescript": ["enableSiteProjection"],
        "kotlin": ["nodeEnableSiteProjection"],
        "swift": ["enableSiteProjection"],
    },
    ("Server", "node_commit_deploy"): {
        "python": ["commit_deploy"],
        "typescript": ["commitDeploy"],
        "kotlin": ["nodeCommitDeploy"],
        "swift": ["commitDeploy"],
    },
    ("Server", "node_rollback_deploy"): {
        "python": ["rollback_deploy"],
        "typescript": ["rollbackDeploy"],
        "kotlin": ["nodeRollbackDeploy"],
        "swift": ["rollbackDeploy"],
    },
    ("Server", "node_disable_site_projection"): {
        "python": ["disable_site_projection"],
        "typescript": ["disableSiteProjection"],
        "kotlin": ["nodeDisableSiteProjection"],
        "swift": ["disableSiteProjection"],
    },
    # Context -- receive needs mapping in Kotlin
    ("Context", "receive"): {
        "typescript": ["contextSubscribe"],
        "kotlin": ["contextSubscribe"],
    },
    # Context -- consequence_rules surfaced via the existing create() and
    # context_create wrappers (parameter, not a separate function).
    ("Context", "create_with_consequence_rules"): {
        "python": ["create", "context_create"],
        "typescript": ["create", "contextCreate"],
        "swift": ["contextCreate"],
    },
    ("Context", "restore_context"): {
        "python": ["restore_context"],
        "typescript": ["contextRestore"],
        "kotlin": ["restoreContext"],
        "swift": ["restoreContext"],
    },
    ("Context", "restore_all_contexts"): {
        "python": ["restore_all_contexts"],
        "typescript": ["contextRestoreAll"],
        "kotlin": ["restoreAllContexts"],
        "swift": ["restoreAllContexts"],
    },
    ("Context", "import_context"): {
        "swift": ["contextImport"],
    },
    # Messaging -- spending_ucan_jwt is a parameter on send() / context_send
    # exposed via existing wrappers in all four SDKs.
    ("Messaging", "send_with_spending_ucan"): {
        "python": ["send", "context_send"],
        "typescript": ["send", "contextSend"],
        "kotlin": ["contextSend"],
        "swift": ["send"],
    },
    # Messaging -- spending_ucan_jwt parameter on join() / context_join.
    # Bridge drift documented in matrix notes; tree-sitter sees the wrapper
    # signature in PyO3, NAPI TS, and Swift surfaces.
    ("Messaging", "join_with_spending_ucan"): {
        "python": ["join", "context_join"],
        "typescript": ["join", "contextJoin"],
        "swift": ["joinContext"],
    },
    # Trust -- consequence rule validation is exercised via aggregate_trust_input
    # (consequenceRulesJson parameter is parsed and validated in all four SDKs).
    ("Trust", "consequence_rule_validate"): {
        "python": ["aggregate_trust_input"],
        "typescript": ["aggregateTrustInput"],
        "kotlin": ["aggregateTrustInput"],
        "swift": ["aggregateTrustInput"],
    },
    ("Trust", "evaluate_consequence_rules"): {
        "python": ["aggregate_trust_input"],
        "typescript": ["aggregateTrustInput"],
        "kotlin": ["aggregateTrustInput"],
        "swift": ["aggregateTrustInput"],
    },
    # Lifecycle: constructor / property / factory naming across SDKs.
    ("Lifecycle", "scp_new"): {
        "python": ["SCP"],
        "typescript": ["SCP"],
        "swift": ["SCP"],
        "kotlin": ["SCP"],
    },
    ("Lifecycle", "scp_instance_id"): {
        "python": ["instance_id"],
        "typescript": ["instanceId"],
        "swift": ["instanceId"],
        "kotlin": ["instanceId"],
    },
    ("Lifecycle", "scp_with_storage_in_memory"): {
        "python": ["SCP"],
        "typescript": ["SCP"],
        "swift": ["withStorage", "SCP"],
        "kotlin": ["withStorage", "SCP"],
    },
    ("Lifecycle", "with_storage_sqlite"): {
        "python": ["SCP"],
        "typescript": ["SCP"],
        "swift": ["withStorage"],
        "kotlin": ["withSqlite"],
    },
    ("Lifecycle", "shutdown_timeout"): {
        "python": ["shutdown"],
        "typescript": ["shutdown"],
        "swift": ["shutdown"],
        "kotlin": ["shutdown"],
    },
    ("Lifecycle", "add_relay_url"): {
        "python": ["transport_add_relay"],
        "typescript": ["transportAddRelay", "configureRelayTransport"],
        "swift": ["addRelay"],
        "kotlin": ["addRelay"],
    },
}


# ---------------------------------------------------------------------------
# Tree-sitter helpers
# ---------------------------------------------------------------------------


def _node_text(node: "Node") -> str:
    """Return the decoded text of a tree-sitter node, or '' if None.

    Decodes with errors="replace" so an identifier node containing invalid
    UTF-8 cannot raise and abort the whole run.
    """
    return (node.text or b"").decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Name conversion helpers
# ---------------------------------------------------------------------------


def _to_camel(snake: str) -> str:
    """Convert snake_case to camelCase."""
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# ---------------------------------------------------------------------------
# Tree-sitter parsers (initialized once)
# ---------------------------------------------------------------------------

_PARSERS: dict[str, Parser] = {}


def _get_parser(sdk: str) -> Parser:
    """Return a cached tree-sitter Parser for the given SDK language."""
    if sdk not in _PARSERS:
        lang_map = {
            "python": Language(tspython.language()),
            "typescript": Language(tstypescript.language_typescript()),
            "kotlin": Language(tskotlin.language()),
            "swift": Language(tsswift.language()),
        }
        _PARSERS[sdk] = Parser(lang_map[sdk])
    return _PARSERS[sdk]


# ---------------------------------------------------------------------------
# AST symbol extraction — per-language
# ---------------------------------------------------------------------------


def _get_func_name_from_definition(func_node: Node) -> str | None:
    """Extract the function/method name from a function_definition node."""
    for child in func_node.children:
        if child.type == "identifier":
            return _node_text(child) or None
    return None


def _extract_python_methods_from_block(
    class_name: str, block_node: Node, symbols: set[str]
) -> None:
    """Extract method names from a Python class body block.

    Handles both plain function_definition and decorated_definition
    (e.g., @classmethod, @staticmethod, @property) inside the block.
    """
    for member in block_node.children:
        if member.type == "function_definition":
            name = _get_func_name_from_definition(member)
            if name:
                symbols.add(f"{class_name}.{name}")
                symbols.add(name)

        elif member.type == "decorated_definition":
            # @classmethod / @staticmethod / @property decorated methods
            for inner in member.children:
                if inner.type == "function_definition":
                    name = _get_func_name_from_definition(inner)
                    if name:
                        symbols.add(f"{class_name}.{name}")
                        symbols.add(name)


def _extract_python_class(class_node: Node, symbols: set[str]) -> None:
    """Extract class name and all its methods from a class_definition node."""
    class_name = None
    for child in class_node.children:
        if child.type == "identifier":
            class_name = _node_text(child) or None
            break
    if not class_name:
        return

    symbols.add(class_name)
    for child in class_node.children:
        if child.type == "block":
            _extract_python_methods_from_block(class_name, child, symbols)


def _extract_python_symbols(root_node: Node) -> set[str]:
    """Extract function and class.method names from a Python AST.

    Collects:
      - Top-level function names (including decorated, e.g., @decorated)
      - Class names
      - Method names as both "ClassName.method_name" and bare "method_name"
      - Decorated methods (@classmethod, @staticmethod, @property)
    """
    symbols: set[str] = set()

    for child in root_node.children:
        if child.type == "function_definition":
            name = _get_func_name_from_definition(child)
            if name:
                symbols.add(name)

        elif child.type == "class_definition":
            _extract_python_class(child, symbols)

        elif child.type == "decorated_definition":
            # Handle top-level decorated functions and classes
            for inner in child.children:
                if inner.type == "function_definition":
                    name = _get_func_name_from_definition(inner)
                    if name:
                        symbols.add(name)
                elif inner.type == "class_definition":
                    _extract_python_class(inner, symbols)

    return symbols


def _extract_typescript_symbols(root_node: Node) -> set[str]:
    """Extract exported symbols from a TypeScript AST.

    Collects:
      - Exported function names (export_statement -> function_declaration)
      - Exported const names (export_statement -> lexical_declaration)
      - Exported class names and their methods
      - Re-exported names (export { X } from './module')
      - Exported interface names and type aliases
    """
    symbols: set[str] = set()

    for child in root_node.children:
        if child.type != "export_statement":
            continue

        for sub in child.children:
            if sub.type == "function_declaration":
                for fc in sub.children:
                    if fc.type == "identifier":
                        symbols.add(_node_text(fc))
                        break

            elif sub.type == "class_declaration":
                class_name = None
                for fc in sub.children:
                    if fc.type == "type_identifier":
                        class_name = _node_text(fc) or None
                        break
                if class_name:
                    symbols.add(class_name)
                    # Extract methods from class_body
                    for fc in sub.children:
                        if fc.type == "class_body":
                            for member in fc.children:
                                if member.type == "method_definition":
                                    for mc in member.children:
                                        if mc.type == "property_identifier":
                                            method_name = _node_text(mc)
                                            symbols.add(f"{class_name}.{method_name}")
                                            symbols.add(method_name)
                                            break
                                elif member.type == "public_field_definition":
                                    # Handle class fields (arrow function
                                    # properties)
                                    for mc in member.children:
                                        if mc.type == "property_identifier":
                                            symbols.add(_node_text(mc))
                                            break

            elif sub.type == "lexical_declaration":
                # export const myFunc = ...
                for decl in sub.children:
                    if decl.type == "variable_declarator":
                        for dc in decl.children:
                            if dc.type == "identifier":
                                symbols.add(_node_text(dc))
                                break

            elif sub.type == "interface_declaration":
                for fc in sub.children:
                    if fc.type == "type_identifier":
                        symbols.add(_node_text(fc))
                        break

            elif sub.type == "type_alias_declaration":
                for fc in sub.children:
                    if fc.type == "type_identifier":
                        symbols.add(_node_text(fc))
                        break

            elif sub.type == "export_clause":
                # export { X, Y as Z } from './module'
                for spec in sub.children:
                    if spec.type == "export_specifier":
                        ids = [c for c in spec.children if c.type == "identifier"]
                        if len(ids) >= 2:
                            # export { X as Y } -- the exported name is Y
                            symbols.add(_node_text(ids[1]))
                        elif len(ids) == 1:
                            symbols.add(_node_text(ids[0]))

    return symbols


def _has_kotlin_visibility(node: Node, exclude: set[str]) -> bool:
    """Check if a Kotlin node has a visibility modifier in the exclude set.

    In Kotlin, default visibility is public (no modifier needed).
    Returns True if the node has a modifier that should be excluded.
    """
    for child in node.children:
        if child.type == "modifiers":
            for mod in child.children:
                if mod.type == "visibility_modifier":
                    vis_text = _node_text(mod).strip()
                    if vis_text in exclude:
                        return True
    return False


def _extract_kotlin_symbols(root_node: Node) -> set[str]:
    """Extract public symbols from a Kotlin AST.

    In Kotlin, the default visibility is public, so we include everything
    that is NOT explicitly private or internal.

    Collects:
      - Top-level function names
      - Class/object names and their methods
      - Companion object methods as ClassName.method
    """
    symbols: set[str] = set()
    exclude_vis = {"private", "internal"}
    # Kotlin allows backtick-escaped identifiers (`` `addRelay` ``), and
    # UniFFI-generated bindings backtick-quote every name. Strip the ticks so
    # the captured symbol matches the plain operation name.
    id_types = ("identifier", "simple_identifier")

    def _first_ident(node: Node) -> str | None:
        for c in node.children:
            if c.type in id_types:
                return _node_text(c).strip("`") or None
        return None

    def _property_name(prop_node: Node) -> str | None:
        # `val instanceId: ULong` -> property_declaration > variable_declaration
        # > (simple_)identifier. Some grammars place the identifier directly.
        for c in prop_node.children:
            if c.type == "variable_declaration":
                name = _first_ident(c)
                if name:
                    return name
            if c.type in id_types:
                return _node_text(c).strip("`") or None
        return None

    type_decls = ("class_declaration", "object_declaration", "interface_declaration")

    def _walk(node: Node, class_name: str | None) -> None:
        """Recursively collect public function/property names, tracking the
        nearest enclosing type so methods land as both bare and `Type.method`.

        Recursive (not just top-level + class_body) because UniFFI-generated
        Kotlin nests the public API on interfaces and override-method bodies
        whose container node types vary across the grammar; a depth-bounded
        walk missed them (e.g. `TransportManager.addRelay`). Over-capture is
        the safe failure mode for a fail-closed coverage gate.
        """
        for child in node.children:
            t = child.type
            if t == "function_declaration":
                if not _has_kotlin_visibility(child, exclude_vis):
                    name = _first_ident(child)
                    if name:
                        symbols.add(name)
                        if class_name:
                            symbols.add(f"{class_name}.{name}")
                _walk(child, class_name)
            elif t == "property_declaration":
                if not _has_kotlin_visibility(child, exclude_vis):
                    name = _property_name(child)
                    if name:
                        symbols.add(name)
                        if class_name:
                            symbols.add(f"{class_name}.{name}")
            elif t in type_decls:
                if _has_kotlin_visibility(child, exclude_vis):
                    continue
                cname = _first_ident(child)
                if cname:
                    symbols.add(cname)
                _walk(child, cname)
            else:
                _walk(child, class_name)

    _walk(root_node, None)
    return symbols


def _extract_swift_symbols(root_node: Node) -> set[str]:
    """Extract public symbols from a Swift AST.

    Only collects symbols marked `public` (Swift default is internal).

    Collects:
      - public func names
      - public class/struct/enum/actor names and their public methods
      - public extension methods (attributed to the extended type)
      - public protocol method declarations
    """
    symbols: set[str] = set()

    def _is_public(node: Node) -> bool:
        """Check if a Swift node has a `public` visibility modifier."""
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type == "visibility_modifier":
                        if _node_text(mod).strip() == "public":
                            return True
        return False

    def _has_restrictive_visibility(node: Node) -> bool:
        """Check if a Swift node has private, internal, or fileprivate."""
        restrictive = {"private", "internal", "fileprivate"}
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type == "visibility_modifier":
                        if _node_text(mod).strip() in restrictive:
                            return True
        return False

    def _get_swift_type_name(node: Node) -> str | None:
        """Get the name of a class/struct/enum/actor/extension declaration."""
        for child in node.children:
            if child.type == "type_identifier":
                return _node_text(child) or None
            # Extensions use user_type > type_identifier
            if child.type == "user_type":
                for uc in child.children:
                    if uc.type == "type_identifier":
                        return _node_text(uc) or None
        return None

    def _extract_methods_from_body(
        type_name: str, body_node: Node, parent_is_public: bool
    ) -> None:
        """Extract methods from a class/struct/extension body."""
        for member in body_node.children:
            if member.type == "function_declaration":
                # Explicit private/internal/fileprivate overrides parent
                if _has_restrictive_visibility(member):
                    continue
                # In public extensions, methods without explicit visibility
                # inherit public. In classes/structs, they need explicit
                # public.
                is_public = _is_public(member) or parent_is_public
                if not is_public:
                    continue
                for mc in member.children:
                    if mc.type == "simple_identifier":
                        method_name = _node_text(mc)
                        symbols.add(f"{type_name}.{method_name}")
                        symbols.add(method_name)
                        break

    for child in root_node.children:
        if child.type == "function_declaration":
            if not _is_public(child):
                continue
            for fc in child.children:
                if fc.type == "simple_identifier":
                    symbols.add(_node_text(fc))
                    break

        elif child.type == "class_declaration":
            # Covers class, struct, enum, actor, extension
            if not _is_public(child):
                continue

            type_name = _get_swift_type_name(child)
            if type_name:
                # Don't add extension names as standalone symbols
                is_extension = any(c.type == "extension" for c in child.children)
                if not is_extension:
                    symbols.add(type_name)

                # Public extensions: methods inherit public visibility
                is_public_extension = is_extension

                for fc in child.children:
                    if fc.type in ("class_body", "enum_class_body"):
                        _extract_methods_from_body(type_name, fc, is_public_extension)

        elif child.type == "protocol_declaration":
            if not _is_public(child):
                continue
            proto_name = None
            for fc in child.children:
                if fc.type == "type_identifier":
                    proto_name = _node_text(fc) or None
                    break
            if proto_name:
                symbols.add(proto_name)
                for fc in child.children:
                    if fc.type == "protocol_body":
                        for member in fc.children:
                            if member.type == "protocol_function_declaration":
                                for mc in member.children:
                                    if mc.type == "simple_identifier":
                                        method_name = _node_text(mc)
                                        symbols.add(f"{proto_name}.{method_name}")
                                        symbols.add(method_name)
                                        break

    return symbols


# ---------------------------------------------------------------------------
# Extraction dispatcher
# ---------------------------------------------------------------------------

_EXTRACTORS: dict[str, Callable[[Node], set[str]]] = {
    "python": _extract_python_symbols,
    "typescript": _extract_typescript_symbols,
    "kotlin": _extract_kotlin_symbols,
    "swift": _extract_swift_symbols,
}


def _collect_sdk_symbols(sdk: str) -> set[str]:
    """Parse all source files for an SDK and return the union of extracted
    symbols."""
    sdk_path = SDK_PATHS[sdk]
    if not sdk_path.exists():
        return set()

    parser = _get_parser(sdk)
    extractor = _EXTRACTORS[sdk]
    ext = SDK_EXTENSIONS[sdk]
    all_symbols: set[str] = set()

    for filepath in sdk_path.rglob(ext):
        try:
            source = filepath.read_bytes()
        except OSError:
            continue

        # Parsing and extraction are wrapped too: a single unparseable file
        # (grammar quirk, malformed source) must skip that file, not abort the
        # whole run and silently weaken the gate to "no symbols extracted".
        try:
            tree = parser.parse(source)
            file_symbols = extractor(tree.root_node)
        except Exception:  # noqa: BLE001 - per-file robustness; skip and continue
            continue
        all_symbols.update(file_symbols)

    return all_symbols


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------


def _check_operation_in_sdk(
    sdk_symbols: set[str], sdk: str, domain: str, op_name: str
) -> bool:
    """Check whether the SDK's extracted symbols contain a symbol of the
    expected name for this operation.

    Strategy (in order):
      1. Explicit aliases from the ALIASES table
      2. Exact match against auto-generated name variants
         (snake_case, camelCase, domain-prefixed)

    Returns True if any check succeeds.

    Note: suffix/substring matching was intentionally removed. It allowed
    ~23 fabricated operation names to pass via suffix collision with common
    verbs. All legitimate cross-SDK name mappings must be explicit in ALIASES.
    """
    # 1. Check explicit aliases first
    alias_key = (domain, op_name)
    if alias_key in ALIASES and sdk in ALIASES[alias_key]:
        for alias in ALIASES[alias_key][sdk]:
            if alias in sdk_symbols:
                return True

    # 2. Generate name variants and check exact match.
    #    Only domain-prefixed forms are checked here.  Bare op_name/camel/pascal
    #    candidates were removed because they accepted any unrelated SDK symbol
    #    that happened to share the operation name (e.g. a `migrate` helper
    #    anywhere in the codebase satisfied `Identity/migrate`).  All legitimate
    #    cross-SDK name irregularities — where the SDK uses a name that is not
    #    the domain-prefixed form — must be registered in the ALIASES table above.
    camel = _to_camel(op_name)

    # Domain-prefixed variants
    domain_lower = domain.lower()
    domain_snake = f"{domain_lower}_{op_name}"
    domain_camel = _to_camel(domain_snake)

    candidates = [
        # Domain-prefixed
        domain_snake,  # messaging_send_message
        domain_camel,  # messagingSendMessage
        # Class.method patterns — use domain name as-is from JSON
        # (preserves EventLog, UCAN, MCP casing)
        f"{domain}.{op_name}",  # EventLog.verify
        f"{domain}.{camel}",
    ]

    for candidate in candidates:
        if candidate in sdk_symbols:
            return True

    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    if not MATRIX_PATH.exists():
        print(f"FAIL: Matrix file not found: {MATRIX_PATH}", file=sys.stderr)
        return 1

    try:
        with open(MATRIX_PATH, encoding="utf-8") as f:
            matrix = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"FAIL: could not parse matrix {MATRIX_PATH}: {e}", file=sys.stderr)
        return 1

    # Validate matrix shape before touching it. A malformed top-level shape
    # must produce a clean diagnostic and exit 1 — never an uncaught traceback.
    if not isinstance(matrix, dict) or not isinstance(matrix.get("capabilities"), list):
        print(
            "FAIL: matrix must be an object with a 'capabilities' array.",
            file=sys.stderr,
        )
        return 1

    # Pre-extract all SDK symbols via tree-sitter
    sdk_symbols: dict[str, set[str]] = {}
    for sdk in ("python", "typescript", "kotlin", "swift"):
        sdk_symbols[sdk] = _collect_sdk_symbols(sdk)
        if not sdk_symbols[sdk]:
            print(f"  WARNING: No symbols extracted for {sdk} SDK at {SDK_PATHS[sdk]}")

    total_ops = 0
    errors = 0
    missing_exemptions = 0
    unmatched_true = 0
    coverage_exempted = 0
    all_exempted_ops = 0

    sdks = ("python", "typescript", "kotlin", "swift")
    expected_sdks = frozenset(sdks)

    for domain_entry in matrix.get("capabilities", []):
        if not isinstance(domain_entry, dict):
            print(
                f"  ERROR: capabilities entry must be an object, "
                f"got {type(domain_entry).__name__}."
            )
            errors += 1
            continue
        domain = domain_entry.get("domain", "?")
        operations = domain_entry.get("operations", [])
        if not isinstance(operations, list):
            print(
                f"  ERROR: {domain}: 'operations' must be an array, "
                f"got {type(operations).__name__}."
            )
            errors += 1
            continue
        for op in operations:
            if not isinstance(op, dict):
                print(
                    f"  ERROR: {domain}: operation entry must be an object, "
                    f"got {type(op).__name__}."
                )
                errors += 1
                continue
            op_name = op.get("name", "?")
            total_ops += 1

            # Fail if any expected SDK key is absent entirely from this entry.
            # A missing key is structurally different from false/null: it means
            # the operation was never evaluated for that SDK, which is always
            # an authoring gap (not a deliberate exemption).
            present_sdks = expected_sdks.intersection(op.keys())
            missing_sdks = expected_sdks - present_sdks
            if missing_sdks:
                for missing_sdk in sorted(missing_sdks):
                    print(
                        f"  ERROR: {domain}/{op_name} is missing SDK key "
                        f"'{missing_sdk}' entirely — add a true/false entry "
                        f"(and an exemption if false)."
                    )
                    errors += 1

            exemptions = op.get("exemptions", {})
            coverage_exemptions = op.get("coverage_exemptions", {})

            # Guard against malformed exemption blocks: a non-dict value would
            # make the .items()/membership accesses below raise. Emit a clean
            # ERROR and treat the block as empty (fail-closed: missing
            # exemptions then surface as their own errors downstream).
            if not isinstance(exemptions, dict):
                print(
                    f"  ERROR: {domain}/{op_name}: 'exemptions' must be an object, "
                    f"got {type(exemptions).__name__}."
                )
                errors += 1
                exemptions = {}
            if not isinstance(coverage_exemptions, dict):
                print(
                    f"  ERROR: {domain}/{op_name}: 'coverage_exemptions' must be an "
                    f"object, got {type(coverage_exemptions).__name__}."
                )
                errors += 1
                coverage_exemptions = {}

            # Track per-op coverage state for the all-exempted check below.
            op_true_sdks: list[str] = []
            op_exempted_sdks: list[str] = []
            op_verified_sdks: list[str] = []

            # Validate that all coverage_exemptions reasons are non-empty strings.
            for sdk, reason in coverage_exemptions.items():
                if not isinstance(reason, str) or not reason.strip():
                    print(
                        f"  ERROR: {domain}/{op_name}: coverage_exemptions[{sdk}] has an "
                        f"empty or blank reason — must cite a symbol name or ADR section."
                    )
                    errors += 1

            for sdk in sdks:
                expected = op.get(sdk)
                if expected is None:
                    continue

                if expected is True:
                    op_true_sdks.append(sdk)
                    # AST check: does the SDK have a symbol for this?
                    found = _check_operation_in_sdk(
                        sdk_symbols[sdk], sdk, domain, op_name
                    )
                    if found:
                        op_verified_sdks.append(sdk)
                        continue
                    # Fail-closed: a capability marked present whose SDK symbol
                    # cannot be located is a real gap (or a stale matrix entry)
                    # UNLESS it carries an explicit, reasoned coverage exemption.
                    # The escape hatch is for capabilities that genuinely exist
                    # but resist static extraction (e.g. methods only in
                    # generated bindings the AST grammar can't parse) — never a
                    # silent pass. Resolve a real one of three ways: add the SDK
                    # wrapper, add an ALIASES entry pointing at the real symbol,
                    # or add a coverage_exemptions reason citing the symbol.
                    if sdk in coverage_exemptions:
                        print(
                            f"  NOTE: {domain}/{op_name} ({sdk}) coverage-exempt: "
                            f"{coverage_exemptions[sdk]}"
                        )
                        op_exempted_sdks.append(sdk)
                        coverage_exempted += 1
                    else:
                        print(
                            f"  ERROR: {domain}/{op_name} marked true for {sdk} "
                            f"but no matching SDK symbol was found and no "
                            f"coverage_exemptions reason is recorded. Add the "
                            f"wrapper, an ALIASES entry, or a coverage_exemptions "
                            f"reason."
                        )
                        unmatched_true += 1
                        errors += 1
                elif expected is False:
                    # Must have an exemption with a non-empty reason string
                    if sdk not in exemptions:
                        print(
                            f"  ERROR: {domain}/{op_name} marked false for "
                            f"{sdk} but no exemption provided"
                        )
                        missing_exemptions += 1
                        errors += 1
                    else:
                        reason = exemptions.get(sdk, "")
                        if not isinstance(reason, str) or not reason.strip():
                            print(
                                f"  ERROR: 'exemptions.{sdk}' for op '{domain}/{op_name}' "
                                f"must be a non-empty string"
                            )
                            errors += 1
                else:
                    # Cell value is neither True, False, nor None (e.g. a
                    # typo'd string "true" or an integer).  Reject it so
                    # authoring errors don't silently fall through.
                    print(
                        f"  ERROR: {domain}/{op_name}: SDK '{sdk}' has unexpected cell value "
                        f"{expected!r} — must be true, false, or null."
                    )
                    errors += 1

            # All-exempted check: if every SDK that claims coverage for this
            # operation has a coverage_exemption (and none was statically
            # verified), there is no ground-truth verified implementation.
            # This prevents a coverage_exemptions entry from acting as an
            # unbounded prose bypass when ALL SDKs use one simultaneously.
            # At least one SDK must have its symbol verified by static
            # extraction for the exemptions to be legitimate.
            if (
                op_true_sdks
                and not op_verified_sdks
                and set(op_exempted_sdks) == set(op_true_sdks)
            ):
                print(
                    f"  ERROR: All SDKs claiming coverage for {domain}/{op_name} "
                    f"have coverage_exemptions with no statically-verified SDK — "
                    f"coverage cannot be verified. Add an ALIASES entry or add the "
                    f"missing wrapper so at least one SDK is statically confirmed."
                )
                all_exempted_ops += 1
                errors += 1

    # Floor guard: a coverage gate must never pass on an empty matrix. If the
    # "capabilities" array is empty or missing, total_ops stays 0 and the loop
    # above records no errors — without this guard a truncated/empty matrix
    # would be reported as PASS, silently disabling the gate. This is a NEW
    # assertion that expands coverage (it can only ADD a failure), never a
    # bypass of an existing check.
    if total_ops == 0:
        print(
            "FAIL: matrix produced zero operations — the 'capabilities' array is "
            "empty or missing. A coverage gate cannot pass on an empty matrix.",
            file=sys.stderr,
        )
        return 1

    # Summary
    print()
    print("=" * 60)
    print("SDK Capability Matrix Coverage Check")
    print("=" * 60)
    print(f"  Matrix file:        {MATRIX_PATH}")
    print(f"  Total operations:   {total_ops}")
    print(
        f"  Coverage-exempt:    {coverage_exempted} (present but not statically matchable)"
    )
    print(f"  Errors:             {errors}")
    print(
        f"    unmatched true:   {unmatched_true} (true but no symbol and no coverage exemption)"
    )
    print(f"    false w/o exempt: {missing_exemptions}")
    print(
        f"    all-exempted ops: {all_exempted_ops} (all true SDKs have exemptions, none verified)"
    )
    print("=" * 60)

    if errors > 0:
        print(
            f"\nFAIL: {errors} error(s) — {unmatched_true} unmatched true entr(ies), "
            f"{missing_exemptions} false entr(ies) lacking exemptions, "
            f"{all_exempted_ops} op(s) with all-exempted coverage (unverifiable)."
        )
        return 1

    print("\nPASS: All matrix entries validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
