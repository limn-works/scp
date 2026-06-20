#!/usr/bin/env python3
"""check-sdk-coverage.py -- CI gate enforcing SDK capability matrix conformance.

Reads `.docs/standards/sdk-capability-matrix.json` and validates:
  1. Every entry marked `true` has corresponding code in the SDK source.
  2. Every entry marked `false` has an `exemptions` entry with a reason.

Detection strategy per SDK (AST-based via tree-sitter):
  - Python:     function_definition / class_definition in bindings/python/scp_sdk/*.py
  - TypeScript:  exported declarations in bindings/typescript/src/*.ts
  - Kotlin:      public class/function declarations in bindings/kotlin/scp-kt/src/main/kotlin/**/*.kt
  - Swift:       public func/class/struct/actor/extension in bindings/swift/Sources/SCP/**/*.swift

Exit 0 if all checks pass, 1 if any `false` entry lacks an exemption.

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
# exists and implements the capability.
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
    # Note: renew_attestation is missing from TypeScript SDK entirely.
    # The matrix should mark it false with exemption, not alias it.
    ("Identity", "verify_attestation"): {
        "kotlin": ["verifyLinkAttestation"],
    },
    # Context validation helpers
    ("Context", "validate_params"): {
        "python": ["validate_context_params"],
        "typescript": ["validateContextParams"],
        "kotlin": ["validateContextParams"],
    },
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
    },
    # Messaging -- validate_broadcast_key has _hex suffix in some SDKs
    ("Messaging", "validate_broadcast_key"): {
        "python": ["validate_broadcast_key_hex"],
        "typescript": ["validateBroadcastKeyHex"],
        "kotlin": ["validateBroadcastKeyHex"],
        "swift": ["validateBroadcastKeyHex"],
    },
    # Tools -- TypeScript uses domain-prefixed naming (toolXxx on SCP class)
    ("Tools", "register"): {
        "typescript": ["toolRegister"],
    },
    ("Tools", "invoke"): {
        "python": ["tool_invoke"],
        "typescript": ["toolInvoke"],
    },
    ("Tools", "verify"): {
        "python": ["tool_verify"],
        "typescript": ["toolVerify"],
    },
    ("Tools", "invoke_cross_context"): {
        "python": ["tool_invoke_cross_context"],
        "typescript": ["toolInvokeCrossContext"],
        "swift": ["toolInvokeCrossContext"],
    },
    ("Tools", "session_create"): {
        "python": ["tool_session_create"],
        "typescript": ["toolSessionCreate"],
        "swift": ["toolSessionCreate"],
    },
    ("Tools", "session_invoke"): {
        "python": ["tool_session_invoke"],
        "typescript": ["toolSessionInvoke"],
        "swift": ["toolSessionInvoke"],
    },
    ("Tools", "session_close"): {
        "python": ["tool_session_close"],
        "typescript": ["toolSessionClose"],
        "swift": ["toolSessionClose"],
    },
    ("Tools", "interface_expose"): {
        "python": ["tool_interface_expose"],
        "typescript": ["toolInterfaceExpose"],
        "swift": ["exposeToolInterface"],
    },
    ("Tools", "interface_accept"): {
        "python": ["tool_interface_accept"],
        "typescript": ["toolInterfaceAccept"],
        "swift": ["acceptToolInterface"],
    },
    ("Tools", "interface_revoke"): {
        "python": ["tool_interface_revoke"],
        "typescript": ["toolInterfaceRevoke"],
        "swift": ["revokeToolInterface"],
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
        "typescript": ["contextApplyPendingCeilingModification"],
    },
    ("Governance", "finalize_close"): {
        "typescript": ["contextFinalizeClose"],
    },
    ("Governance", "create_governance_checkpoint"): {
        "typescript": ["contextCreateGovernanceCheckpoint"],
    },
    ("Governance", "add_checkpoint_cosignature"): {
        "typescript": ["contextAddCheckpointCosignature"],
    },
    ("Governance", "member_count"): {
        "python": ["member_count", "context_member_count"],
        "typescript": ["contextMemberCount"],
        "swift": ["memberCount"],
    },
    ("Governance", "is_member"): {
        "python": ["is_member", "context_is_member"],
        "typescript": ["contextIsMember"],
        "swift": ["isMember"],
    },
    ("Governance", "member_role"): {
        "swift": ["memberRole"],
    },
    # Governance rows whose method lives under context_* in Python / TypeScript.
    ("Governance", "handle_ttl_expiry"): {
        "python": ["context_handle_ttl_expiry"],
        "typescript": ["contextHandleTtlExpiry"],
    },
    ("Governance", "propose_ttl_extension"): {
        "python": ["context_propose_ttl_extension"],
        "typescript": ["contextProposeTtlExtension"],
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
    },
    ("EventLog", "checkpoint"): {
        "typescript": ["eventLogCheckpoint"],
        "kotlin": ["eventLogCheckpoint"],
    },
    ("EventLog", "checkpoint_by_did"): {
        "python": ["event_log_checkpoint_by_did"],
        "typescript": ["eventLogCheckpointByDid"],
        "kotlin": ["eventLogCheckpointByDid"],
        "swift": ["eventLogCheckpointByDid"],
    },
    ("EventLog", "signed_checkpoint"): {
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
    # Media
    ("Media", "check_capability"): {
        "python": ["check_media_capability"],
    },
    # Discovery -- discover is `discoverContexts` in TS, `discover` in Kotlin,
    # and `contextDiscover` in Swift (generated UniFFI binding)
    ("Discovery", "discover"): {
        "python": ["discover_contexts"],
        "typescript": ["discoverContexts"],
        "kotlin": ["discover", "contextDiscover"],
        "swift": ["contextDiscover"],
    },
    ("Discovery", "scope_register"): {
        "swift": ["registerScope"],
    },
    ("Discovery", "scope_lookup"): {
        "swift": ["lookupScope"],
    },
    ("Discovery", "scope_deregister"): {
        "swift": ["deregisterScope"],
    },
    # Sync
    ("Sync", "get_policy"): {
        "typescript": ["getSyncPolicy"],
    },
    # Provenance
    ("Provenance", "evaluate_quality"): {
        "python": ["evaluate_provenance_quality"],
        "typescript": ["evaluateProvenanceQuality"],
        "swift": ["evaluateProvenanceQuality"],
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
    # Bridge -- register is surfaced as BridgeRegistration type in TS and
    # `register` function in Python/Swift/Kotlin bridge modules.
    ("Bridge", "register"): {
        "typescript": ["BridgeRegistration", "createNativeBridge", "createWasmBridge"],
    },
    # MCP
    ("MCP", "serve"): {
        "python": ["serve_mcp", "McpServer"],
    },
    ("MCP", "connect_client"): {
        "python": ["McpClient"],
        "typescript": ["connectMcp", "McpClient"],
        "swift": ["McpClient", "connect"],
    },
    # Server -- methods live on Relay/Node classes
    ("Server", "relay_start_in_memory"): {
        "python": ["start_in_memory"],
        "typescript": ["startInMemory"],
        "swift": ["startInMemory"],
    },
    ("Server", "relay_start_local"): {
        "python": ["start_local"],
        "typescript": ["startLocal"],
        "swift": ["startLocal"],
    },
    ("Server", "relay_shutdown"): {
        "python": ["shutdown"],
        "typescript": ["shutdown"],
        "swift": ["shutdown"],
    },
    ("Server", "node_start_in_memory"): {
        "python": ["start_in_memory"],
        "typescript": ["startInMemory"],
        "swift": ["startInMemory"],
    },
    ("Server", "node_start_local"): {
        "python": ["start_local"],
        "typescript": ["startLocal"],
        "swift": ["startLocal"],
    },
    ("Server", "node_shutdown"): {
        "python": ["shutdown"],
        "typescript": ["shutdown"],
        "swift": ["shutdown"],
    },
    ("Server", "node_enable_site_projection"): {
        "python": ["enable_site_projection"],
        "typescript": ["enableSiteProjection"],
        "swift": ["enableSiteProjection"],
    },
    ("Server", "node_commit_deploy"): {
        "python": ["commit_deploy"],
        "typescript": ["commitDeploy"],
        "swift": ["commitDeploy"],
    },
    ("Server", "node_rollback_deploy"): {
        "python": ["rollback_deploy"],
        "typescript": ["rollbackDeploy"],
        "swift": ["rollbackDeploy"],
    },
    ("Server", "node_disable_site_projection"): {
        "python": ["disable_site_projection"],
        "typescript": ["disableSiteProjection"],
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
        "typescript": ["contextRestore"],
    },
    ("Context", "restore_all_contexts"): {
        "typescript": ["contextRestoreAll"],
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
    ("Lifecycle", "suspend"): {
        "kotlin": ["suspendInstance"],
    },
}


# ---------------------------------------------------------------------------
# Name conversion helpers
# ---------------------------------------------------------------------------


def _to_camel(snake: str) -> str:
    """Convert snake_case to camelCase."""
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _to_pascal(snake: str) -> str:
    """Convert snake_case to PascalCase."""
    return "".join(p.capitalize() for p in snake.split("_"))


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
            return child.text.decode()
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
            class_name = child.text.decode()
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
                        symbols.add(fc.text.decode())
                        break

            elif sub.type == "class_declaration":
                class_name = None
                for fc in sub.children:
                    if fc.type == "type_identifier":
                        class_name = fc.text.decode()
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
                                            method_name = mc.text.decode()
                                            symbols.add(f"{class_name}.{method_name}")
                                            symbols.add(method_name)
                                            break
                                elif member.type == "public_field_definition":
                                    # Handle class fields (arrow function
                                    # properties)
                                    for mc in member.children:
                                        if mc.type == "property_identifier":
                                            symbols.add(mc.text.decode())
                                            break

            elif sub.type == "lexical_declaration":
                # export const myFunc = ...
                for decl in sub.children:
                    if decl.type == "variable_declarator":
                        for dc in decl.children:
                            if dc.type == "identifier":
                                symbols.add(dc.text.decode())
                                break

            elif sub.type == "interface_declaration":
                for fc in sub.children:
                    if fc.type == "type_identifier":
                        symbols.add(fc.text.decode())
                        break

            elif sub.type == "type_alias_declaration":
                for fc in sub.children:
                    if fc.type == "type_identifier":
                        symbols.add(fc.text.decode())
                        break

            elif sub.type == "export_clause":
                # export { X, Y as Z } from './module'
                for spec in sub.children:
                    if spec.type == "export_specifier":
                        ids = [c for c in spec.children if c.type == "identifier"]
                        if len(ids) >= 2:
                            # export { X as Y } -- the exported name is Y
                            symbols.add(ids[1].text.decode())
                        elif len(ids) == 1:
                            symbols.add(ids[0].text.decode())

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
                    vis_text = mod.text.decode().strip()
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
                return c.text.decode().strip("`")
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
                return c.text.decode().strip("`")
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
                        if mod.text.decode().strip() == "public":
                            return True
        return False

    def _has_restrictive_visibility(node: Node) -> bool:
        """Check if a Swift node has private, internal, or fileprivate."""
        restrictive = {"private", "internal", "fileprivate"}
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type == "visibility_modifier":
                        if mod.text.decode().strip() in restrictive:
                            return True
        return False

    def _get_swift_type_name(node: Node) -> str | None:
        """Get the name of a class/struct/enum/actor/extension declaration."""
        for child in node.children:
            if child.type == "type_identifier":
                return child.text.decode()
            # Extensions use user_type > type_identifier
            if child.type == "user_type":
                for uc in child.children:
                    if uc.type == "type_identifier":
                        return uc.text.decode()
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
                        method_name = mc.text.decode()
                        symbols.add(f"{type_name}.{method_name}")
                        symbols.add(method_name)
                        break

    for child in root_node.children:
        if child.type == "function_declaration":
            if not _is_public(child):
                continue
            for fc in child.children:
                if fc.type == "simple_identifier":
                    symbols.add(fc.text.decode())
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
                    proto_name = fc.text.decode()
                    break
            if proto_name:
                symbols.add(proto_name)
                for fc in child.children:
                    if fc.type == "protocol_body":
                        for member in fc.children:
                            if member.type == "protocol_function_declaration":
                                for mc in member.children:
                                    if mc.type == "simple_identifier":
                                        method_name = mc.text.decode()
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

        tree = parser.parse(source)
        file_symbols = extractor(tree.root_node)
        all_symbols.update(file_symbols)

    return all_symbols


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------


def _check_operation_in_sdk(
    sdk_symbols: set[str], sdk: str, domain: str, op_name: str
) -> bool:
    """Check whether the SDK's extracted symbols contain code for this
    operation.

    Strategy (in order):
      1. Explicit aliases from the ALIASES table
      2. Exact match against auto-generated name variants
         (snake_case, camelCase, PascalCase, domain-prefixed)

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

    # 2. Generate name variants and check exact match
    camel = _to_camel(op_name)
    pascal = _to_pascal(op_name)

    # Domain-prefixed variants
    domain_lower = domain.lower()
    domain_snake = f"{domain_lower}_{op_name}"
    domain_camel = _to_camel(domain_snake)
    # py_ prefixed (PyO3 bridge naming convention)
    py_prefixed = f"py_{op_name}"

    candidates = [
        # Raw operation names
        op_name,  # send_message
        camel,  # sendMessage
        pascal,  # SendMessage
        # Domain-prefixed
        domain_snake,  # messaging_send_message
        domain_camel,  # messagingSendMessage
        py_prefixed,  # py_send_message
        # Class.method patterns — use domain name as-is from JSON
        # (preserves EventLog, UCAN, MCP casing)
        f"{domain}.{op_name}",  # EventLog.verify
        f"{domain}.{camel}",  # EventLog.verify
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

    with open(MATRIX_PATH, encoding="utf-8") as f:
        matrix = json.load(f)

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

    for domain_entry in matrix.get("capabilities", []):
        domain = domain_entry.get("domain", "?")
        for op in domain_entry.get("operations", []):
            op_name = op.get("name", "?")
            total_ops += 1
            exemptions = op.get("exemptions", {})
            coverage_exemptions = op.get("coverage_exemptions", {})

            # Track per-op coverage state for the all-exempted check below.
            op_true_sdks: list[str] = []
            op_exempted_sdks: list[str] = []
            op_verified_sdks: list[str] = []

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
                    # Must have an exemption
                    if sdk not in exemptions:
                        print(
                            f"  ERROR: {domain}/{op_name} marked false for "
                            f"{sdk} but no exemption provided"
                        )
                        missing_exemptions += 1
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
