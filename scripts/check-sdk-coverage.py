#!/usr/bin/env python3
"""check-sdk-coverage.py -- CI gate enforcing SDK capability matrix conformance.

Reads `.docs/standards/sdk-capability-matrix.json` and validates:
  1. Every entry marked `true` has corresponding code in the SDK source.
  2. Every entry marked `false` has an `exemptions` entry with a reason.

Detection strategy per SDK (heuristic grep -- warnings, not hard failures):
  - Python:     class/method names in bindings/python/scp_sdk/*.py
  - TypeScript:  exported names in bindings/typescript/src/*.ts
  - Kotlin:      class/function names in bindings/kotlin/scp-kt/src/main/kotlin/**/*.kt
  - Swift:       public class/func declarations in bindings/swift/Sources/SCP/**/*.swift

Exit 0 if all checks pass, 1 if any `false` entry lacks an exemption.

Usage: python3.12 scripts/check-sdk-coverage.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = REPO_ROOT / ".docs" / "standards" / "sdk-capability-matrix.json"

# SDK source directories
SDK_PATHS: dict[str, Path] = {
    "python": REPO_ROOT / "bindings" / "python" / "scp_sdk",
    "typescript": REPO_ROOT / "bindings" / "typescript" / "src",
    "kotlin": REPO_ROOT / "bindings" / "kotlin" / "scp-kt" / "src" / "main" / "kotlin" / "works" / "limn" / "scp",
    "swift": REPO_ROOT / "bindings" / "swift" / "Sources" / "SCP",
}

# Explicit alias table: (domain, operation) -> {sdk: [search_strings]}
# Only needed when the auto-generated patterns fail to match the actual code.
ALIASES: dict[tuple[str, str], dict[str, list[str]]] = {
    # Identity attestations use different names across SDKs
    ("Identity", "create_attestation"): {
        "kotlin": ["createLinkAttestation"],
        "swift": ["createIdentityAttestation"],
    },
    ("Identity", "list_attestations"): {
        "kotlin": ["linkAttestations"],
        "swift": ["listIdentityAttestations"],
    },
    ("Identity", "remove_attestation"): {
        "kotlin": ["removeLinkAttestation"],
        "swift": ["removeIdentityAttestation"],
    },
    ("Identity", "renew_attestation"): {
        "typescript": ["renewAttestation"],
    },
    ("Identity", "verify_attestation"): {
        "kotlin": ["verifyLinkAttestation"],
    },
    # Context validation helpers
    ("Context", "validate_params"): {
        "python": ["validate_context_params", "validateContextParams"],
        "typescript": ["validateContextParams"],
        "kotlin": ["validateContextParams"],
    },
    ("Context", "metadata_record_serialize"): {
        "python": ["metadataRecordToJson", "metadata_record_to_json"],
        "typescript": ["metadataRecordToJson"],
        "kotlin": ["metadataRecordToJson"],
        "swift": ["serializeMetadataRecord"],
    },
    ("Context", "metadata_record_deserialize"): {
        "python": ["metadataRecordFromJson", "metadata_record_from_json"],
        "typescript": ["metadataRecordFromJson"],
        "kotlin": ["metadataRecordFromJson"],
        "swift": ["deserializeMetadataRecord"],
    },
    # Messaging
    ("Messaging", "send_message"): {
        "typescript": ["send(", "ctx.send"],
        "kotlin": ["contextSend"],
        "swift": ["func send("],
    },
    # Tools -- TypeScript uses different naming
    ("Tools", "invoke_cross_context"): {
        "typescript": ["toolInvokeCrossContext"],
    },
    ("Tools", "session_create"): {
        "typescript": ["toolSessionCreate"],
    },
    ("Tools", "session_invoke"): {
        "typescript": ["toolSessionInvoke"],
    },
    ("Tools", "session_close"): {
        "typescript": ["toolSessionClose"],
    },
    # Governance -- uses different naming in all SDKs
    ("Governance", "execute_action"): {
        "python": ["execute_governance_action"],
        "typescript": ["executeGovernanceAction", "governanceExecute"],
        "kotlin": ["governanceExecute"],
        "swift": ["executeGovernanceAction"],
    },
    ("Governance", "propose_action"): {
        "python": ["propose_governance_action"],
        "typescript": ["proposeGovernanceAction", "governancePropose"],
        "kotlin": ["governancePropose"],
        "swift": ["proposeGovernanceAction"],
    },
    ("Governance", "approve_proposal"): {
        "python": ["approve_governance_proposal"],
        "typescript": ["approveGovernanceProposal", "governanceApprove"],
        "kotlin": ["governanceApprove"],
        "swift": ["approveGovernanceProposal"],
    },
    ("Governance", "reject_proposal"): {
        "python": ["reject_governance_proposal"],
        "typescript": ["rejectGovernanceProposal", "governanceReject"],
        "kotlin": ["governanceReject"],
        "swift": ["rejectGovernanceProposal"],
    },
    ("Governance", "withdraw_vote"): {
        "python": ["withdraw_governance_vote"],
        "typescript": ["withdrawGovernanceVote", "governanceWithdraw"],
        "kotlin": ["governanceWithdraw"],
        "swift": ["withdrawGovernanceVote"],
    },
    ("Governance", "member_count"): {
        "swift": ["memberCount"],
    },
    ("Governance", "is_member"): {
        "swift": ["isMember"],
    },
    ("Governance", "member_role"): {
        "swift": ["memberRole"],
    },
    # EventLog
    ("EventLog", "signed_checkpoint"): {
        "typescript": ["eventLogCheckpoint", "signedCheckpoint"],
        "kotlin": ["eventLogCheckpoint"],
        "swift": ["generateEventLogCheckpoint"],
    },
    # Provenance
    ("Provenance", "evaluate_quality"): {
        "python": ["evaluate_provenance_quality"],
        "typescript": ["evaluateProvenanceQuality"],
    },
    # MCP
    ("MCP", "connect_client"): {
        "python": ["McpClient"],
        "typescript": ["connectMcp", "McpClient"],
        "swift": ["McpClientHandle", "McpClient"],
    },
    # Server -- methods live on Relay/Node classes
    ("Server", "relay_shutdown"): {
        "python": ["shutdown", "async def shutdown"],
        "typescript": ["shutdown", "stop"],
        "swift": ["shutdown"],
    },
    ("Server", "node_shutdown"): {
        "python": ["shutdown"],
        "typescript": ["shutdown", "stop"],
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
}


def _to_camel(snake: str) -> str:
    """Convert snake_case to camelCase."""
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _to_pascal(snake: str) -> str:
    """Convert snake_case to PascalCase."""
    return "".join(p.capitalize() for p in snake.split("_"))


def _collect_sdk_source(sdk: str) -> str:
    """Read all source files for an SDK into a single string."""
    sdk_path = SDK_PATHS[sdk]
    if not sdk_path.exists():
        return ""

    extensions = {
        "python": "*.py",
        "typescript": "*.ts",
        "kotlin": "*.kt",
        "swift": "*.swift",
    }
    ext = extensions[sdk]
    content_parts: list[str] = []
    for p in sdk_path.rglob(ext):
        try:
            content_parts.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n".join(content_parts)


def _check_operation_in_sdk(
    sdk_source: str, sdk: str, domain: str, op_name: str
) -> bool:
    """Heuristic check: does the SDK source contain code for this operation?

    Returns True if any of the generated patterns match anywhere in the source.
    """
    # Check explicit aliases first
    alias_key = (domain, op_name)
    if alias_key in ALIASES and sdk in ALIASES[alias_key]:
        for alias in ALIASES[alias_key][sdk]:
            if alias in sdk_source:
                return True

    # Auto-generated patterns
    camel = _to_camel(op_name)
    pascal = _to_pascal(op_name)

    # Domain-prefixed variants
    domain_lower = domain.lower()
    domain_snake = f"{domain_lower}_{op_name}"
    domain_camel = _to_camel(domain_snake)

    # py_ prefixed (PyO3 bridge naming)
    py_prefixed = f"py_{op_name}"

    # Domain-prefixed patterns (most specific)
    # Also try class-method patterns: Domain.operation, Domain.camelCase
    domain_pascal = _to_pascal(domain_lower)
    candidates = [
        domain_snake,                    # event_log_verify
        domain_camel,                    # eventLogVerify
        py_prefixed,                     # py_verify
        f"{domain_pascal}.{op_name}",    # EventLog.verify
        f"{domain_pascal}.{camel}",      # EventLog.verify (camel)
        f".{op_name}(",                  # .verify( — method call
        f".{camel}(",                    # .verify( — camelCase method call
        f"def {op_name}",               # Python: def verify
        f"fn {op_name}",                # Rust/Swift: fn verify
        f"fun {op_name}",               # Kotlin: fun verify
        f"func {op_name}",              # Swift: func verify
        op_name,                         # raw snake_case
        camel,                           # raw camelCase
        pascal,                          # raw PascalCase
    ]
    for pat in candidates:
        if pat in sdk_source:
            return True

    return False


def main() -> int:
    if not MATRIX_PATH.exists():
        print(f"FAIL: Matrix file not found: {MATRIX_PATH}", file=sys.stderr)
        return 1

    with open(MATRIX_PATH, encoding="utf-8") as f:
        matrix = json.load(f)

    # Pre-load all SDK sources
    sdk_sources: dict[str, str] = {}
    for sdk in ("python", "typescript", "kotlin", "swift"):
        sdk_sources[sdk] = _collect_sdk_source(sdk)
        if not sdk_sources[sdk]:
            print(f"  WARNING: No source files found for {sdk} SDK at {SDK_PATHS[sdk]}")

    total_ops = 0
    warnings = 0
    errors = 0
    missing_exemptions = 0

    sdks = ("python", "typescript", "kotlin", "swift")

    for domain_entry in matrix.get("capabilities", []):
        domain = domain_entry.get("domain", "?")
        for op in domain_entry.get("operations", []):
            op_name = op.get("name", "?")
            total_ops += 1
            exemptions = op.get("exemptions", {})

            for sdk in sdks:
                expected = op.get(sdk)
                if expected is None:
                    continue

                if expected is True:
                    # Heuristic check: does the SDK have code for this?
                    found = _check_operation_in_sdk(
                        sdk_sources[sdk], sdk, domain, op_name
                    )
                    if not found:
                        print(
                            f"  WARNING: {domain}/{op_name} marked true for {sdk} "
                            f"but grep could not find matching code"
                        )
                        warnings += 1
                elif expected is False:
                    # Must have an exemption
                    if sdk not in exemptions:
                        print(
                            f"  ERROR: {domain}/{op_name} marked false for {sdk} "
                            f"but no exemption provided"
                        )
                        missing_exemptions += 1
                        errors += 1

    # Summary
    print()
    print("=" * 60)
    print("SDK Capability Matrix Coverage Check")
    print("=" * 60)
    print(f"  Matrix file:       {MATRIX_PATH}")
    print(f"  Total operations:  {total_ops}")
    print(f"  Warnings:          {warnings} (true entries with no grep match)")
    print(f"  Errors:            {errors} (false entries with no exemption)")
    print("=" * 60)

    if errors > 0:
        print(f"\nFAIL: {missing_exemptions} false entries lack exemptions")
        return 1

    if warnings > 0:
        print(
            f"\nPASS with {warnings} warnings. "
            f"Review warnings -- they may indicate stale matrix entries."
        )
    else:
        print("\nPASS: All entries validated.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
