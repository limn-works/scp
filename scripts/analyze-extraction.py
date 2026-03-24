#!/usr/bin/env python3.12
"""Analyze scp-core module dependencies for scp-protocol extraction.

For each file planned to move to scp-protocol, extracts all `crate::` references
and classifies them as:
- INTERNAL: target module also moves → no change needed
- OUTBOUND: target stays in scp-core → must refactor
- TEST_ONLY: reference is inside #[cfg(test)] → can stay as integration test

Uses tree-sitter for accurate Rust parsing (handles grouped imports, inline refs).
"""

import tree_sitter_rust as ts_rust
from tree_sitter import Language, Parser
from pathlib import Path
import re
import sys

RUST_LANG = Language(ts_rust.language())
parser = Parser(RUST_LANG)

# Root of scp-core source
CORE_SRC = Path("crates/scp-core/src")

# Files/directories planned to move to scp-protocol
# Each entry is relative to crates/scp-core/src/
MOVING = {
    # Leaf utils
    "jcs.rs",
    "serde_util.rs",
    "time.rs",
    "uri.rs",
    # Crypto
    "crypto/canonical.rs",
    "crypto/ed25519.rs",
    "crypto/tofu.rs",
    "crypto/key_continuity.rs",
    "crypto/bip39_wordlist.rs",
    "crypto/envelope_seal.rs",
    # Sender keys (pure parts)
    "crypto/sender_keys/encrypt.rs",
    "crypto/sender_keys/key_protocol_verify.rs",
    # Access keys (pure parts)
    "crypto/access_keys/wrapping.rs",
    # UCAN (pure parts)
    "crypto/ucan/capability.rs",
    "crypto/ucan/nonce.rs",
    "crypto/ucan/revoke.rs",
    "crypto/ucan/spending.rs",
    "crypto/ucan/validate.rs",
    # Trust
    "trust/custody_violation.rs",
    "trust/admission.rs",
    "trust/aggregate.rs",
    "trust/attestation.rs",
    "trust/capability_registry.rs",
    "trust/capability_uri.rs",
    "trust/challenge.rs",
    "trust/consequence.rs",
    "trust/participation.rs",
    "trust/renewal.rs",
    "trust/sybil.rs",
    # Context types
    "context/params.rs",
    "context/state_machine.rs",
    "context/roles.rs",
    "context/membership.rs",
    "context/memory_scope.rs",
    "context/metadata.rs",
    "context/templates.rs",
    "context/close.rs",
    "context/nesting.rs",
    "context/invitation.rs",
    "context/promotion.rs",
    # Identity pure parts
    "identity/block_list.rs",
    "identity/private_state.rs",
    "identity/private_state_events.rs",
    "identity/attestation.rs",
    # Governance (pure parts)
    "context/governance/majority.rs",
    "context/governance/multisig.rs",
    "context/governance/unanimity.rs",
    "context/governance/mls_integration.rs",
    # Broadcast
    "context/broadcast.rs",
    "context/broadcast_content.rs",
    "crypto/sender_keys/broadcast.rs",
    # Provenance
    "provenance/attach.rs",
    "provenance/evaluate.rs",
    # Context tools (pure parts)
    "context/tools/integrity.rs",
    "context/tools/lifecycle.rs",
    "context/tools/registry.rs",
    "context/tools/schema.rs",
    "context/tools/summary.rs",
    # Economy (pure parts)
    "economy/types.rs",
    "economy/policy.rs",
    "economy/budget.rs",
    "economy/pricing.rs",
    "economy/estimate.rs",
    "economy/antispam.rs",
    # Discovery (pure parts only)
    "discovery/handles.rs",
    "discovery/petnames.rs",
    "discovery/scope.rs",
    "discovery/context.rs",
    "discovery/push.rs",
    # Envelope (pure parts)
    "envelope/inner/mod.rs",
    "envelope/outer/mod.rs",
    "envelope/chunk.rs",
    "envelope/padding.rs",
    "envelope/validation.rs",
    # Sync (pure parts)
    "sync/alerts.rs",
    "sync/conflict_resolution.rs",
    # Bridge types
    "bridge/mod.rs",  # BridgeMode, BridgeConnector, ShadowIdentity types
    "bridge/claiming.rs",
    "bridge/envelope.rs",
    "bridge/provenance.rs",
    "bridge/registration.rs",
    "bridge/shadow.rs",
    # Parent mod.rs files (contain types that move)
    "context/mod.rs",  # ContextState, ContextError, context_id_bytes (NOT ContextHandle — tokio)
    "context/governance/mod.rs",  # GovernanceAction, GovernanceEngine trait, compute_proposal_id
    "context/tools/mod.rs",  # ToolSchema, ToolError types
    "crypto/mod.rs",  # re-exports
    "crypto/sender_keys/mod.rs",  # SenderKey, SenderKeyError, SenderKeyStore types
    "crypto/access_keys/mod.rs",  # AccessKey, AccessKeyError types
    "crypto/ucan/mod.rs",  # UcanError, UcanToken, UcanHeader types
    "trust/mod.rs",  # TrustError, trust types
    "identity/mod.rs",  # re-exports
    "envelope/mod.rs",  # SCP_PROTOCOL_VERSION, VersionCompatibility, EnvelopeError
    "economy/mod.rs",  # EconomicPolicy, CostSchedule, Amount types
    "economy/types.rs",
    "discovery/mod.rs",  # DiscoveryError
    "provenance/mod.rs",  # DataProvenance, CounterpartyPolicy types
    "sync/mod.rs",  # sync types
    # Additional context files
    "context/policy.rs",  # policy types
    "context/standing.rs",  # standing types
}

# Exact module paths that are moving (derived from file paths)
# "crypto/ucan/validate.rs" -> "crypto::ucan::validate"
MOVING_MODULES = set()
for f in MOVING:
    mod_path = f.replace("/", "::").replace(".rs", "").replace("::mod", "")
    MOVING_MODULES.add(mod_path)

# Also track which PARENT modules have ALL children moving vs SOME
# A parent is "fully moving" if all its .rs files are in MOVING
# A parent is "partially moving" if only some files move
STAYING_FILES = set()
for p in CORE_SRC.rglob("*.rs"):
    rel = str(p.relative_to(CORE_SRC))
    if rel not in MOVING and "mod.rs" not in rel:
        mod_path = rel.replace("/", "::").replace(".rs", "")
        STAYING_FILES.add(mod_path)


def resolve_crate_ref(ref_path: str) -> str:
    """Given a crate:: reference path, determine if the target is moving or staying.

    Strategy: find the most specific module in the path and check if it's moving.
    For crate::crypto::ucan::mint::MintParams, check:
    1. crypto::ucan::mint::MintParams - not a module
    2. crypto::ucan::mint - is this moving? Check MOVING_MODULES
    3. crypto::ucan - is this moving? Only if ALL ucan files move
    """
    path = ref_path.removeprefix("crate::")
    parts = path.split("::")

    # Try longest module path first
    for i in range(len(parts), 0, -1):
        candidate = "::".join(parts[:i])
        # Direct match: this exact module is moving
        if candidate in MOVING_MODULES:
            return "INTERNAL"
        # Direct match: this exact module is staying
        if candidate in STAYING_FILES:
            return "OUTBOUND"

    # If no direct match, check if the top-level module has ANY moving files
    # This handles cases like crate::trust::TrustError where trust/mod.rs
    # isn't in MOVING but trust/*.rs files are
    top = parts[0]
    has_moving = any(m.startswith(top) for m in MOVING_MODULES)
    has_staying = any(m.startswith(top) for m in STAYING_FILES)

    if has_moving and not has_staying:
        return "INTERNAL"
    elif has_staying and not has_moving:
        return "OUTBOUND"
    else:
        # Mixed module - could go either way. Flag as OUTBOUND to be safe.
        return "OUTBOUND"


def extract_crate_refs(source: bytes, file_path: str) -> list[dict]:
    """Extract all crate:: references from a Rust source file using tree-sitter."""
    tree = parser.parse(source)
    refs = []

    def walk(node, in_test: bool = False):
        # Check if we're inside a #[cfg(test)] block
        test_ctx = in_test
        if node.type == "attribute_item":
            text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if "cfg(test)" in text:
                # The NEXT sibling is the test module
                test_ctx = True

        # Look for use_declaration and scoped_use_list containing "crate::"
        if node.type == "use_declaration":
            text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if "crate::" in text:
                # Extract all crate:: paths from this use statement
                for match in re.finditer(r"crate::([\w:]+)", text):
                    full_path = f"crate::{match.group(1)}"
                    refs.append({
                        "path": full_path,
                        "line": node.start_point[0] + 1,
                        "in_test": in_test,
                        "classification": resolve_crate_ref(full_path),
                    })

        # Look for inline crate:: references (not in use statements)
        if node.type == "scoped_identifier" or node.type == "scoped_type_identifier":
            text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            if text.startswith("crate::"):
                refs.append({
                    "path": text.split("(")[0].split("<")[0],  # strip generics/calls
                    "line": node.start_point[0] + 1,
                    "in_test": in_test,
                    "classification": resolve_crate_ref(text),
                })

        # Check for #[cfg(test)] module
        if node.type == "mod_item":
            # Check if preceded by #[cfg(test)]
            for child in node.children:
                if child.type == "attribute_item":
                    attr_text = source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
                    if "cfg(test)" in attr_text:
                        test_ctx = True

        for child in node.children:
            walk(child, test_ctx)

    walk(tree.root_node)
    return refs


def find_cfg_test_ranges(source: bytes) -> list[tuple[int, int]]:
    """Find line ranges of #[cfg(test)] modules using simple text search."""
    lines = source.decode("utf-8", errors="replace").split("\n")
    ranges = []
    i = 0
    while i < len(lines):
        if "#[cfg(test)]" in lines[i]:
            # Find the module/impl block that follows
            # Look for the opening brace
            brace_count = 0
            started = False
            start_line = i + 1
            for j in range(i + 1, len(lines)):
                for ch in lines[j]:
                    if ch == "{":
                        brace_count += 1
                        started = True
                    elif ch == "}":
                        brace_count -= 1
                if started and brace_count == 0:
                    ranges.append((start_line, j + 1))
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1
    return ranges


def is_in_test(line: int, test_ranges: list[tuple[int, int]]) -> bool:
    for start, end in test_ranges:
        if start <= line <= end:
            return True
    return False


def main():
    outbound_total = 0
    internal_total = 0
    test_only_total = 0

    outbound_details = []

    for rel_path in sorted(MOVING):
        file_path = CORE_SRC / rel_path
        if not file_path.exists():
            print(f"WARNING: {file_path} does not exist!")
            continue

        source = file_path.read_bytes()
        test_ranges = find_cfg_test_ranges(source)

        # Use regex-based extraction (more reliable for use statements)
        lines = source.decode("utf-8", errors="replace").split("\n")
        refs = []
        for i, line in enumerate(lines, 1):
            for match in re.finditer(r"crate::([\w:]+)", line):
                full_path = f"crate::{match.group(1)}"
                in_test = is_in_test(i, test_ranges)
                classification = resolve_crate_ref(full_path)
                if in_test and classification == "OUTBOUND":
                    classification = "TEST_ONLY"
                refs.append({
                    "path": full_path,
                    "line": i,
                    "in_test": in_test,
                    "classification": classification,
                })

        if not refs:
            continue

        outbound = [r for r in refs if r["classification"] == "OUTBOUND"]
        test_only = [r for r in refs if r["classification"] == "TEST_ONLY"]
        internal = [r for r in refs if r["classification"] == "INTERNAL"]

        if outbound or test_only:
            print(f"\n{'='*60}")
            print(f"FILE: {rel_path}")
            print(f"  INTERNAL: {len(internal)} | OUTBOUND: {len(outbound)} | TEST_ONLY: {len(test_only)}")

            if outbound:
                print(f"  --- OUTBOUND (must fix) ---")
                for r in outbound:
                    print(f"    L{r['line']}: {r['path']}")
                    outbound_details.append((rel_path, r["line"], r["path"]))

            if test_only:
                print(f"  --- TEST_ONLY (extract to scp-core integration tests) ---")
                for r in test_only:
                    print(f"    L{r['line']}: {r['path']}")

        outbound_total += len(outbound)
        internal_total += len(internal)
        test_only_total += len(test_only)

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"  INTERNAL (no change needed): {internal_total}")
    print(f"  OUTBOUND (must fix):         {outbound_total}")
    print(f"  TEST_ONLY (extract tests):   {test_only_total}")
    print(f"  TOTAL references:            {internal_total + outbound_total + test_only_total}")

    if outbound_details:
        print(f"\n{'='*60}")
        print(f"ALL OUTBOUND REFERENCES (production code that breaks):")
        # Group by target module
        targets = {}
        for file, line, path in outbound_details:
            target = path.split("::")[1] if "::" in path else path
            targets.setdefault(target, []).append((file, line, path))

        for target in sorted(targets):
            print(f"\n  Target module: {target}")
            for file, line, path in targets[target]:
                print(f"    {file}:{line} → {path}")


if __name__ == "__main__":
    main()
