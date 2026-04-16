#!/usr/bin/env python3.12
"""Verify scp-protocol contains zero async fn in production code.

Uses tree-sitter to parse Rust files and detect async functions outside
#[cfg(test)] modules and outside #[async_trait]-annotated trait definitions
and impl blocks.  Inherent async methods that call through async trait
methods are allowed only via an explicit allowlist.
Fails CI if any non-exempt async fn are found.
"""
import sys
import os
import tree_sitter_rust as ts_rust
from tree_sitter import Language, Parser

RUST_LANG = Language(ts_rust.language())
parser = Parser(RUST_LANG)

PROTO_SRC = "crates/scp-protocol/src"
violations = []

# Inherent async methods in scp-protocol that call through async trait
# methods (ContextCryptoProvider).  These do NOT introduce a runtime
# dependency — they are desugared by the caller's async executor.
ALLOWED_INHERENT_ASYNC_FNS = {
    "destroy_ephemeral_keys",
    "initiate_close",
    "complete_summary_close",
}


def has_test_cfg_attribute(node, source):
    """Check if the preceding sibling(s) of a mod_item are #[cfg(test)] attrs.

    In tree-sitter's Rust grammar, attributes like #[cfg(test)] appear as
    sibling attribute_item nodes immediately before the mod_item, not as
    children. This function checks all preceding siblings.
    """
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            text = source[sibling.start_byte:sibling.end_byte].decode(
                "utf-8", errors="replace"
            )
            if "cfg(" in text and "test" in text:
                return True
        elif sibling.type == "line_comment" or sibling.type == "block_comment":
            # Skip comments between attributes and the mod item
            sibling = sibling.prev_sibling
            continue
        else:
            break
        sibling = sibling.prev_sibling
    return False


def has_async_trait_attribute(node, source):
    """Check if the preceding sibling(s) include an #[async_trait] attribute."""
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            text = source[sibling.start_byte:sibling.end_byte].decode(
                "utf-8", errors="replace"
            )
            if "async_trait" in text:
                return True
        elif sibling.type == "line_comment" or sibling.type == "block_comment":
            sibling = sibling.prev_sibling
            continue
        else:
            break
        sibling = sibling.prev_sibling
    return False


def walk(node, source, in_test=False, in_trait=False, filepath=""):
    test_ctx = in_test
    trait_ctx = in_trait

    # Check if this node is a test-gated module
    if node.type == "mod_item":
        if has_test_cfg_attribute(node, source):
            test_ctx = True

    # Only exempt trait_item and impl_item blocks that carry an
    # #[async_trait] attribute.  Plain impl blocks are NOT exempt —
    # inherent async methods must be in the explicit allowlist.
    if node.type in ("trait_item", "impl_item"):
        if has_async_trait_attribute(node, source):
            trait_ctx = True

    # Check for async fn in production code (exempt test + trait contexts)
    if node.type == "function_item" and not test_ctx and not trait_ctx:
        for child in node.children:
            if child.type == "function_modifiers":
                mod_text = source[child.start_byte:child.end_byte].decode(
                    "utf-8", errors="replace"
                )
                if "async" in mod_text:
                    line = node.start_point[0] + 1
                    name_node = next(
                        (c for c in node.children if c.type == "identifier"), None
                    )
                    name = (
                        source[name_node.start_byte:name_node.end_byte].decode("utf-8")
                        if name_node
                        else "unknown"
                    )
                    if name not in ALLOWED_INHERENT_ASYNC_FNS:
                        violations.append(f"{filepath}:{line}: async fn {name}")

    for child in node.children:
        walk(child, source, test_ctx, trait_ctx, filepath)


for root, dirs, files in os.walk(PROTO_SRC):
    for fname in sorted(files):
        if not fname.endswith(".rs"):
            continue
        path = os.path.join(root, fname)
        source = open(path, "rb").read()
        tree = parser.parse(source)
        rel = os.path.relpath(path, ".")
        walk(tree.root_node, source, filepath=rel)

if violations:
    print(f"ERROR: {len(violations)} async fn in scp-protocol production code:")
    for v in violations:
        print(f"  {v}")
    sys.exit(1)
else:
    print("scp-protocol sync check passed: zero async fn in production code (trait methods exempt).")
