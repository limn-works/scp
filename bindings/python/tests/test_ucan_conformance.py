"""Cross-language conformance test for UCAN error prefix matching.

``_classify_ucan_error()`` in ``scp_sdk.trust`` uses string prefix matching
against Rust ``UcanError::Display`` output to classify validation failures
into pipeline stages.  If the Rust error messages change, this classification
silently falls back to ``"unknown"`` (fail-closed).

This test parses **both** the Python prefix constants and the Rust
``#[error("...")]`` annotations from source, then verifies bidirectional
coverage:

1. Every Python prefix must match at least one Rust error pattern.
2. Every Rust *validation-pipeline* error must be covered by at least one
   Python prefix (operational errors like ``RevocationUnauthorized`` are
   explicitly excluded — they are not produced by the 11-step pipeline).

If either side changes without updating the other, this test fails.

See GitHub issue #989.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

from scp_sdk.trust import (
    _CAPABILITY_CEILING_PREFIXES,
    _EXPIRY_PREFIXES,
    _NONCE_PREFIXES,
    _REVOCATION_PREFIXES,
    _SIGNATURE_CHAIN_PREFIXES,
    _TOKEN_PARSE_PREFIXES,
    _classify_ucan_error,
)

# ---------------------------------------------------------------------------
# Paths — resolve relative to this file so the test works from any cwd.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RUST_UCAN_MOD = _REPO_ROOT / "crates" / "scp-core" / "src" / "crypto" / "ucan" / "mod.rs"
_RUST_VALIDATE = _REPO_ROOT / "crates" / "scp-core" / "src" / "crypto" / "ucan" / "validate.rs"
_RUST_RESOLVERS = _REPO_ROOT / "crates" / "scp-ffi" / "common" / "src" / "resolvers.rs"


# ---------------------------------------------------------------------------
# Helpers — parse Rust source for #[error("...")] annotations
# ---------------------------------------------------------------------------

# Matches thiserror #[error("...")] attribute strings, including multi-line
# annotations where whitespace may appear between the parentheses.
# Uses re.DOTALL so \s matches newlines between the opening paren and the
# closing paren.  Captures everything inside the outermost quotes.
_ERROR_ATTR_RE = re.compile(r'#\[error\(\s*"([^"]+)"\s*\)\]', re.DOTALL)

# Matches Display impl format strings: write!(f, "...", ...) patterns.
_WRITE_FMT_RE = re.compile(r'write!\(f,\s*"([^"]+)"')

# Matches runtime MalformedToken(format!("...", ...)) constructions.
# Captures the format string literal inside the format!() macro.
# Uses re.DOTALL so \s matches newlines in multi-line format! calls.
_MALFORMED_TOKEN_FMT_RE = re.compile(r'MalformedToken\(format!\(\s*"([^"]+)"', re.DOTALL)

# Matches runtime MalformedToken("...".to_owned()) constructions —
# string-literal variants without format!().  For example:
#   MalformedToken("missing signature segment".to_owned())
# Captures the string literal inside the quotes.
_MALFORMED_TOKEN_LITERAL_RE = re.compile(r'MalformedToken\(\s*"([^"]+)"\.to_owned\(\)', re.DOTALL)


def _extract_error_prefixes_from_thiserror(source: str) -> list[str]:
    """Extract the static prefix of each ``#[error("...")]`` annotation.

    For format strings like ``"malformed token: {0}"``, the prefix is
    ``"malformed token: "`` (everything before the first ``{``).
    For literal strings like ``"signature verification failed"``, the
    entire string is the prefix.
    """
    prefixes: list[str] = []
    for match in _ERROR_ATTR_RE.finditer(source):
        fmt = match.group(1)
        # Extract the static prefix (before the first format placeholder).
        brace_idx = fmt.find("{")
        if brace_idx == -1:
            prefixes.append(fmt)
        else:
            prefixes.append(fmt[:brace_idx])
    return prefixes


def _extract_runtime_malformed_token_prefixes(source: str) -> list[str]:
    """Extract static prefixes from runtime ``MalformedToken`` constructions.

    Handles two patterns:

    1. ``MalformedToken(format!("...", ...))`` — dynamic format strings.
    2. ``MalformedToken("...".to_owned())`` — string-literal constructions.

    The Display output is ``"malformed token: <inner string>"`` because
    ``MalformedToken(String)`` has ``#[error("malformed token: {0}")]``.

    Returns the ``"malformed token: <static prefix>"`` for each call.
    """
    prefixes: list[str] = []

    # Pattern 1: format!() constructions.
    for match in _MALFORMED_TOKEN_FMT_RE.finditer(source):
        fmt = match.group(1)
        brace_idx = fmt.find("{")
        if brace_idx == -1:
            static_part = fmt
        else:
            static_part = fmt[:brace_idx]
        # The Display impl wraps with "malformed token: " prefix.
        prefixes.append(f"malformed token: {static_part}")

    # Pattern 2: "...".to_owned() literal constructions.
    for match in _MALFORMED_TOKEN_LITERAL_RE.finditer(source):
        literal = match.group(1)
        prefixes.append(f"malformed token: {literal}")

    return prefixes


def _extract_resolution_error_prefixes(source: str) -> list[str]:
    """Extract static prefixes from the ``ResolutionError`` Display impl.

    These are ``write!(f, "DID not found: {msg}")`` style patterns in the
    hand-written Display impl.  Each becomes ``MalformedToken("DID not found: ...")``
    via ``From<ResolutionError> for CoreUcanError``, so the Python-visible
    prefix is ``"malformed token: DID not found: "`` etc.

    The search is scoped to the ``impl Display for ResolutionError`` block
    to avoid false-positive matches if other ``write!(f, ...)`` calls are
    added elsewhere in the file.
    """
    # Extract the impl Display for ResolutionError block.
    display_block_re = re.compile(
        r"impl\s+(?:(?:std::)?fmt::)?Display\s+for\s+ResolutionError\s*\{",
    )
    m = display_block_re.search(source)
    if m is None:
        return []

    # Find the matching closing brace by tracking brace depth.
    start = m.start()
    depth = 0
    block_end = len(source)
    for i in range(m.end() - 1, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                block_end = i + 1
                break

    display_source = source[start:block_end]

    prefixes: list[str] = []
    for match in _WRITE_FMT_RE.finditer(display_source):
        fmt = match.group(1)
        brace_idx = fmt.find("{")
        if brace_idx == -1:
            static_part = fmt
        else:
            static_part = fmt[:brace_idx]
        # These become MalformedToken(e.to_string()), so the final Display
        # is "malformed token: <ResolutionError Display>".
        prefixes.append(f"malformed token: {static_part}")
    return prefixes


# ---------------------------------------------------------------------------
# Collect all Python-side prefixes into a flat set.
# ---------------------------------------------------------------------------

_ALL_PYTHON_PREFIXES: tuple[tuple[str, ...], ...] = (
    _TOKEN_PARSE_PREFIXES,
    _SIGNATURE_CHAIN_PREFIXES,
    _CAPABILITY_CEILING_PREFIXES,
    _NONCE_PREFIXES,
    _REVOCATION_PREFIXES,
    _EXPIRY_PREFIXES,
)

_FLAT_PYTHON_PREFIXES: set[str] = set()
for _group in _ALL_PYTHON_PREFIXES:
    _FLAT_PYTHON_PREFIXES.update(_group)


# ---------------------------------------------------------------------------
# Rust UcanError variants that are NOT part of the 11-step validation
# pipeline and are intentionally unmapped in _classify_ucan_error.
#
# These are operational errors (revocation management, URI parsing, etc.)
# that never appear as validation failures.  They correctly classify as
# "unknown" and produce fail-closed (all False) behavior.
# ---------------------------------------------------------------------------

_OPERATIONAL_ERROR_PREFIXES: frozenset[str] = frozenset(
    {
        "revocation unauthorized: ",
        "revocation failed: ",
        "invalid capability URI: ",
    }
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRustSourceExists:
    """Guard: ensure the Rust source files exist at the expected paths."""

    def test_ucan_mod_rs_exists(self) -> None:
        assert _RUST_UCAN_MOD.exists(), (
            f"Rust UcanError source not found at {_RUST_UCAN_MOD}. "
            f"If the file moved, update _RUST_UCAN_MOD in this test."
        )

    def test_validate_rs_exists(self) -> None:
        assert _RUST_VALIDATE.exists(), (
            f"Rust validate source not found at {_RUST_VALIDATE}. "
            f"If the file moved, update _RUST_VALIDATE in this test."
        )

    def test_resolvers_rs_exists(self) -> None:
        assert _RUST_RESOLVERS.exists(), (
            f"Rust ResolutionError source not found at {_RUST_RESOLVERS}. "
            f"If the file moved, update _RUST_RESOLVERS in this test."
        )


class TestEveryPythonPrefixMatchesRust:
    """Every Python prefix must match at least one Rust error pattern.

    If a Python prefix doesn't match any Rust error, it's dead code that
    gives false confidence about coverage.
    """

    @pytest.fixture(scope="class")
    def rust_prefixes(self) -> set[str]:
        """All Rust-side static error prefixes (UcanError + ResolutionError)."""
        ucan_source = _RUST_UCAN_MOD.read_text()
        resolver_source = _RUST_RESOLVERS.read_text()

        ucan_prefixes = _extract_error_prefixes_from_thiserror(ucan_source)
        resolution_prefixes = _extract_resolution_error_prefixes(resolver_source)

        return set(ucan_prefixes) | set(resolution_prefixes)

    @pytest.fixture(scope="class")
    def rust_full_strings(self) -> list[str]:
        """Full #[error("...")] format strings (before placeholder expansion)."""
        ucan_source = _RUST_UCAN_MOD.read_text()
        return [m.group(1) for m in _ERROR_ATTR_RE.finditer(ucan_source)]

    @pytest.fixture(scope="class")
    def rust_runtime_prefixes(self) -> set[str]:
        """All runtime MalformedToken prefixes from validate.rs and resolvers.rs.

        Used to verify that Python sub-prefixes under a generic thiserror
        prefix (e.g. ``"malformed token: "``) match a specific runtime
        construction, not just the generic prefix.
        """
        validate_source = _RUST_VALIDATE.read_text()
        resolver_source = _RUST_RESOLVERS.read_text()

        validate_rt = _extract_runtime_malformed_token_prefixes(validate_source)
        resolver_rt = _extract_runtime_malformed_token_prefixes(resolver_source)
        resolution_display = _extract_resolution_error_prefixes(resolver_source)

        return set(validate_rt) | set(resolver_rt) | set(resolution_display)

    def test_each_python_prefix_has_rust_match(
        self, rust_prefixes: set[str], rust_runtime_prefixes: set[str]
    ) -> None:
        """For each Python prefix, at least one Rust prefix must start with it
        (or vice versa --- the Python prefix starts with a Rust prefix).

        Additionally, when a Python prefix matches only via the "starts with
        a generic Rust prefix" path (e.g. ``"malformed token: DID not found"``
        matching ``"malformed token: "``), the Python prefix must also match
        at least one *specific* runtime construction from validate.rs or
        resolvers.rs.  This prevents typos in Python sub-prefixes from
        silently passing.
        """
        unmatched: list[str] = []
        for py_prefix in sorted(_FLAT_PYTHON_PREFIXES):
            # A Python prefix matches a Rust error if:
            # - Some Rust prefix starts with the Python prefix, OR
            # - The Python prefix starts with some Rust prefix.
            # The second case handles sub-patterns like
            #   "malformed token: DID not found" matching Rust
            #   "malformed token: " (the MalformedToken variant).
            has_exact = any(rust_pfx.startswith(py_prefix) for rust_pfx in rust_prefixes)
            if has_exact:
                continue

            has_generic = any(py_prefix.startswith(rust_pfx) for rust_pfx in rust_prefixes)
            if not has_generic:
                unmatched.append(py_prefix)
                continue

            # The Python prefix matched only via a generic Rust prefix
            # (e.g. "malformed token: ").  Verify it also matches a specific
            # runtime construction to catch typos.
            has_specific = any(
                rt_pfx.startswith(py_prefix) or py_prefix.startswith(rt_pfx)
                for rt_pfx in rust_runtime_prefixes
            )
            if not has_specific:
                unmatched.append(py_prefix)

        assert not unmatched, (
            "Python prefixes with no matching Rust error pattern:\n"
            + "\n".join(f"  - {p!r}" for p in unmatched)
            + "\n\nEither the Rust error message changed (update the Python "
            "prefix) or the Python prefix is stale (remove it).\n"
            "Note: sub-prefixes under generic Rust prefixes (e.g. "
            "'malformed token: ...') must match a specific runtime "
            "construction in validate.rs or resolvers.rs."
        )


class TestEveryRustValidationErrorMatchesPython:
    """Every Rust validation-pipeline error must be covered by a Python prefix.

    Operational errors (revocation management, URI parsing) are excluded —
    they correctly classify as "unknown" (fail-closed).
    """

    @pytest.fixture(scope="class")
    def rust_validation_prefixes(self) -> list[str]:
        """Rust error prefixes that are part of the validation pipeline."""
        ucan_source = _RUST_UCAN_MOD.read_text()
        all_prefixes = _extract_error_prefixes_from_thiserror(ucan_source)
        return [p for p in all_prefixes if p not in _OPERATIONAL_ERROR_PREFIXES]

    @pytest.fixture(scope="class")
    def resolution_prefixes(self) -> list[str]:
        """Rust ResolutionError prefixes (wrapped as MalformedToken)."""
        resolver_source = _RUST_RESOLVERS.read_text()
        return _extract_resolution_error_prefixes(resolver_source)

    def test_each_rust_validation_prefix_covered(self, rust_validation_prefixes: list[str]) -> None:
        """Each Rust validation error prefix must be covered by at least one
        Python prefix (the Python prefix is a prefix of the Rust prefix,
        or matches exactly)."""
        uncovered: list[str] = []
        for rust_pfx in rust_validation_prefixes:
            covered = any(
                rust_pfx.startswith(py_prefix) or py_prefix.startswith(rust_pfx)
                for py_prefix in _FLAT_PYTHON_PREFIXES
            )
            if not covered:
                uncovered.append(rust_pfx)
        assert not uncovered, (
            "Rust validation error prefixes not covered by any Python prefix:\n"
            + "\n".join(f"  - {p!r}" for p in uncovered)
            + "\n\nAdd a matching prefix to the appropriate _*_PREFIXES tuple "
            "in scp_sdk/trust.py."
        )

    def test_each_resolution_error_prefix_covered(self, resolution_prefixes: list[str]) -> None:
        """Each ResolutionError prefix (wrapped as MalformedToken) must be
        covered by at least one Python prefix."""
        uncovered: list[str] = []
        for rust_pfx in resolution_prefixes:
            covered = any(
                rust_pfx.startswith(py_prefix) or py_prefix.startswith(rust_pfx)
                for py_prefix in _FLAT_PYTHON_PREFIXES
            )
            if not covered:
                uncovered.append(rust_pfx)
        assert not uncovered, (
            "ResolutionError prefixes not covered by any Python prefix:\n"
            + "\n".join(f"  - {p!r}" for p in uncovered)
            + "\n\nThese become MalformedToken(...) via From<ResolutionError>. "
            "Add a matching prefix to _SIGNATURE_CHAIN_PREFIXES in "
            "scp_sdk/trust.py."
        )


class TestClassifyCoversAllRustVariants:
    """Integration: feed synthetic Rust error messages through _classify_ucan_error
    and verify none classify as "unknown" (except operational errors)."""

    @pytest.fixture(scope="class")
    def synthetic_messages(self) -> list[tuple[str, bool]]:
        """Generate a synthetic error message for each Rust UcanError variant.

        Returns (message, is_operational) tuples.  For format-string variants,
        placeholder values are filled with representative strings.
        """
        ucan_source = _RUST_UCAN_MOD.read_text()
        results: list[tuple[str, bool]] = []

        for match in _ERROR_ATTR_RE.finditer(ucan_source):
            fmt = match.group(1)
            # Replace thiserror placeholders with representative values.
            # {0}, {1}, etc. — positional
            msg = re.sub(r"\{[0-9]+\}", "test_value", fmt)
            # {name} — named
            msg = re.sub(r"\{[a-z_]+\}", "test_value", fmt)

            is_op = any(fmt.startswith(op_pfx.rstrip()) for op_pfx in _OPERATIONAL_ERROR_PREFIXES)
            results.append((msg, is_op))
        return results

    def test_validation_errors_never_classify_as_unknown(
        self, synthetic_messages: list[tuple[str, bool]]
    ) -> None:
        """Every validation-pipeline error must classify to a known stage."""
        unknown_msgs: list[str] = []
        for msg, is_operational in synthetic_messages:
            if is_operational:
                continue
            stage = _classify_ucan_error(msg)
            if stage == "unknown":
                unknown_msgs.append(msg)
        assert not unknown_msgs, (
            "Validation errors classified as 'unknown' "
            "(Python prefix missing or changed):\n" + "\n".join(f"  - {m!r}" for m in unknown_msgs)
        )

    def test_operational_errors_classify_as_unknown(
        self, synthetic_messages: list[tuple[str, bool]]
    ) -> None:
        """Operational errors must classify as 'unknown' (fail-closed)."""
        misclassified: list[tuple[str, str]] = []
        for msg, is_operational in synthetic_messages:
            if not is_operational:
                continue
            stage = _classify_ucan_error(msg)
            if stage != "unknown":
                misclassified.append((msg, stage))
        assert not misclassified, (
            "Operational errors should classify as 'unknown' but got:\n"
            + "\n".join(f"  - {m!r} -> {s!r}" for m, s in misclassified)
        )


class TestResolutionErrorClassification:
    """ResolutionError variants become MalformedToken(...) and must classify
    to the correct pipeline stage."""

    _RESOLUTION_MESSAGES: ClassVar[list[tuple[str, str]]] = [
        ("malformed token: DID not found: did:dht:z6MkTest", "signatures"),
        ("malformed token: invalid DID document: bad sig", "signatures"),
        ("malformed token: network unavailable: timeout", "signatures"),
        ("malformed token: DID revoked/downgraded: seq mismatch", "signatures"),
    ]

    @pytest.mark.parametrize(
        ("message", "expected_stage"),
        _RESOLUTION_MESSAGES,
        ids=[m[0].split(": ", 2)[1] for m in _RESOLUTION_MESSAGES],
    )
    def test_resolution_error_classifies_correctly(self, message: str, expected_stage: str) -> None:
        assert _classify_ucan_error(message) == expected_stage


class TestRuntimeMalformedTokenCoverage:
    """Runtime ``MalformedToken(format!(...))`` and ``MalformedToken("...".to_owned())``
    constructions in validate.rs and resolvers.rs must be covered by specific
    Python sub-prefixes.

    These runtime messages are wrapped by the ``#[error("malformed token: {0}")]``
    Display impl, so the Python-visible prefix is ``"malformed token: <static part>"``.
    Without specific sub-prefixes, they all fall through to the generic
    ``"malformed token:"`` catch-all in ``_TOKEN_PARSE_PREFIXES`` and classify
    as ``token_parse`` instead of the correct pipeline stage.

    **Scope note:** ``mint.rs`` and ``nonce.rs`` are intentionally excluded.
    ``MalformedToken`` constructions in ``mint.rs`` occur during token
    *minting* (not validation) and do not flow through
    ``_classify_ucan_error``.  ``nonce.rs`` is also excluded — its
    ``MalformedToken`` constructions are storage/persistence operations
    (serialization/deserialization), not validation-pipeline errors.  Only
    ``validate.rs`` and ``resolvers.rs`` produce runtime ``MalformedToken``
    errors that reach the Python validation pipeline.
    """

    @pytest.fixture(scope="class")
    def validate_runtime_prefixes(self) -> list[str]:
        """Extract runtime MalformedToken prefixes from validate.rs."""
        source = _RUST_VALIDATE.read_text()
        return _extract_runtime_malformed_token_prefixes(source)

    @pytest.fixture(scope="class")
    def resolver_runtime_prefixes(self) -> list[str]:
        """Extract runtime MalformedToken prefixes from resolvers.rs."""
        source = _RUST_RESOLVERS.read_text()
        return _extract_runtime_malformed_token_prefixes(source)

    def test_both_format_and_literal_patterns_extracted(
        self, validate_runtime_prefixes: list[str]
    ) -> None:
        """Verify that both ``format!()`` and ``.to_owned()`` constructions
        are extracted from validate.rs.

        validate.rs contains at least one ``MalformedToken("...".to_owned())``
        at line 792 (``"missing signature segment"``).  If the literal regex
        stops matching, this test catches it.
        """
        literal_prefix = "malformed token: missing signature segment"
        assert literal_prefix in validate_runtime_prefixes, (
            f"Expected {literal_prefix!r} from .to_owned() pattern, "
            f"but only found: {validate_runtime_prefixes}"
        )
        # Also verify we have at least one format!() prefix (there are many).
        format_prefixes = [p for p in validate_runtime_prefixes if p != literal_prefix]
        assert len(format_prefixes) > 0, (
            "Expected at least one format!() runtime prefix from validate.rs"
        )

    def test_each_validate_runtime_prefix_covered(
        self, validate_runtime_prefixes: list[str]
    ) -> None:
        """Each validate.rs runtime MalformedToken prefix must be covered
        by at least one Python prefix."""
        uncovered: list[str] = []
        for rust_pfx in validate_runtime_prefixes:
            covered = any(
                rust_pfx.startswith(py_prefix) or py_prefix.startswith(rust_pfx)
                for py_prefix in _FLAT_PYTHON_PREFIXES
            )
            if not covered:
                uncovered.append(rust_pfx)
        assert not uncovered, (
            "validate.rs runtime MalformedToken prefixes not covered:\n"
            + "\n".join(f"  - {p!r}" for p in uncovered)
            + "\n\nAdd a matching sub-prefix to the appropriate "
            "_*_PREFIXES tuple in scp_sdk/trust.py."
        )

    def test_each_resolver_runtime_prefix_covered(
        self, resolver_runtime_prefixes: list[str]
    ) -> None:
        """Each resolvers.rs runtime MalformedToken prefix must be covered
        by at least one Python prefix."""
        uncovered: list[str] = []
        for rust_pfx in resolver_runtime_prefixes:
            covered = any(
                rust_pfx.startswith(py_prefix) or py_prefix.startswith(rust_pfx)
                for py_prefix in _FLAT_PYTHON_PREFIXES
            )
            if not covered:
                uncovered.append(rust_pfx)
        assert not uncovered, (
            "resolvers.rs runtime MalformedToken prefixes not covered:\n"
            + "\n".join(f"  - {p!r}" for p in uncovered)
            + "\n\nAdd a matching sub-prefix to _SIGNATURE_CHAIN_PREFIXES "
            "in scp_sdk/trust.py."
        )

    def test_runtime_prefixes_classify_correctly(
        self, validate_runtime_prefixes: list[str], resolver_runtime_prefixes: list[str]
    ) -> None:
        """Runtime MalformedToken messages should NOT classify as 'unknown'."""
        all_prefixes = validate_runtime_prefixes + resolver_runtime_prefixes
        unknown_msgs: list[str] = []
        for prefix in all_prefixes:
            # Create a synthetic message by appending a test value.
            msg = f"{prefix}test_value"
            stage = _classify_ucan_error(msg)
            if stage == "unknown":
                unknown_msgs.append(msg)
        assert not unknown_msgs, (
            "Runtime MalformedToken messages classified as 'unknown':\n"
            + "\n".join(f"  - {m!r}" for m in unknown_msgs)
        )


class TestPrefixCountsMatchExpected:
    """Sanity check: the number of Rust UcanError variants must match what
    we expect.  If a variant is added or removed, this test catches it
    even if the prefix matching accidentally still passes."""

    def test_ucan_error_variant_count(self) -> None:
        """UcanError should have exactly the expected number of #[error] attrs."""
        ucan_source = _RUST_UCAN_MOD.read_text()
        error_count = len(_ERROR_ATTR_RE.findall(ucan_source))
        # 28 variants as of the current codebase.
        # If this fails, a variant was added or removed — update both
        # this count AND the Python prefix tuples in trust.py.
        assert error_count == 28, (
            f"Expected 28 UcanError variants, found {error_count}. "
            f"If a variant was added, add the corresponding prefix to "
            f"trust.py and update this count. If removed, clean up "
            f"trust.py and update this count."
        )

    def test_resolution_error_variant_count(self) -> None:
        """ResolutionError should have exactly 4 Display arms."""
        resolver_source = _RUST_RESOLVERS.read_text()
        # Count prefixes extracted from the impl Display for ResolutionError
        # block.  _extract_resolution_error_prefixes scopes the search to
        # that specific impl block, not the entire file.
        resolution_count = len(_extract_resolution_error_prefixes(resolver_source))
        assert resolution_count == 4, (
            f"Expected exactly 4 ResolutionError Display arms, found "
            f"{resolution_count}. If variants were added or removed, "
            f"update _SIGNATURE_CHAIN_PREFIXES in trust.py and this count."
        )
