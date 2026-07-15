"""Cross-language prefix parity test: TypeScript vs Python UCAN error prefixes.

The TypeScript SDK (``bindings/typescript/src/trust.ts``) maintains hand-written
copies of the same error-message prefix arrays that live in the Python SDK
(``scp_sdk.trust``).  Nothing mechanically enforces that they stay in sync; this
test fills that gap.

For each pipeline stage the test:

1. Reads ``trust.ts`` from source and extracts the prefix array literal using
   a regex that handles both single-line and multi-line array declarations.
2. Imports the corresponding Python tuple directly.
3. Asserts that the two sets are identical (order-independent).

If a prefix is added to one side but not the other, this test fails CI.
"""

from __future__ import annotations

import re
from pathlib import Path

from scp_sdk.trust import (
    _CAPABILITY_CEILING_PREFIXES,
    _EXPIRY_PREFIXES,
    _NONCE_PREFIXES,
    _REVOCATION_PREFIXES,
    _SIGNATURE_CHAIN_PREFIXES,
    _TOKEN_PARSE_PREFIXES,
)

# ---------------------------------------------------------------------------
# Path resolution — works from any cwd.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TS_TRUST = _REPO_ROOT / "bindings" / "typescript" / "src" / "trust.ts"


# ---------------------------------------------------------------------------
# TS prefix extraction helper.
# ---------------------------------------------------------------------------

# Matches a TS const array declaration of the form:
#
#   const SOME_NAME: readonly string[] = [
#     "item1",
#     "item2",
#     ...
#   ] as const;
#
# or the shorter single-line variant:
#
#   const SOME_NAME: readonly string[] = ["item1"];
#
# Group 1 captures SOME_NAME; group 2 captures the raw content between [ and ].
_TS_ARRAY_RE = re.compile(
    r"const\s+(\w+)\s*:\s*readonly\s+string\[\]\s*=\s*\[([^\]]*)\]",
    re.DOTALL,
)

# Matches a quoted string literal inside a TS array: "...", with an optional
# trailing comma and whitespace.
_TS_STRING_LITERAL_RE = re.compile(r'"([^"]*)"')


def _parse_ts_prefix_arrays(source: str) -> dict[str, list[str]]:
    """Return a mapping of TS constant name → list of string literals."""
    result: dict[str, list[str]] = {}
    for m in _TS_ARRAY_RE.finditer(source):
        name = m.group(1)
        body = m.group(2)
        items = [lit.group(1) for lit in _TS_STRING_LITERAL_RE.finditer(body)]
        result[name] = items
    return result


# ---------------------------------------------------------------------------
# Test class.
# ---------------------------------------------------------------------------


class TestTsPythonPrefixParity:
    """Verify that TypeScript prefix arrays match Python prefix tuples exactly."""

    @classmethod
    def _ts_arrays(cls) -> dict[str, list[str]]:
        source = _TS_TRUST.read_text(encoding="utf-8")
        return _parse_ts_prefix_arrays(source)

    # ---- per-stage tests ---------------------------------------------------

    def test_token_parse_prefixes_match(self) -> None:
        """TOKEN_PARSE_PREFIXES (TS) == _TOKEN_PARSE_PREFIXES (Python)."""
        ts = set(self._ts_arrays().get("TOKEN_PARSE_PREFIXES", []))
        py = set(_TOKEN_PARSE_PREFIXES)
        only_ts = ts - py
        only_py = py - ts
        assert not only_ts and not only_py, (
            f"TOKEN_PARSE_PREFIXES mismatch.\n"
            f"  Only in TS:     {sorted(only_ts)}\n"
            f"  Only in Python: {sorted(only_py)}"
        )

    def test_signature_chain_prefixes_match(self) -> None:
        """SIGNATURE_CHAIN_PREFIXES (TS) == _SIGNATURE_CHAIN_PREFIXES (Python)."""
        ts = set(self._ts_arrays().get("SIGNATURE_CHAIN_PREFIXES", []))
        py = set(_SIGNATURE_CHAIN_PREFIXES)
        only_ts = ts - py
        only_py = py - ts
        assert not only_ts and not only_py, (
            f"SIGNATURE_CHAIN_PREFIXES mismatch.\n"
            f"  Only in TS:     {sorted(only_ts)}\n"
            f"  Only in Python: {sorted(only_py)}"
        )

    def test_capability_ceiling_prefixes_match(self) -> None:
        """CAPABILITY_CEILING_PREFIXES (TS) == _CAPABILITY_CEILING_PREFIXES (Python)."""
        ts = set(self._ts_arrays().get("CAPABILITY_CEILING_PREFIXES", []))
        py = set(_CAPABILITY_CEILING_PREFIXES)
        only_ts = ts - py
        only_py = py - ts
        assert not only_ts and not only_py, (
            f"CAPABILITY_CEILING_PREFIXES mismatch.\n"
            f"  Only in TS:     {sorted(only_ts)}\n"
            f"  Only in Python: {sorted(only_py)}"
        )

    def test_nonce_prefixes_match(self) -> None:
        """NONCE_PREFIXES (TS) == _NONCE_PREFIXES (Python)."""
        ts = set(self._ts_arrays().get("NONCE_PREFIXES", []))
        py = set(_NONCE_PREFIXES)
        only_ts = ts - py
        only_py = py - ts
        assert not only_ts and not only_py, (
            f"NONCE_PREFIXES mismatch.\n"
            f"  Only in TS:     {sorted(only_ts)}\n"
            f"  Only in Python: {sorted(only_py)}"
        )

    def test_revocation_prefixes_match(self) -> None:
        """REVOCATION_PREFIXES (TS) == _REVOCATION_PREFIXES (Python)."""
        ts = set(self._ts_arrays().get("REVOCATION_PREFIXES", []))
        py = set(_REVOCATION_PREFIXES)
        only_ts = ts - py
        only_py = py - ts
        assert not only_ts and not only_py, (
            f"REVOCATION_PREFIXES mismatch.\n"
            f"  Only in TS:     {sorted(only_ts)}\n"
            f"  Only in Python: {sorted(only_py)}"
        )

    def test_expiry_prefixes_match(self) -> None:
        """EXPIRY_PREFIXES (TS) == _EXPIRY_PREFIXES (Python)."""
        ts = set(self._ts_arrays().get("EXPIRY_PREFIXES", []))
        py = set(_EXPIRY_PREFIXES)
        only_ts = ts - py
        only_py = py - ts
        assert not only_ts and not only_py, (
            f"EXPIRY_PREFIXES mismatch.\n"
            f"  Only in TS:     {sorted(only_ts)}\n"
            f"  Only in Python: {sorted(only_py)}"
        )

    def test_no_extra_ts_prefix_arrays_unguarded(self) -> None:
        """Every *_PREFIXES array in trust.ts has a corresponding Python counterpart.

        If a new prefix array is added to TS without updating this test (and the
        matching Python tuple), this test catches it.
        """
        arrays = self._ts_arrays()
        expected_names = {
            "TOKEN_PARSE_PREFIXES",
            "SIGNATURE_CHAIN_PREFIXES",
            "CAPABILITY_CEILING_PREFIXES",
            "NONCE_PREFIXES",
            "REVOCATION_PREFIXES",
            "EXPIRY_PREFIXES",
        }
        prefix_arrays_in_ts = {name for name in arrays if name.endswith("PREFIXES")}
        unguarded = prefix_arrays_in_ts - expected_names
        assert not unguarded, (
            f"New *_PREFIXES array(s) found in trust.ts without a Python parity "
            f"test: {sorted(unguarded)}. Add the corresponding Python tuple and a "
            f"test method to TestTsPythonPrefixParity."
        )
