"""Canonical JSON normalization for cross-bridge output comparison.

Bridges differ superficially in ways that do not indicate behavioral
divergence: PyO3 returns snake_case keys, NAPI returns camelCase; bytes
come back as Python `bytes`, `Buffer`, `Uint8Array`, or `list[int]`
depending on the bridge; wall-clock timestamps vary by microseconds.

This module provides `normalize(raw, schema)` which applies a declarative
`OpSchema` (per-field `FieldSpec`s) to produce a canonical dict suitable
for equality comparison between bridge outputs.

Encoding is explicit, not inferred. Every byte-valued field must declare
the encoding of the raw value via one of `bytes_from_hex`, `bytes_from_b64`,
or `bytes_raw` — the normalizer never guesses whether a hex-looking string
is hex or base64. Ambiguous strings (e.g. "beefcafe" — valid hex, also
valid base64 with a different value) silently corrupted comparisons when
the auto-detector was in place. Callers now declare intent.

See ADR-046.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Literal

Comparator = Literal[
    "exact",
    "bytes_from_hex",
    "bytes_from_b64",
    "bytes_raw",
    "ignore",
    "regex",
    "timestamp_window",
]


@dataclass(frozen=True)
class FieldSpec:
    """Describes how a single field should be compared across bridges.

    The `name` is the canonical snake_case key name (post-normalization).
    Nested paths use dot notation: "error.code". Patterns for "regex" use
    Python's `re` syntax and must match the full value (anchored).

    For byte-valued fields, the caller declares the raw encoding via one
    of the `bytes_*` comparators. The normalizer canonicalizes to base64
    and compares literally; it never auto-detects hex vs base64.
    """

    name: str
    comparator: Comparator
    pattern: str | None = None
    window_secs: int | None = None


@dataclass(frozen=True)
class OpSchema:
    """Schema for normalizing an operation's output.

    Fields not declared in `fields` pass through unchanged (recursively
    normalized). Fields declared `ignore` are removed. Fields declared
    `regex` are replaced with a stable marker string after validating the
    pattern — this preserves shape while erasing value differences.
    """

    fields: tuple[FieldSpec, ...]


_CAMEL_SPLIT = re.compile(r"([a-z0-9])([A-Z])")
_HEX_ONLY = re.compile(r"\A[0-9a-fA-F]+\Z")


def _to_snake(name: str) -> str:
    """Convert a single key from camelCase/PascalCase to snake_case."""
    # Insert underscore between lowercase/digit and uppercase boundary,
    # then lowercase. "contextId" -> "context_id", "DIDDocument" ->
    # "d_i_d_document" is fine for our shape — bridges use one style
    # consistently and we are canonicalizing, not pretty-printing.
    step1 = _CAMEL_SPLIT.sub(r"\1_\2", name)
    # Collapse repeated underscores (from stepped acronyms) and lowercase.
    return re.sub(r"_+", "_", step1).lower()


def _is_raw_bytes_like(value: object) -> bool:
    """True for byte-like values that do NOT need encoding declaration.

    Covers native byte types across bridges: Python `bytes`/`bytearray`/
    `memoryview`, NAPI `Buffer` (surfaces as `bytes`), and `Uint8Array`
    (surfaces as `list[int]` after JSON serialization).
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return True
    if (
        isinstance(value, list)
        and value
        and all(isinstance(v, int) and 0 <= v < 256 for v in value)
    ):
        return True
    return False


def _raw_to_b64(value: object, field_name: str) -> str:
    """Convert a byte-like value (native bytes, Buffer, Uint8Array/list[int]) to base64."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, list):
        return base64.b64encode(bytes(value)).decode("ascii")
    raise TypeError(
        f"field '{field_name}' declared bytes_raw but value is {type(value).__name__}: {value!r}"
    )


def _hex_to_b64(value: object, field_name: str) -> str:
    """Convert a hex-encoded string to canonical base64.

    Byte-like values (bytes/Buffer/Uint8Array/list[int]) pass through via
    `_raw_to_b64` — bridges sometimes return the same semantic value as
    raw bytes on one side and as a hex string on the other.
    """
    if _is_raw_bytes_like(value):
        return _raw_to_b64(value, field_name)
    if not isinstance(value, str):
        raise TypeError(
            f"field '{field_name}' declared bytes_from_hex but value is "
            f"{type(value).__name__}: {value!r}"
        )
    if _HEX_ONLY.fullmatch(value) is None or len(value) % 2 != 0:
        raise ValueError(
            f"field '{field_name}' declared bytes_from_hex but value is not valid hex: {value!r}"
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as err:
        raise ValueError(f"field '{field_name}' failed hex decode: {err}") from err
    return base64.b64encode(raw).decode("ascii")


def _b64_to_canonical(value: object, field_name: str) -> str:
    """Re-encode a base64 string to canonical base64 (round-trip validates)."""
    if _is_raw_bytes_like(value):
        return _raw_to_b64(value, field_name)
    if not isinstance(value, str):
        raise TypeError(
            f"field '{field_name}' declared bytes_from_b64 but value is "
            f"{type(value).__name__}: {value!r}"
        )
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as err:  # type: ignore[attr-defined]
        raise ValueError(f"field '{field_name}' failed base64 decode: {err}") from err
    return base64.b64encode(raw).decode("ascii")


def _recursive_snake(value: object) -> object:
    """Recursively rename dict keys from camelCase to snake_case."""
    if isinstance(value, dict):
        return {_to_snake(str(k)): _recursive_snake(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_recursive_snake(v) for v in value]
    return value


def _get_path(d: dict[str, object], path: str) -> tuple[dict[str, object], str, bool]:
    """Resolve a dotted path to (parent_dict, leaf_key, exists)."""
    parts = path.split(".")
    cur: object = d
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return {}, parts[-1], False
        cur = cur[part]
    if not isinstance(cur, dict):
        return {}, parts[-1], False
    return cur, parts[-1], parts[-1] in cur


def _apply_field(d: dict[str, object], spec: FieldSpec) -> None:
    parent, leaf, exists = _get_path(d, spec.name)
    if not exists:
        # Field is declared but missing from this particular response.
        # For error paths we want "ignore"/"exact" to both accept absence
        # — equality against the other side's absence is still useful.
        return

    value = parent[leaf]

    if spec.comparator == "ignore":
        del parent[leaf]
        return

    if spec.comparator == "exact":
        # Nothing to rewrite — value is compared literally.
        return

    if spec.comparator == "bytes_raw":
        parent[leaf] = _raw_to_b64(value, spec.name)
        return

    if spec.comparator == "bytes_from_hex":
        parent[leaf] = _hex_to_b64(value, spec.name)
        return

    if spec.comparator == "bytes_from_b64":
        parent[leaf] = _b64_to_canonical(value, spec.name)
        return

    if spec.comparator == "regex":
        if spec.pattern is None:
            raise ValueError(f"regex comparator for '{spec.name}' requires a pattern")
        if not isinstance(value, str):
            raise TypeError(
                f"field '{spec.name}' declared regex but value is {type(value).__name__}"
            )
        if re.fullmatch(spec.pattern, value) is None:
            raise AssertionError(
                f"field '{spec.name}' value {value!r} does not match pattern {spec.pattern!r}"
            )
        # Erase the actual value so cross-bridge comparison passes on
        # matching shape. Include the pattern in the marker so a mistake
        # at pattern-authoring time is visible.
        parent[leaf] = f"<regex:{spec.pattern}>"
        return

    if spec.comparator == "timestamp_window":
        # Timestamps vary per call. For intra-run comparison, the sane
        # behavior is to replace with a stable marker after confirming
        # the value is a numeric timestamp-ish thing. The window is
        # retained in the schema for future per-bridge consistency
        # checks (e.g., ensuring NAPI's timestamp is within window of
        # PyO3's).
        if not isinstance(value, (int, float)):
            raise TypeError(
                f"field '{spec.name}' declared timestamp_window but value is {type(value).__name__}"
            )
        parent[leaf] = "<timestamp>"
        return

    raise ValueError(f"unknown comparator: {spec.comparator}")


def _sort_keys(value: object) -> object:
    if isinstance(value, dict):
        return {k: _sort_keys(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_sort_keys(v) for v in value]
    return value


def normalize(raw: object, schema: OpSchema) -> dict[str, object]:
    """Normalize a raw bridge response into a canonical dict.

    Pipeline:
      1. Recursively snake_case all keys.
      2. Apply each field spec. Byte-valued fields must declare their
         raw encoding explicitly (`bytes_from_hex`, `bytes_from_b64`, or
         `bytes_raw`) — no auto-detection.
      3. Sort keys for stable equality comparison.

    Fields not declared in the schema pass through after step 1.

    Raises TypeError, ValueError, or AssertionError on schema violations —
    the comparator's precondition (e.g., "this field must be bytes") is
    part of the test surface, not just a hint.
    """
    if not isinstance(raw, dict):
        raise TypeError(f"normalize() expects a dict, got {type(raw).__name__}")

    snaked = _recursive_snake(raw)
    if not isinstance(snaked, dict):
        # _recursive_snake preserves type; dict in => dict out.
        raise TypeError("internal: snake-case pass returned non-dict")

    for spec in schema.fields:
        _apply_field(snaked, spec)

    result = _sort_keys(snaked)
    if not isinstance(result, dict):
        raise TypeError("internal: key-sort pass returned non-dict")
    return result
