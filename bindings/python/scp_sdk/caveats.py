"""Caveat helpers for outlet UCAN invocations (review item 33).

These helpers reduce the 11-field :class:`~scp_sdk.outlets.InvocationCaveats`
friction at call sites. Each helper returns a builder that accumulates
caveat fields via chainable setters and materializes to an
:class:`InvocationCaveats` via :meth:`CaveatBuilder.build`.

Usage::

    from scp_sdk import caveats

    c = caveats.spending_cap(per_call=100).time_bounded(
        valid_from=0, valid_until=9_999_999_999,
    ).build()

Each top-level helper seeds a fresh builder; chained helpers merge into
that builder. See §7.3.8 for the field semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scp_sdk.outlets import InvocationCaveats


@dataclass
class CaveatBuilder:
    """Mutable builder for :class:`~scp_sdk.outlets.InvocationCaveats`.

    Returned by every top-level helper. Chain additional helpers to
    attach more constraints; call :meth:`build` to materialize.
    """

    _fields: dict[str, Any] = field(default_factory=dict)

    def spending_cap(
        self,
        *,
        per_call: int | None = None,
        cumulative: int | None = None,
    ) -> CaveatBuilder:
        """Attach spending caps (§7.3.8 ``amount_max_per_call`` / ``amount_max_cumulative``)."""
        if per_call is not None:
            self._fields["amount_max_per_call"] = per_call
        if cumulative is not None:
            self._fields["amount_max_cumulative"] = cumulative
        return self

    def time_bounded(
        self,
        *,
        valid_from: int | None = None,
        valid_until: int | None = None,
        hours_of_day: int | None = None,
        days_of_week: int | None = None,
    ) -> CaveatBuilder:
        """Attach temporal bounds (§7.3.8)."""
        if valid_from is not None:
            self._fields["valid_from"] = valid_from
        if valid_until is not None:
            self._fields["valid_until"] = valid_until
        if hours_of_day is not None:
            # 24-bit mask assertion (§7.3.8 ``hours_of_day`` constraint).
            if not 0 <= hours_of_day < (1 << 24):
                raise ValueError(
                    f"hours_of_day must be a 24-bit bitmask (0 <= x < 2^24); got {hours_of_day}"
                )
            self._fields["hours_of_day"] = hours_of_day
        if days_of_week is not None:
            if not 0 <= days_of_week < (1 << 7):
                raise ValueError(
                    f"days_of_week must be a 7-bit bitmask (0 <= x < 128); got {days_of_week}"
                )
            self._fields["days_of_week"] = days_of_week
        return self

    def rate_limited(
        self,
        *,
        max_calls: int | None = None,
        rate_window: int | None = None,
    ) -> CaveatBuilder:
        """Attach a rate limit (§7.3.8 ``max_calls`` / ``rate_window``)."""
        if max_calls is not None:
            self._fields["max_calls"] = max_calls
        if rate_window is not None:
            self._fields["rate_window"] = rate_window
        return self

    def for_target(
        self,
        *,
        allowed_target_dids: list[str] | None = None,
        allowed_adapters: list[str] | None = None,
    ) -> CaveatBuilder:
        """Restrict target DIDs and/or adapters (§7.3.8)."""
        if allowed_target_dids is not None:
            self._fields["allowed_target_dids"] = list(allowed_target_dids)
        if allowed_adapters is not None:
            self._fields["allowed_adapters"] = list(allowed_adapters)
        return self

    def input_schema(self, schema: dict[str, Any]) -> CaveatBuilder:
        """Attach a JSON-Schema narrowing for the outlet input."""
        self._fields["input_schema"] = schema
        return self

    def origin_kind(self, kind: str) -> CaveatBuilder:
        """Pin the origin outlet kind (``"Query"`` or ``"Action"``)."""
        if kind not in ("Query", "Action"):
            raise ValueError(f"origin_kind must be 'Query' or 'Action', got {kind!r}")
        self._fields["origin_kind"] = kind
        return self

    def build(self) -> InvocationCaveats:
        """Materialize the accumulated fields into an :class:`InvocationCaveats`."""
        return InvocationCaveats(**self._fields)


def spending_cap(
    *,
    per_call: int | None = None,
    cumulative: int | None = None,
) -> CaveatBuilder:
    """Start a builder with spending-cap fields populated."""
    return CaveatBuilder().spending_cap(per_call=per_call, cumulative=cumulative)


def time_bounded(
    *,
    valid_from: int | None = None,
    valid_until: int | None = None,
    hours_of_day: int | None = None,
    days_of_week: int | None = None,
) -> CaveatBuilder:
    """Start a builder with time-bound fields populated."""
    return CaveatBuilder().time_bounded(
        valid_from=valid_from,
        valid_until=valid_until,
        hours_of_day=hours_of_day,
        days_of_week=days_of_week,
    )


def rate_limited(
    *,
    max_calls: int | None = None,
    rate_window: int | None = None,
) -> CaveatBuilder:
    """Start a builder with rate-limit fields populated."""
    return CaveatBuilder().rate_limited(max_calls=max_calls, rate_window=rate_window)


def for_target(
    *,
    allowed_target_dids: list[str] | None = None,
    allowed_adapters: list[str] | None = None,
) -> CaveatBuilder:
    """Start a builder with target-restriction fields populated."""
    return CaveatBuilder().for_target(
        allowed_target_dids=allowed_target_dids,
        allowed_adapters=allowed_adapters,
    )


__all__ = [
    "CaveatBuilder",
    "for_target",
    "rate_limited",
    "spending_cap",
    "time_bounded",
]
