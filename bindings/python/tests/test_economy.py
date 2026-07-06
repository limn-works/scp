"""Tests for the SCP Python SDK economy amount display helper and string wire.

Covers:
- ``format_amount`` known-currency and explicit-decimals formatting
- Exact formatting of amounts beyond 2**53 (pure integer arithmetic)
- Unknown-currency and misuse error paths
- The string-wire economy round-trip: JSON monetary amounts are canonical
  decimal STRINGS (ADR-060), while Python SDK amounts stay native ``int``

See ``.docs/adrs/ADR-060-monetary-value-representation.md`` and spec §19.
"""

from __future__ import annotations

import json

import pytest

from scp_sdk import format_amount
from scp_sdk.economy import estimate_cost, evaluate_formula
from scp_sdk.errors import ScpError


class TestFormatAmount:
    def test_usd_two_decimals(self) -> None:
        assert format_amount(150, "USD") == "1.50"
        assert format_amount(0, "USD") == "0.00"
        assert format_amount(5, "USD") == "0.05"
        assert format_amount(1234567, "USD") == "12345.67"

    def test_btc_eight_decimals(self) -> None:
        assert format_amount(100_000_000, "BTC") == "1.00000000"
        assert format_amount(1, "BTC") == "0.00000001"

    def test_zero_decimal_currency(self) -> None:
        assert format_amount(150, "SAT") == "150"
        assert format_amount(0, "SAT") == "0"

    def test_full_known_currency_table(self) -> None:
        assert format_amount(100, "EUR") == "1.00"
        assert format_amount(100, "GBP") == "1.00"
        assert format_amount(1_000_000_000, "SOL") == "1.000000000"
        assert format_amount(1_000_000, "USDC") == "1.000000"
        assert format_amount(10**18, "ETH") == "1.000000000000000000"

    def test_case_insensitive_currency(self) -> None:
        assert format_amount(150, "usd") == "1.50"
        assert format_amount(150, "Usd") == "1.50"

    def test_amounts_above_2_53_format_exactly(self) -> None:
        # 2**53 + 1 — the first integer a 64-bit float cannot represent.
        assert format_amount(9_007_199_254_740_993, "USD") == "90071992547409.93"
        # A full-width u64 near the maximum.
        assert format_amount(18_446_744_073_709_551_615, "USD") == "184467440737095516.15"

    def test_explicit_decimals_override(self) -> None:
        assert format_amount(1500, decimals=3) == "1.500"
        assert format_amount(42, decimals=0) == "42"
        assert format_amount(123_456, decimals=4) == "12.3456"

    def test_unknown_currency_raises(self) -> None:
        with pytest.raises(ScpError) as exc:
            format_amount(100, "XYZ")
        assert exc.value.code == "SCP-ECON-12070"

    def test_requires_exactly_one_of_currency_or_decimals(self) -> None:
        with pytest.raises(ScpError):
            format_amount(100)
        with pytest.raises(ScpError):
            format_amount(100, "USD", decimals=2)

    def test_negative_amount_raises(self) -> None:
        with pytest.raises(ScpError):
            format_amount(-1, "USD")

    def test_negative_decimals_raises(self) -> None:
        with pytest.raises(ScpError):
            format_amount(1, decimals=-1)


class TestStringWireRoundTrip:
    """JSON economy amounts are canonical decimal strings (ADR-060); the
    Python SDK still exposes them as native ``int``."""

    def test_estimate_cost_parses_string_amount_policy(self) -> None:
        # A paid policy whose per-message cost is a decimal STRING (the ADR-060
        # JSON wire form). The bridge must parse the string amount and return
        # the estimated cost as a native Python int.
        policy = json.dumps(
            {
                "locked": False,
                "cost_schedule": {"currency": [85, 83, 68, 0], "per_message": "100"},
                "payment_adapters": ["x402"],
                "pricing_formula": None,
                "payee": "did:dht:zpayee",
            }
        )
        cost = estimate_cost(policy, "MessageSend", {})
        assert isinstance(cost, int)
        assert cost == 100

    def test_estimate_cost_rejects_bare_number_amount(self) -> None:
        # A bare JSON number for a monetary amount is no longer accepted.
        bad_policy = json.dumps(
            {
                "locked": False,
                "cost_schedule": {"currency": [85, 83, 68, 0], "per_message": 100},
                "payment_adapters": ["x402"],
                "pricing_formula": None,
                "payee": "did:dht:zpayee",
            }
        )
        # The PyO3 bridge surfaces a serde parse failure as a native
        # ``ValueError`` at this pure-helper boundary.
        with pytest.raises(ValueError):
            estimate_cost(bad_policy, "MessageSend", {})

    def test_free_context_estimate_is_zero_int(self) -> None:
        cost = estimate_cost("", "MessageSend", {})
        assert isinstance(cost, int)
        assert cost == 0

    def test_evaluate_formula_string_amount(self) -> None:
        # A pricing formula with a decimal-string base cost and no variables
        # evaluates to that exact base cost as a native int.
        formula = json.dumps({"base_cost": "250", "variables": [], "cap": None, "floor": None})
        result = evaluate_formula(formula, {})
        assert isinstance(result, int)
        assert result == 250
