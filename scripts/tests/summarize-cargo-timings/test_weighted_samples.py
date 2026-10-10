"""Tests for the concurrency weighting in scripts/summarize-cargo-timings.py.

Run with `python3.12 -m pytest scripts/tests/summarize-cargo-timings/ -v`.
"""

from __future__ import annotations

import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "summarize-cargo-timings.py"
_spec = importlib.util.spec_from_file_location("summarize_cargo_timings", _SCRIPT)
assert _spec is not None and _spec.loader is not None
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

# The sample times of the scp-ffi rebuild report from compile-timings run 38006910347:
# four samples in the first 1.34 s, then one at 105.27 s, with a 105.3 s wall.
REBUILD_T = [0.0, 1.22, 1.34, 1.34, 105.27]


def _samples(times: list[float], active: int = 1) -> list[dict]:
    return [{"t": t, "active": active, "waiting": 0, "inactive": 0} for t in times]


def test_each_sample_covers_the_time_until_the_next_one() -> None:
    durations = [dt for _, dt in mod.weighted_samples(_samples(REBUILD_T), 105.3)]
    assert durations == pytest.approx([1.22, 0.12, 0.0, 103.93, 0.03])
    assert sum(durations) == pytest.approx(105.3)


def test_uneven_samples_are_not_weighted_evenly() -> None:
    # Even weighting gives every sample 105.27 / 4 = 26.3 s; the sample before the
    # long gap must carry the gap.
    weighted = mod.weighted_samples(_samples(REBUILD_T), 105.3)
    assert weighted[3][1] != pytest.approx(105.27 / 4)


@pytest.mark.parametrize(
    ("times", "wall"),
    [
        ([0.5, 2.0, 3.0], 10.0),  # first sample after the build starts
        ([0.0, 4.0, 12.0], 10.0),  # a sample after the last unit finishes
        ([3.0, 0.0, 1.0], 5.0),  # samples out of order
        ([0.0], 7.0),  # a single sample
    ],
)
def test_durations_are_non_negative_and_sum_to_wall(
    times: list[float], wall: float
) -> None:
    durations = [dt for _, dt in mod.weighted_samples(_samples(times), wall)]
    assert all(dt >= 0 for dt in durations)
    assert sum(durations) == pytest.approx(wall)


def _summary(
    tmp_path: Path, units: list[dict], concurrency: list[dict], cores: int
) -> str:
    report = tmp_path / "rebuild" / "timing.html"
    report.parent.mkdir()
    report.write_text(
        f"<script>\nconst UNIT_DATA = {json.dumps(units)};\n"
        f"const CONCURRENCY_DATA = {json.dumps(concurrency)};\n</script>",
        encoding="utf-8",
    )
    out = io.StringIO()
    with redirect_stdout(out):
        mod.summarize(report, cores)
    return out.getvalue()


def _unit(start: float, duration: float) -> dict:
    return {
        "name": "u",
        "version": "1",
        "target": "",
        "start": start,
        "duration": duration,
    }


def test_rebuild_report_shares_stay_within_the_build(tmp_path: Path) -> None:
    text = _summary(tmp_path, [_unit(1.34, 103.96)], _samples(REBUILD_T), 3)
    assert "wall time under 3 active:   105.3 s (100% of the build)" in text
    assert "wall time at 1 or 0 active: 105.3 s (100%)" in text
    assert "125%" not in text


def test_a_full_machine_counts_as_no_starved_time(tmp_path: Path) -> None:
    text = _summary(tmp_path, [_unit(0.0, 10.0)], _samples([0.0, 9.0], active=3), 3)
    assert "wall time under 3 active:   0.0 s (0% of the build)" in text
    assert "wall time at 1 or 0 active: 0.0 s (0%)" in text
