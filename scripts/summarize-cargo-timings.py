#!/usr/bin/env python3
"""Print what a `cargo build --timings=html` report says, as text a log can carry.

`.github/workflows/compile-timings.yml` runs `cargo build --timings` for each
cargo invocation `ci.yml`'s `rust-test` job runs, then calls this script on the directory
holding the reports. The HTML report embeds two JavaScript arrays, and this script reads
both out of it:

  UNIT_DATA         one entry per compiled unit, carrying its start second, its duration,
                    and the seconds the unit spent producing rmeta before its dependents
                    could start.
  CONCURRENCY_DATA  samples at uneven times, each carrying its second `t`, how many units
                    were running, how many were ready but waiting for a core, and how many
                    were blocked on a dependency.

From those two arrays this script reports the wall time, the summed unit time and the
floor that the runner's core count imposes on it, the twenty slowest units, how much of the
wall time ran fewer units than the machine has cores, and the longest chain of units that
the schedule actually realised. It reads the reports and writes text; it
compiles nothing and it fails no build.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# The number of vCPUs a GitHub-hosted `ubuntu-latest` runner gives a job, used when the
# caller names no count. A sample whose `active` count falls below the core count means
# cargo could not fill the machine. The `bridge-timings` job runs on `macos-latest`, which
# gives a job 3 vCPUs, so it passes 3 as the second argument.
DEFAULT_RUNNER_CORES = 4
TOP_N = 20


def extract_array(html: str, name: str) -> list[dict]:
    """Return the JavaScript array literal `name` that cargo embedded in its report.

    Returns an empty list when the report carries no such array, because cargo has
    renamed these arrays before and a summary is worth less than a failed build.
    """
    match = re.search(rf"(?:const|let|var)\s+{name}\s*=\s*(\[.*?\]);", html, re.DOTALL)
    if match is None:
        print(f"  (note: {name} is absent from the report; cargo's format changed)")
        return []
    return json.loads(match.group(1))


def weighted_samples(concurrency: list[dict], wall: float) -> list[tuple[dict, float]]:
    """Pair each concurrency sample, in time order, with the seconds of the build it covers.

    Cargo does not sample on a fixed clock, so each sample holds from its own `t` until
    the next sample's `t`, and the last one holds until `wall`. The first sample also
    covers the build's start, and every `t` is clamped into [0, wall], so the durations
    are never negative and always sum to `wall`: no share computed from them exceeds 100%.
    """
    ordered = sorted(concurrency, key=lambda s: s["t"])
    bounds = [0.0] + [min(max(s["t"], 0.0), wall) for s in ordered[1:]] + [wall]
    return [(s, bounds[i + 1] - bounds[i]) for i, s in enumerate(ordered)]


def summarize(report: Path, cores: int) -> None:
    html = report.read_text(encoding="utf-8")
    print(f"=== {report.parent.name} ===")
    units = extract_array(html, "UNIT_DATA")
    concurrency = extract_array(html, "CONCURRENCY_DATA")
    if not units:
        print("  the report carries no unit data\n")
        return

    wall = max(u["start"] + u["duration"] for u in units)
    cpu_seconds = sum(u["duration"] for u in units)

    print(f"units compiled:            {len(units)}")
    print(f"wall time:                 {wall:.1f} s")
    print(f"summed unit time:          {cpu_seconds:.1f} s")
    print(f"mean parallelism:          {cpu_seconds / wall:.2f} units")
    # A runner with `cores` vCPUs cannot finish sooner than the summed unit time divided by
    # `cores`, whatever the dependency graph allows. Comparing the wall time against that
    # floor says whether the build is short of work to run or short of cores to run it on.
    print(
        f"{cores}-core floor (summed/{cores}): {cpu_seconds / cores:.1f} s"
        f"  — wall is {100 * wall / (cpu_seconds / cores) - 100:+.0f}% against it"
    )

    if concurrency:
        weighted = weighted_samples(concurrency, wall)
        starved = sum(dt for s, dt in weighted if s["active"] < cores)
        single = sum(dt for s, dt in weighted if s["active"] <= 1)
        blocked = sum(
            dt for s, dt in weighted if s["active"] < cores and s["waiting"] == 0
        )
        print(
            f"wall time under {cores} active:   {starved:.1f} s "
            f"({100 * starved / wall:.0f}% of the build)"
        )
        print(
            f"  of which no unit was ready to start (the dependency graph forced it): "
            f"{blocked:.1f} s ({100 * blocked / wall:.0f}%)"
        )
        print(
            f"wall time at 1 or 0 active: {single:.1f} s ({100 * single / wall:.0f}%)"
        )

    last_start = max(u["start"] for u in units)
    print(f"tail after the last unit starts: {wall - last_start:.1f} s")

    # The longest chain the schedule realised: walk units in start order and, for each,
    # take the largest finish time among units that finished before it started. This is a
    # lower bound on the critical path — it charges a unit's wait to whichever earlier unit
    # finished latest, whether or not that unit was the dependency it waited on.
    chain: dict[int, float] = {}
    ordered = sorted(range(len(units)), key=lambda i: units[i]["start"])
    best_finish_before: list[tuple[float, int]] = []
    for i in ordered:
        start, duration = units[i]["start"], units[i]["duration"]
        predecessor = 0.0
        for finish, j in best_finish_before:
            if finish <= start + 1e-6:
                predecessor = max(predecessor, chain[j])
        chain[i] = predecessor + duration
        best_finish_before.append((start + duration, i))
    print(f"longest realised unit chain:     {max(chain.values()):.1f} s")

    print(f"\nslowest {TOP_N} units:")
    for u in sorted(units, key=lambda u: -u["duration"])[:TOP_N]:
        # cargo 1.98 writes the literal string "todo" into every unit's `mode` field, so
        # `target` is the only field that says which target of the package this unit is.
        # An empty `target` means the package's own library.
        target = (u.get("target") or "").strip() or "lib"
        print(f"  {u['duration']:7.1f} s  {u['name']} v{u['version']}  {target}")
    print()


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "timings")
    cores = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_RUNNER_CORES
    if cores < 1:
        raise SystemExit(f"the core count must be at least 1, got {cores}")
    reports = sorted(root.glob("*/timing.html"))
    if not reports:
        raise SystemExit(f"no timing.html under {root}")
    for report in reports:
        summarize(report, cores)


if __name__ == "__main__":
    main()
