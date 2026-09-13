#!/usr/bin/env python3
"""Print what a `cargo build --timings=html` report says, as text a log can carry.

`.github/workflows/compile-timings.yml` runs `cargo build --timings` for each
cargo invocation `ci.yml`'s `rust-test` job runs, then calls this script on the directory
holding the reports. The HTML report embeds two JavaScript arrays, and this script reads
both out of it:

  UNIT_DATA         one entry per compiled unit, carrying its start second, its duration,
                    and the seconds the unit spent producing rmeta before its dependents
                    could start.
  CONCURRENCY_DATA  one sample per 100 ms, carrying how many units were running, how many
                    were ready but waiting for a core, and how many were blocked on a
                    dependency.

From those two arrays this script reports the wall time, the summed unit time and the
floor that a four-core runner imposes on it, the twenty slowest units, how much of the
wall time ran fewer units than the machine has cores, and the longest chain of units that
the schedule actually realised. It reads the reports and writes text; it
compiles nothing and it fails no build.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# The number of vCPUs a GitHub-hosted `ubuntu-latest` runner gives a job. A sample whose
# `active` count falls below this number means cargo could not fill the machine.
RUNNER_CORES = 4
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


def units_from_json(report: Path) -> list[dict]:
    """Read unit durations out of cargo's `--timings=json` stream.

    The stream carries a duration per unit and no start second, so a caller gets the
    slowest-unit ranking from it and gets no concurrency or wall-time figure.
    """
    path = report.parent / "timing.json"
    if not path.exists():
        return []
    units = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("reason") != "timing-info":
            continue
        name, version = record["package_id"].split()[:2]
        units.append(
            {
                "name": name.rsplit("#", 1)[-1],
                "version": version.lstrip("v"),
                "mode": record.get("mode", ""),
                "duration": record["duration"],
                "start": 0.0,
                "target": ",".join(record.get("target", {}).get("kind", [])),
            }
        )
    return units


def summarize(report: Path) -> None:
    html = report.read_text(encoding="utf-8")
    print(f"=== {report.parent.name} ===")
    units = extract_array(html, "UNIT_DATA")
    concurrency = extract_array(html, "CONCURRENCY_DATA")
    if not units:
        units = units_from_json(report)
    if not units:
        print("  no unit data in either the HTML or the JSON report\n")
        return

    wall = max(u["start"] + u["duration"] for u in units)
    cpu_seconds = sum(u["duration"] for u in units)

    print(f"units compiled:            {len(units)}")
    print(f"wall time:                 {wall:.1f} s")
    print(f"summed unit time:          {cpu_seconds:.1f} s")
    print(f"mean parallelism:          {cpu_seconds / wall:.2f} units")
    # A 4-vCPU runner cannot finish sooner than the summed unit time divided by 4, whatever
    # the dependency graph allows. Comparing the wall time against that floor says whether
    # the build is short of work to run or short of cores to run it on.
    print(
        f"{RUNNER_CORES}-core floor (summed/{RUNNER_CORES}): {cpu_seconds / RUNNER_CORES:.1f} s"
        f"  — wall is {100 * wall / (cpu_seconds / RUNNER_CORES) - 100:+.0f}% against it"
    )

    if concurrency:
        span = concurrency[-1]["t"] / max(len(concurrency) - 1, 1)
        starved = sum(span for s in concurrency if s["active"] < RUNNER_CORES)
        single = sum(span for s in concurrency if s["active"] <= 1)
        blocked = sum(span for s in concurrency if s["active"] < RUNNER_CORES and s["waiting"] == 0)
        print(
            f"wall time under {RUNNER_CORES} active:   {starved:.1f} s "
            f"({100 * starved / wall:.0f}% of the build)"
        )
        print(
            f"  of which no unit was ready to start (the dependency graph forced it): "
            f"{blocked:.1f} s ({100 * blocked / wall:.0f}%)"
        )
        print(f"wall time at 1 or 0 active: {single:.1f} s ({100 * single / wall:.0f}%)")

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
    reports = sorted(root.glob("*/timing.html"))
    if not reports:
        raise SystemExit(f"no timing.html under {root}")
    for report in reports:
        summarize(report)


if __name__ == "__main__":
    main()
