"""Experiment only: write one bash script per compile step of one cache-warm.yml job.

Clippy commands get the readers' `-- -D warnings`, so the units they cache carry the
readers' CLIPPY_ARGS. A failing command does not stop the script.
"""

import os
import sys

import yaml

wf = yaml.safe_load(open(sys.argv[2]))
job = wf["jobs"][sys.argv[1]]
outdir = sys.argv[3]
os.makedirs(outdir, exist_ok=True)
past_cache = False
n = 0
for step in job["steps"]:
    if step.get("id") == "cache":
        past_cache = True
        continue
    if not past_cache or "run" not in step:
        continue
    lines = ["set +e"]
    if step.get("working-directory"):
        lines.append(f"cd {step['working-directory']}")
    for k, v in step.get("env", {}).items():
        lines.append(f"export {k}='{v}'")
    for line in step["run"].splitlines():
        s = line.strip()
        if s.startswith("cargo clippy") and " -- " not in s:
            line = line + " -- -D warnings"
        lines.append(line)
    n += 1
    with open(os.path.join(outdir, f"{n:02d}.sh"), "w") as f:
        f.write("\n".join(lines) + "\n")
