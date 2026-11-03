"""Experiment only: print a bash script running every compile step of one cache-warm.yml job.

Clippy commands get the readers' `-- -D warnings`, so the units they cache carry the
readers' CLIPPY_ARGS. The script does not stop on a failing command.
"""

import sys

import yaml

wf = yaml.safe_load(open(sys.argv[2]))
job = wf["jobs"][sys.argv[1]]
out = ["set +e"]
past_cache = False
for step in job["steps"]:
    if step.get("id") == "cache":
        past_cache = True
        continue
    if not past_cache or "run" not in step:
        continue
    wd = step.get("working-directory")
    envs = step.get("env", {})
    out.append(f"echo '::group::{step.get('name', 'step')}'")
    out.append("(")
    if wd:
        out.append(f"cd {wd}")
    for k, v in envs.items():
        out.append(f"export {k}='{v}'")
    for line in step["run"].splitlines():
        s = line.strip()
        if s.startswith("cargo clippy") and " -- " not in s:
            line = line + " -- -D warnings"
        out.append(line)
    out.append(")")
    out.append("echo '::endgroup::'")
print("\n".join(out))
