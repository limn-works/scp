#!/usr/bin/env python3
"""Wait until another job of this workflow run has uploaded a named artifact.

A consumer job that lists its producer in `needs:` starts only when the producer
ends, so every setup step the consumer runs before its download waits behind the
whole producer. kotlin-android-instrumented builds its own Android cdylib for 1 to
6 minutes before it reads the one file it takes from uniffi-cdylib-linux, the
generated `scp.kt`. This script lets such a consumer start with the run and block
only at the step that reads the artifact.

GitHub skips a job whose `needs:` holds a skipped job, and fails nothing on a
producer that failed, because the consumer never starts. A consumer that waits here
gets neither guarantee from the runner, so this script supplies both: it exits 0 only
when the artifact exists in this run, and exits 1 the moment the producer job has
completed without it, whatever the producer's conclusion (failure, cancelled,
skipped or success). A deadline bounds the wait, and an API error ends it.

Each poll lists the run's artifacts by name, then the latest attempt of each of the
run's jobs. It reads the artifact list again after it sees the producer completed,
because the upload can finish between the first read and the job's completion.

Inputs:
  --artifact NAME      the artifact name the producer's upload step uses.
  --producer NAME      the producer job's display name (its `name:` in the
                       workflow), which is what the jobs API returns.
  --timeout SECONDS    give up after this long.
  --interval SECONDS   time between polls (default 10).
  GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID, GH_TOKEN
                       set by the runner, except GH_TOKEN, which the step sets
                       from `github.token`. The job needs `actions: read`.

Exit 0: the artifact exists in this run.
Exit 1: the producer completed without uploading it, or the deadline passed.
Exit 2: the GitHub API refused a request or answered with something this script
        cannot read, or failed transiently MAX_CONSECUTIVE_ERRORS times in a row.
Exit 3: an input this script needs is absent or empty.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Transient failures (a 5xx answer, a timeout, a reset connection) tolerated in a
# row before the wait ends with exit 2. A 4xx answer ends it at once.
MAX_CONSECUTIVE_ERRORS = 5
REQUEST_TIMEOUT_SECONDS = 30
PAGE_SIZE = 100


class ApiRefused(Exception):
    """The API answered with a status or body this script must not retry."""


class ApiTransient(Exception):
    """The API failed in a way the next poll may not repeat."""


def get_json(url: str, token: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        if 500 <= error.code < 600:
            raise ApiTransient(f"GET {url}: HTTP {error.code}") from error
        raise ApiRefused(f"GET {url}: HTTP {error.code} {error.reason}") from error
    except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
        raise ApiTransient(f"GET {url}: {error}") from error
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as error:
        raise ApiRefused(f"GET {url}: body is not JSON ({error})") from error
    if not isinstance(parsed, dict):
        raise ApiRefused(f"GET {url}: body is not a JSON object")
    return parsed


def list_field(page: dict, field: str, url: str) -> list[dict]:
    items = page.get(field)
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise ApiRefused(f"GET {url}: no `{field}` list in the answer")
    return items


def artifact_present(base: str, token: str, name: str) -> bool:
    query = urllib.parse.urlencode({"name": name, "per_page": PAGE_SIZE})
    url = f"{base}/artifacts?{query}"
    artifacts = list_field(get_json(url, token), "artifacts", url)
    return any(a.get("name") == name and a.get("expired") is False for a in artifacts)


def producer_state(base: str, token: str, producer: str) -> tuple[str, str] | None:
    """Return (status, conclusion) of the producer's latest attempt, or None if unlisted."""
    page_number = 1
    while True:
        query = urllib.parse.urlencode(
            {"filter": "latest", "per_page": PAGE_SIZE, "page": page_number}
        )
        url = f"{base}/jobs?{query}"
        page = get_json(url, token)
        jobs = list_field(page, "jobs", url)
        matches = [job for job in jobs if job.get("name") == producer]
        if len(matches) > 1:
            raise ApiRefused(f"run lists {len(matches)} jobs named {producer!r}")
        if matches:
            job = matches[0]
            return str(job.get("status")), str(job.get("conclusion"))
        if len(jobs) < PAGE_SIZE:
            return None
        page_number += 1


def wait(
    base: str, token: str, artifact: str, producer: str, timeout: float, interval: float
) -> int:
    deadline = time.monotonic() + timeout
    errors = 0
    while True:
        try:
            if artifact_present(base, token, artifact):
                print(f"artifact {artifact} is in this run")
                return 0
            state = producer_state(base, token, producer)
            if state is not None and state[0] == "completed":
                if artifact_present(base, token, artifact):
                    print(f"artifact {artifact} is in this run")
                    return 0
                print(
                    f"::error::job {producer!r} completed with conclusion {state[1]} "
                    f"and uploaded no artifact {artifact}"
                )
                return 1
            errors = 0
            shown = "not created yet" if state is None else state[0]
            print(f"waiting for {artifact}: job {producer!r} is {shown}", flush=True)
        except ApiRefused as error:
            print(f"::error::{error}")
            return 2
        except ApiTransient as error:
            errors += 1
            print(f"::warning::{error} ({errors} in a row)", flush=True)
            if errors >= MAX_CONSECUTIVE_ERRORS:
                print(
                    f"::error::the GitHub API failed {errors} times in a row: {error}"
                )
                return 2
        if time.monotonic() + interval > deadline:
            print(
                f"::error::artifact {artifact} did not appear within {timeout:.0f} s "
                f"while job {producer!r} ran"
            )
            return 1
        time.sleep(interval)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--interval", type=float, default=10.0)
    args = parser.parse_args(argv)
    env = {
        key: os.environ.get(key, "")
        for key in ("GITHUB_API_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GH_TOKEN")
    }
    missing = [key for key, value in env.items() if not value]
    if not args.artifact or not args.producer:
        missing.append("--artifact/--producer")
    if args.timeout <= 0 or args.interval <= 0:
        missing.append("a positive --timeout and --interval")
    if missing:
        print(f"::error::missing input: {', '.join(missing)}")
        return 3
    base = (
        f"{env['GITHUB_API_URL'].rstrip('/')}/repos/{env['GITHUB_REPOSITORY']}"
        f"/actions/runs/{env['GITHUB_RUN_ID']}"
    )
    return wait(
        base, env["GH_TOKEN"], args.artifact, args.producer, args.timeout, args.interval
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
