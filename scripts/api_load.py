#!/usr/bin/env python3
"""The 9B-2 API latency test (ADR 0054). Standard library only.

    api_load.py --base http://127.0.0.1:8080 --tokens tokens.txt [--seconds 60]

One client per token (16 by default), each a different actor, so each has
its own read quota: 120 a minute (ADR 0038). Each client keeps under it
and cycles through what the NOC UI calls most: the incident list
(limit 100), an incident's detail and the mitigation list. The database
must already hold at least --min-incidents incidents. Results go to --out
as JSON and Markdown; the exit status is 1 when a p99 is above 250 ms or
any response is an error.
"""

import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request

MAX_P99_SECONDS = 0.25
# Two a second is the quota; stay just under it.
REQUEST_INTERVAL = 0.55


def get(base, token, path):
    request = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        body, status = error.read(), error.code
    except OSError:
        body, status = b"", 0
    return status, time.perf_counter() - started, body


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def client(base, token, ids, deadline, results, lock):
    endpoints = [
        ("incident list", lambda: "/api/v1/incidents?limit=100"),
        ("incident detail", lambda: "/api/v1/incidents/" + random.choice(ids)),
        ("mitigation list", lambda: "/api/v1/mitigations?limit=200&live=false"),
    ]
    turn = random.randrange(len(endpoints))
    while time.monotonic() < deadline:
        name, path = endpoints[turn % len(endpoints)]
        turn += 1
        began = time.monotonic()
        status, seconds, _ = get(base, token, path())
        with lock:
            results.setdefault(name, []).append((status, seconds))
        time.sleep(max(0.0, REQUEST_INTERVAL - (time.monotonic() - began)))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", required=True)
    parser.add_argument("--tokens", required=True, help="one token per line, one client each")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--min-incidents", type=int, default=10_000)
    parser.add_argument("--out", default="api-results")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    with open(args.tokens) as tokens_file:
        tokens = [line.strip() for line in tokens_file if line.strip()]

    status, _, body = get(args.base, tokens[0], "/api/v1/incidents?limit=100&include_total=true")
    if status != 200:
        sys.exit(f"the incident list answered {status}")
    page = json.loads(body)
    total = page.get("total") or 0
    ids = [item["incident_id"] for item in page["items"]]
    if total < args.min_incidents or not ids:
        sys.exit(f"the database holds {total} incidents; at least {args.min_incidents} are needed")
    time.sleep(1)

    results, lock = {}, threading.Lock()
    deadline = time.monotonic() + args.seconds
    threads = [
        threading.Thread(target=client, args=(args.base, token, ids, deadline, results, lock))
        for token in tokens
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    rows, reasons = [], []
    for name, samples in sorted(results.items()):
        latencies = [seconds for status, seconds in samples if 200 <= status < 300]
        errors = sum(1 for status, _ in samples if not 200 <= status < 300)
        p99 = percentile(latencies, 0.99)
        rows.append({
            "endpoint": name,
            "requests": len(samples),
            "errors": errors,
            "p50_seconds": percentile(latencies, 0.50),
            "p95_seconds": percentile(latencies, 0.95),
            "p99_seconds": p99,
        })
        if errors:
            codes = sorted({status for status, _ in samples if not 200 <= status < 300})
            reasons.append(f"{name}: {errors} error responses ({codes})")
        if p99 is None or p99 > MAX_P99_SECONDS:
            reasons.append(f"{name}: p99 {p99} s above {MAX_P99_SECONDS} s")
    result = {
        "incidents": total,
        "clients": len(tokens),
        "seconds": args.seconds,
        "endpoints": rows,
        "verdict": {"pass": not reasons, "reasons": reasons},
    }

    ms = lambda value: "—" if value is None else f"{1000 * value:.1f} ms"
    lines = [
        "## WetechiNetMon API latency (ADR 0054)",
        "",
        f"**{'PASS' if not reasons else 'FAIL'}**" + ("" if not reasons else ": " + "; ".join(reasons)),
        "",
        f"{total:,} incidents in the database, {len(tokens)} clients (one actor each), {args.seconds} s.",
        "",
        "| Endpoint | Requests | Errors | p50 | p95 | p99 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['endpoint']} | {row['requests']:,} | {row['errors']} | {ms(row['p50_seconds'])} | "
            f"{ms(row['p95_seconds'])} | {ms(row['p99_seconds'])} |"
        )
    report = "\n".join(lines) + "\n"
    with open(os.path.join(args.out, "api.json"), "w") as out:
        json.dump(result, out, indent=2)
    with open(os.path.join(args.out, "api.md"), "w") as out:
        out.write(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            out.write(report)
    print(report)
    sys.exit(0 if not reasons else 1)


if __name__ == "__main__":
    main()
