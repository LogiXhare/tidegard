#!/usr/bin/env python3
"""The 9B load and soak tests (ADR 0054). Linux only; standard library only.

    load_test.py load --collector BIN --replay BIN [--rates 25000,50000,...]
    load_test.py soak --collector BIN --replay BIN --hours 5 --rate 50000

The collector is started here, with the environment the caller exported
(its database and ClickHouse settings), and fed by flow-replay's rate mode
on loopback. Loss is 1 - parsed / sent: it counts every record lost,
the kernel's socket buffer included. Results go to --out as JSON and
Markdown; the exit status is 1 when ADR 0054's pass criteria are missed.
"""

import argparse
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import time
import urllib.request

METRICS = "http://127.0.0.1:9090"
FLOWS = "127.0.0.1:2055"
PARSED = "tidegard_collector_parsed_flow_records_total"
QUEUE_DEPTH = "tidegard_collector_queue_depth"
LATENCY = "tidegard_collector_aggregation_latency_seconds"
# Evidence that records went through the whole pipeline, not only the parser.
INCOMING = 'tidegard_collector_classified_flows_by_direction_total{direction="incoming"}'
ACTIVE_HOSTS = "tidegard_collector_active_hosts"
CLICKHOUSE_ROWS = "tidegard_collector_clickhouse_rows_written_total"

# ADR 0054, written before the first run.
PASS_RATE = 100_000
MAX_LOSS = 0.001
MAX_P99_SECONDS = 1.0
MAX_PEAK_RSS_BYTES = 1 << 30
SOAK_MAX_RSS_GROWTH = 0.10


def scrape():
    """Every sample of the collector's /metrics, by name and labels."""
    with urllib.request.urlopen(METRICS + "/metrics", timeout=5) as response:
        text = response.read().decode()
    samples = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.rpartition(" ")
        samples[name] = float(value)
    return samples


def counter(samples, name):
    return samples.get(name, 0.0)


def buckets(samples, name):
    """A histogram's cumulative buckets, as (upper bound, count)."""
    out = []
    for key, value in samples.items():
        match = re.fullmatch(name + r'_bucket\{le="([^"]+)"\}', key)
        if match:
            bound = float("inf") if match.group(1) == "+Inf" else float(match.group(1))
            out.append((bound, value))
    return sorted(out)


def quantile(before, after, name, q):
    """The q-quantile of a histogram's observations between two scrapes,
    as the upper bound of the bucket it falls in; None without data."""
    first = dict(buckets(before, name))
    deltas = [(bound, count - first.get(bound, 0.0)) for bound, count in buckets(after, name)]
    if not deltas or deltas[-1][1] <= 0:
        return None
    total = deltas[-1][1]
    for bound, count in deltas:
        if count >= q * total:
            return bound
    return deltas[-1][0]


def proc_status(pid):
    """Resident (VmRSS) and peak resident (VmHWM) memory, in bytes."""
    values = {}
    with open(f"/proc/{pid}/status") as status:
        for line in status:
            key, _, rest = line.partition(":")
            if key in ("VmRSS", "VmHWM"):
                values[key] = int(rest.split()[0]) * 1024
    return values


def cpu_seconds(pid):
    with open(f"/proc/{pid}/stat") as stat:
        fields = stat.read().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return (int(fields[11]) + int(fields[12])) / ticks


def machine():
    cpu = "unknown"
    try:
        with open("/proc/cpuinfo") as info:
            for line in info:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    with open("/proc/meminfo") as info:
        memory = int(info.readline().split()[1]) * 1024
    return {
        "runner": os.environ.get("ImageOS", "") + " " + os.environ.get("ImageVersion", ""),
        "kernel": platform.release(),
        "cpu": cpu,
        "cores": os.cpu_count(),
        "memory_bytes": memory,
        "run": os.environ.get("GITHUB_SERVER_URL", "")
        + "/"
        + os.environ.get("GITHUB_REPOSITORY", "")
        + "/actions/runs/"
        + os.environ.get("GITHUB_RUN_ID", ""),
    }


def start_collector(binary, log_path):
    env = dict(os.environ)
    env.setdefault("TIDEGARD_COLLECTOR_BIND", FLOWS)
    env.setdefault("TIDEGARD_COLLECTOR_METRICS_BIND", "127.0.0.1:9090")
    log = open(log_path, "w")
    process = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            with urllib.request.urlopen(METRICS + "/readyz", timeout=2) as response:
                if response.status == 200:
                    return process
        except OSError:
            pass
        if process.poll() is not None:
            break
        time.sleep(0.5)
    process.kill()
    sys.exit(f"the collector did not become ready; see {log_path}")


def settle(previous):
    """Waits until the parsed counter stops moving; returns the last scrape."""
    while True:
        time.sleep(2)
        samples = scrape()
        if counter(samples, PARSED) == counter(previous, PARSED):
            return samples
        previous = samples


def send(replay, rate, seconds, hosts):
    output = subprocess.run(
        [replay, FLOWS, "--rate", str(rate), "--duration-secs", str(seconds), "--hosts", str(hosts)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    match = re.search(r"load: sent (\d+) records", output)
    if not match:
        sys.exit("flow-replay did not report what it sent:\n" + output)
    return int(match.group(1))


def errors_in(log_path):
    with open(log_path, errors="replace") as log:
        return [line.strip() for line in log if '"level":"ERROR"' in line or "panicked" in line]


def load(args):
    collector = start_collector(args.collector, os.path.join(args.out, "collector.log"))
    steps = []
    try:
        for rate in args.rates:
            before = scrape()
            cpu_before = cpu_seconds(collector.pid)
            sent = send(args.replay, rate, args.step_seconds, args.hosts)
            after = settle(before)
            parsed = counter(after, PARSED) - counter(before, PARSED)
            memory = proc_status(collector.pid)
            p99 = quantile(before, after, LATENCY, 0.99)
            step = {
                "rate": rate,
                "seconds": args.step_seconds,
                "sent": sent,
                "parsed": int(parsed),
                "loss": max(0.0, 1 - parsed / sent) if sent else None,
                "classified_incoming": int(counter(after, INCOMING) - counter(before, INCOMING)),
                "active_hosts": int(counter(after, ACTIVE_HOSTS)),
                "clickhouse_rows": int(counter(after, CLICKHOUSE_ROWS) - counter(before, CLICKHOUSE_ROWS)),
                "latency_p99_seconds": p99,
                "rss_bytes": memory.get("VmRSS"),
                "peak_rss_bytes": memory.get("VmHWM"),
                "cpu_cores": (cpu_seconds(collector.pid) - cpu_before) / args.step_seconds,
                "alive": collector.poll() is None,
            }
            steps.append(step)
            print(json.dumps(step), flush=True)
            if not step["alive"]:
                break
    finally:
        collector.send_signal(signal.SIGTERM)
        collector.wait(timeout=30)
    errors = errors_in(os.path.join(args.out, "collector.log"))
    verdict = judge_load(steps, errors)
    return {"kind": "load", "machine": machine(), "steps": steps, "errors": errors[:20], "verdict": verdict}


def judge_load(steps, errors):
    target = next((s for s in steps if s["rate"] == PASS_RATE), None)
    if target is None:
        return {"pass": False, "reasons": [f"no {PASS_RATE} records/s step was run"]}
    reasons = []
    if target["loss"] is None or target["loss"] > MAX_LOSS:
        reasons.append(f"loss {target['loss']} above {MAX_LOSS}")
    if target["latency_p99_seconds"] is None or target["latency_p99_seconds"] > MAX_P99_SECONDS:
        reasons.append(f"aggregation latency p99 {target['latency_p99_seconds']} s above {MAX_P99_SECONDS} s")
    if (target["peak_rss_bytes"] or 0) > MAX_PEAK_RSS_BYTES:
        reasons.append(f"peak resident memory {target['peak_rss_bytes']} above 1 GiB")
    if not all(s["alive"] for s in steps):
        reasons.append("the collector stopped")
    if errors:
        reasons.append(f"{len(errors)} error lines in the collector's log")
    return {"pass": not reasons, "reasons": reasons}


def soak(args):
    collector = start_collector(args.collector, os.path.join(args.out, "collector.log"))
    capacity = int(os.environ.get("TIDEGARD_COLLECTOR_QUEUE_CAPACITY", "10000"))
    seconds = int(args.hours * 3600)
    start = scrape()
    replay = subprocess.Popen(
        [args.replay, FLOWS, "--rate", str(args.rate), "--duration-secs", str(seconds), "--hosts", str(args.hosts)],
        stdout=subprocess.PIPE,
        text=True,
    )
    samples = []
    began = time.time()
    try:
        while replay.poll() is None:
            time.sleep(args.sample_seconds)
            if collector.poll() is not None:
                break
            now = scrape()
            memory = proc_status(collector.pid)
            sample = {
                "elapsed_seconds": round(time.time() - began),
                "parsed": int(counter(now, PARSED) - counter(start, PARSED)),
                "queue_depth": int(counter(now, QUEUE_DEPTH)),
                "rss_bytes": memory.get("VmRSS"),
                "peak_rss_bytes": memory.get("VmHWM"),
            }
            samples.append(sample)
            print(json.dumps(sample), flush=True)
        output = replay.communicate()[0]
        match = re.search(r"load: sent (\d+) records", output or "")
        sent = int(match.group(1)) if match else 0
        end = settle(scrape()) if collector.poll() is None else {}
    finally:
        if replay.poll() is None:
            replay.kill()
        alive = collector.poll() is None
        collector.send_signal(signal.SIGTERM)
        collector.wait(timeout=30)
    parsed = counter(end, PARSED) - counter(start, PARSED)
    errors = errors_in(os.path.join(args.out, "collector.log"))
    summary = {
        "rate": args.rate,
        "hours": args.hours,
        "sent": sent,
        "parsed": int(parsed),
        "loss": max(0.0, 1 - parsed / sent) if sent else None,
        "queue_capacity": capacity,
        "max_queue_depth": max((s["queue_depth"] for s in samples), default=0),
        "alive": alive,
    }
    verdict = judge_soak(summary, samples, errors)
    return {"kind": "soak", "machine": machine(), "summary": summary, "samples": samples,
            "errors": errors[:20], "verdict": verdict}


def rss_in_hour(samples, hour):
    # A sample closes its interval, so the one taken at 3,600 s is the
    # first hour's last, not the second hour's first.
    window = [s["rss_bytes"] for s in samples if hour * 3600 < s["elapsed_seconds"] <= (hour + 1) * 3600]
    return sum(window) / len(window) if window else None


def judge_soak(summary, samples, errors):
    reasons = []
    if summary["loss"] is None or summary["loss"] > MAX_LOSS:
        reasons.append(f"loss {summary['loss']} above {MAX_LOSS}")
    hours = int(summary["hours"])
    first, last = rss_in_hour(samples, 0), rss_in_hour(samples, max(hours - 1, 0))
    if first is None or last is None:
        reasons.append("not enough memory samples")
    elif last > first * (1 + SOAK_MAX_RSS_GROWTH):
        reasons.append(f"resident memory grew {100 * (last / first - 1):.1f}% from the first hour to the last")
    if summary["max_queue_depth"] >= summary["queue_capacity"]:
        reasons.append("the queue reached its capacity")
    if not summary["alive"]:
        reasons.append("the collector stopped")
    if errors:
        reasons.append(f"{len(errors)} error lines in the collector's log")
    return {"pass": not reasons, "reasons": reasons}


def mib(value):
    return "—" if value is None else f"{value / (1 << 20):.0f} MiB"


def markdown(result):
    m = result["machine"]
    lines = [
        f"## Tidegard {result['kind']} test (ADR 0054)",
        "",
        f"**{'PASS' if result['verdict']['pass'] else 'FAIL'}**"
        + ("" if result["verdict"]["pass"] else ": " + "; ".join(result["verdict"]["reasons"])),
        "",
        f"Machine: {m['runner'].strip() or 'unknown runner'}, {m['cpu']}, {m['cores']} cores, "
        f"{m['memory_bytes'] / (1 << 30):.1f} GiB, kernel {m['kernel']}. Run: {m['run']}",
        "",
    ]
    if result["kind"] == "load":
        lines += [
            "| Records/s | Sent | Parsed | Loss | Incoming | Hosts | ClickHouse rows | Latency p99 | RSS | Peak RSS | CPU cores |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for s in result["steps"]:
            loss = "—" if s["loss"] is None else f"{100 * s['loss']:.3f}%"
            p99 = "—" if s["latency_p99_seconds"] is None else f"≤ {s['latency_p99_seconds']} s"
            lines.append(
                f"| {s['rate']:,} | {s['sent']:,} | {s['parsed']:,} | {loss} | {s['classified_incoming']:,} | "
                f"{s['active_hosts']:,} | {s['clickhouse_rows']:,} | {p99} | "
                f"{mib(s['rss_bytes'])} | {mib(s['peak_rss_bytes'])} | {s['cpu_cores']:.2f} |"
            )
    else:
        s = result["summary"]
        loss = "—" if s["loss"] is None else f"{100 * s['loss']:.3f}%"
        lines += [
            f"{s['hours']} h at {s['rate']:,} records/s: sent {s['sent']:,}, parsed {s['parsed']:,}, "
            f"loss {loss}; deepest queue {s['max_queue_depth']:,} of {s['queue_capacity']:,}.",
            "",
            "| Hour | Mean RSS |",
            "|---:|---:|",
        ]
        for hour in range(math.ceil(s["hours"])):
            mean = rss_in_hour(result["samples"], hour)
            if mean is not None:
                lines.append(f"| {hour + 1} | {mib(mean)} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kind", choices=["load", "soak"])
    parser.add_argument("--collector", required=True)
    parser.add_argument("--replay", required=True)
    parser.add_argument("--out", default="load-results")
    parser.add_argument("--hosts", type=int, default=1000)
    parser.add_argument("--rates", default="25000,50000,100000,150000,200000")
    parser.add_argument("--step-seconds", type=int, default=60)
    parser.add_argument("--rate", type=int, default=50_000)
    parser.add_argument("--hours", type=float, default=5)
    parser.add_argument("--sample-seconds", type=int, default=300)
    args = parser.parse_args()
    args.rates = [int(rate) for rate in args.rates.split(",")]
    os.makedirs(args.out, exist_ok=True)

    result = load(args) if args.kind == "load" else soak(args)
    with open(os.path.join(args.out, f"{args.kind}.json"), "w") as out:
        json.dump(result, out, indent=2)
    report = markdown(result)
    with open(os.path.join(args.out, f"{args.kind}.md"), "w") as out:
        out.write(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            out.write(report)
    print(report)
    sys.exit(0 if result["verdict"]["pass"] else 1)


if __name__ == "__main__":
    main()
