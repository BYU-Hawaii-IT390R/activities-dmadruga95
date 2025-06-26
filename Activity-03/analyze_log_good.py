#!/usr/bin/env python3
import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

# ── Regex patterns ──────────────────────────────────────────────────────────
FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[.*?/.*?\] failed"
)

NEW_CONN_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z "
    r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?"
    r"SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

# ── Helper to print counters neatly ─────────────────────────────────────────
def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

# ── Task 1 ──────────────────────────────────────────────────────────────────
def failed_logins(path: str, min_count: int):
    hits = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FAILED_LOGIN_PATTERN.search(line)
            if m:
                hits[m.group("ip")] += 1
    # Apply threshold filter
    hits = Counter({ip: c for ip, c in hits.items() if c >= min_count})
    print(f"Failed login attempts (≥ {min_count})")
    _print_counter(hits, "IP Address", "Count")

# ── Task 2 ──────────────────────────────────────────────────────────────────
def connections(path: str):
    per_min = Counter()
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = NEW_CONN_PATTERN.search(line)
            if m:
                dt = datetime.strptime(m.group("ts")[:19], "%Y-%m-%dT%H:%M:%S")
                per_min[dt.strftime("%Y-%m-%d %H:%M")] += 1
    print("Connections per minute")
    _print_counter(per_min, "Timestamp", "Count", sort_keys=True)

# ── Task 3 ──────────────────────────────────────────────────────────────────
def successful_creds(path: str):
    creds = defaultdict(set)
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = SUCCESS_LOGIN_PATTERN.search(line)
            if m:
                creds[(m.group("user"), m.group("pw"))].add(m.group("ip"))
    print("Successful credential pairs")
    print(f"{'Username':<15} {'Password':<15} {'IPs':>6}")
    print("-" * 38)
    for (u, p), ips in sorted(creds.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{u:<15} {p:<15} {len(ips):>6}")

# ── Task 4 ──────────────────────────────────────────────────────────────────
def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)           # fingerprint → {ip,…}
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            m = FINGERPRINT_PATTERN.search(line)
            if m:
                fp_map[m.group("fp")].add(m.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"Fingerprints seen from ≥ {min_ips} unique IPs")
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")

# ── CLI ─────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="Cowrie log analyzer")
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--task",
                   required=True,
                   choices=["failed-logins", "connections",
                            "successful-creds", "identify-bots"],
                   help="Which analysis to run")
    p.add_argument("--min-count", type=int, default=1,
                   help="Min events to report (failed-logins)")
    p.add_argument("--min-ips", type=int, default=3,
                   help="Min IPs per fingerprint (identify-bots)")
    args = p.parse_args()

    if args.task == "failed-logins":
        failed_logins(args.logfile, args.min_count)
    elif args.task == "connections":
        connections(args.logfile)
    elif args.task == "successful-creds":
        successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)

if __name__ == "__main__":

    main()
