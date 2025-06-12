import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime

FAILED_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?login attempt \[.*?/.*?\] failed"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?login attempt \[(?P<user>[^/]+)/(?P<pw>[^\]]+)\] succeeded"
)

FINGERPRINT_PATTERN = re.compile(
    r"\[HoneyPotSSHTransport,\d+,(?P<ip>\d+\.\d+\.\d+\.\d+)\].*?SSH client hassh fingerprint: (?P<fp>[0-9a-f:]{32})"
)

def _print_counter(counter: Counter, head1: str, head2: str, sort_keys=False):
    width = max((len(str(k)) for k in counter), default=len(head1))
    print(f"{head1:<{width}} {head2:>8}")
    print("-" * (width + 9))
    items = sorted(counter.items()) if sort_keys else counter.most_common()
    for key, cnt in items:
        print(f"{key:<{width}} {cnt:>8}")

def analyze_failed_logins(path: str, min_count: int):
    counter = Counter()
    with open(path, encoding="utf-8") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                counter[ip] += 1
    filtered = Counter({ip: count for ip, count in counter.items() if count >= min_count})
    _print_counter(filtered, "IP Address", "Failed Logins")

def analyze_successful_creds(path: str):
    creds = defaultdict(set)
    with open(path, encoding="utf-8") as f:
        for line in f:
            match = SUCCESS_LOGIN_PATTERN.search(line)
            if match:
                user = match.group("user")
                pw = match.group("pw")
                ip = match.group("ip")
                creds[(user, pw)].add(ip)

    sorted_creds = sorted(creds.items(), key=lambda x: len(x[1]), reverse=True)
    print(f"{'Username':<20} {'Password':<20} {'IP Count'}")
    print("-" * 55)
    for (user, pw), ips in sorted_creds:
        print(f"{user:<20} {pw:<20} {len(ips)}")

def identify_bots(path: str, min_ips: int):
    fp_map = defaultdict(set)
    with open(path, encoding="utf-8") as f:
        for line in f:
            match = FINGERPRINT_PATTERN.search(line)
            if match:
                fp_map[match.group("fp")].add(match.group("ip"))
    bots = {fp: ips for fp, ips in fp_map.items() if len(ips) >= min_ips}
    print(f"{'Fingerprint':<47} {'IPs':>6}")
    print("-" * 53)
    for fp, ips in sorted(bots.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{fp:<47} {len(ips):>6}")

def main():
    parser = argparse.ArgumentParser(description="Cowrie log analyzer")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--task", required=True, choices=["failed-logins", "successful-creds", "identify-bots"])
    parser.add_argument("--min-count", type=int, default=1)
    parser.add_argument("--min-ips", type=int, default=3)
    args = parser.parse_args()

    if args.task == "failed-logins":
        analyze_failed_logins(args.logfile, args.min_count)
    elif args.task == "successful-creds":
        analyze_successful_creds(args.logfile)
    elif args.task == "identify-bots":
        identify_bots(args.logfile, args.min_ips)

if __name__ == "__main__":
    main()
