#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Service degradation runner.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
    parser.add_argument("--action", required=True, choices=[
        "block_scoring",
        "unblock_scoring",
        "stop_http",
        "start_http",
        "stop_dns",
        "start_dns",
    ])
    parser.add_argument("--targets", default="all", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--scoring-ip", default="192.168.192.1", help="Scoring engine IP")
    args = parser.parse_args()

    service_script = SCRIPT_DIR / "service_degradation.py"
    cmd = [
        sys.executable,
        str(service_script),
        "--action",
        args.action,
        "--targets",
        args.targets,
        "--scoring-ip",
        args.scoring_ip,
    ]
    if args.teams:
        cmd.extend(["--teams", args.teams])
    elif args.teams_count:
        cmd.extend(["--teams-count", str(args.teams_count)])
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
