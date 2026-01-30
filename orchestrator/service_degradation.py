#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import resolve_team_numbers
from lib.operations import AttackModules, RemoteExecutor, TARGETS


def parse_targets(choice: str) -> list:
    if choice == "all":
        return [t.hostname for t in TARGETS]
    if choice == "linux":
        return [t.hostname for t in TARGETS if t.os_type == "linux"]
    if choice == "windows":
        return [t.hostname for t in TARGETS if t.os_type == "windows"]
    return [t.strip() for t in choice.split(",") if t.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Service degradation actions across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
    parser.add_argument("--targets", default="all", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--action", required=True, choices=[
        "block_scoring",
        "unblock_scoring",
        "stop_http",
        "start_http",
        "stop_dns",
        "start_dns",
    ])
    parser.add_argument("--scoring-ip", default="192.168.192.1", help="Scoring engine IP")
    args = parser.parse_args()

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    print(f"[+] Target teams: {teams}")
    print(f"[+] Action: {args.action} | Targets: {targets}")

    executor = RemoteExecutor(teams)
    attacks = AttackModules(executor)

    if args.action in {"block_scoring", "unblock_scoring"}:
        action_fn = getattr(attacks, args.action)
        results = action_fn(targets, scoring_ip=args.scoring_ip)
    else:
        action_fn = getattr(attacks, args.action)
        results = action_fn(targets)

    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
