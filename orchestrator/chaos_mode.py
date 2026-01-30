#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import resolve_team_numbers
from lib.operations import ChaosMode, RemoteExecutor, TARGETS


def parse_targets(choice: str) -> list:
    if choice == "all":
        return [t.hostname for t in TARGETS]
    if choice == "linux":
        return [t.hostname for t in TARGETS if t.os_type == "linux"]
    if choice == "windows":
        return [t.hostname for t in TARGETS if t.os_type == "windows"]
    return [t.strip() for t in choice.split(",") if t.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Chaos mode actions across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
    parser.add_argument("--targets", default="linux", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--action", required=True, choices=[
        "deploy_nyan_cat",
        "deploy_matrix_rain",
        "deploy_desktop_goose",
        "remove_chaos",
    ])
    args = parser.parse_args()

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    print(f"[+] Target teams: {teams}")
    print(f"[+] Action: {args.action} | Targets: {targets}")

    executor = RemoteExecutor(teams)
    chaos = ChaosMode(executor)

    action_map = {
        "deploy_nyan_cat": chaos.deploy_nyan_cat,
        "deploy_matrix_rain": chaos.deploy_matrix_rain,
        "deploy_desktop_goose": chaos.deploy_desktop_goose_effect,
        "remove_chaos": chaos.remove_chaos,
    }
    results = action_map[args.action](targets)
    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
