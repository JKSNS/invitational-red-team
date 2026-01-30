#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))

from common import build_team_numbers, prompt_team_count
from operations import ChaosMode, RemoteExecutor, TARGETS


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
    parser.add_argument("--targets", default="linux", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--action", required=True, choices=[
        "deploy_nyan_cat",
        "deploy_matrix_rain",
        "deploy_desktop_goose",
        "remove_chaos",
    ])
    args = parser.parse_args()

    team_count = prompt_team_count(args.teams_count)
    teams = build_team_numbers(team_count)
    targets = parse_targets(args.targets)

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
