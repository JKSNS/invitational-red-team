#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT_DIR / "core"))

from common import build_team_numbers, prompt_team_count
from operations import PersistenceDeployer, RemoteExecutor, TARGETS


def parse_targets(choice: str) -> list:
    if choice == "all":
        return [t.hostname for t in TARGETS]
    if choice == "linux":
        return [t.hostname for t in TARGETS if t.os_type == "linux"]
    if choice == "windows":
        return [t.hostname for t in TARGETS if t.os_type == "windows"]
    return [t.strip() for t in choice.split(",") if t.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy persistence across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--targets", default="all", help="all, linux, windows, or comma-separated hostnames")
    args = parser.parse_args()

    team_count = prompt_team_count(args.teams_count)
    teams = build_team_numbers(team_count)
    targets = parse_targets(args.targets)

    executor = RemoteExecutor(teams)
    deployer = PersistenceDeployer(executor)
    results = deployer.deploy(targets)

    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
