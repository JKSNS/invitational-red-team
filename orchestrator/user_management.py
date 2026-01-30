#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import build_team_numbers, ensure_ssh_keypair, prompt_team_count
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
    parser = argparse.ArgumentParser(description="User management actions across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--targets", default="all", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--action", required=True, choices=[
        "pkill_users",
        "create_themed_users",
        "remove_themed_users",
        "create_glados_admin",
        "weaken_root_password",
    ])
    parser.add_argument("--ssh-key", action="store_true", help="Use SSH key authentication for Linux targets")
    args = parser.parse_args()

    team_count = prompt_team_count(args.teams_count)
    teams = build_team_numbers(team_count)
    targets = parse_targets(args.targets)

    ssh_key = None
    if args.ssh_key:
        ssh_key = str(ensure_ssh_keypair())

    executor = RemoteExecutor(teams, ssh_key=ssh_key)
    attacks = AttackModules(executor)

    action_map = {
        "pkill_users": attacks.pkill_users,
        "create_themed_users": attacks.create_themed_users,
        "remove_themed_users": attacks.remove_themed_users,
        "create_glados_admin": attacks.create_glados_admin,
        "weaken_root_password": attacks.weaken_root_password,
    }
    results = action_map[args.action](targets)
    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
