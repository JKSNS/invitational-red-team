#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import ensure_ssh_keypair, resolve_team_numbers
from lib.operations import AttackModules, RemoteExecutor, TARGETS


def parse_targets(choice: str) -> list:
    if choice == "all":
        return [t.hostname for t in TARGETS]
    if choice == "linux":
        return [t.hostname for t in TARGETS if t.os_type == "linux"]
    if choice == "windows":
        return [t.hostname for t in TARGETS if t.os_type == "windows"]
    return [t.strip() for t in choice.split(",") if t.strip()]


def report_failures(results: dict) -> None:
    failures = results.get("failed", [])
    if not failures:
        return
    print(f"[!] Failure details ({len(failures)}):")
    for failure in failures:
        output = (failure.get("output") or "").strip()
        method = failure.get("method", "unknown")
        print(
            f"  - Team {failure.get('team')} | {failure.get('target')} "
            f"({failure.get('ip')}) [{method}]"
        )
        if output:
            for line in output.splitlines():
                print(f"      {line}")


def main() -> int:
    parser = argparse.ArgumentParser(description="User management actions across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
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

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    print(f"[+] Target teams: {teams}")
    print(f"[+] Action: {args.action} | Targets: {targets}")

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
    report_failures(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
