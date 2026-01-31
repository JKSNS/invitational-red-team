#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import resolve_team_numbers
from lib.operations import PersistenceDeployer, RemoteExecutor, TARGETS


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


def report_skips(results: dict) -> None:
    skipped = results.get("skipped", [])
    if not skipped:
        return
    print(f"[!] Skipped targets ({len(skipped)}):")
    for skip in skipped:
        output = (skip.get("output") or "").strip()
        method = skip.get("method", "unknown")
        print(
            f"  - Team {skip.get('team')} | {skip.get('target')} "
            f"({skip.get('ip')}) [{method}]"
        )
        if output:
            for line in output.splitlines():
                print(f"      {line}")


def report_successes(results: dict) -> None:
    successes = results.get("success", [])
    if not successes:
        return
    print(f"[+] Success details ({len(successes)}):")
    for success in successes:
        output = (success.get("output") or "").strip()
        method = success.get("method", "unknown")
        print(
            f"  - Team {success.get('team')} | {success.get('target')} "
            f"({success.get('ip')}) [{method}]"
        )
        if output:
            for line in output.splitlines():
                print(f"      {line}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy persistence across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
    parser.add_argument("--targets", default="all", help="all, linux, windows, or comma-separated hostnames")
    args = parser.parse_args()

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    print(f"[+] Target teams: {teams}")
    print(f"[+] Action: deploy_persistence | Targets: {targets}")

    executor = RemoteExecutor(teams)
    deployer = PersistenceDeployer(executor)
    results = deployer.deploy(targets)

    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    report_successes(results)
    report_failures(results)
    report_skips(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
