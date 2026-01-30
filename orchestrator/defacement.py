#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import resolve_team_numbers
from lib.operations import RemoteExecutor, TARGETS, WebsiteDefacement


def parse_targets(choice: str) -> list:
    if choice == "all":
        return [t.hostname for t in TARGETS]
    if choice == "linux":
        return [t.hostname for t in TARGETS if t.os_type == "linux"]
    if choice == "windows":
        return [t.hostname for t in TARGETS if t.os_type == "windows"]
    return [t.strip() for t in choice.split(",") if t.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Website defacement actions across all teams.")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
    parser.add_argument("--targets", default="storage", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--action", required=True, choices=["deface_prestashop", "restore_prestashop"])
    parser.add_argument("--root", default="/var/www/prestashop", help="PrestaShop root path")
    args = parser.parse_args()

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    print(f"[+] Target teams: {teams}")
    print(f"[+] Action: {args.action} | Targets: {targets}")

    executor = RemoteExecutor(teams)
    defacer = WebsiteDefacement(executor)

    if args.action == "deface_prestashop":
        results = defacer.deface_prestashop(targets, prestashop_root=args.root)
    else:
        results = defacer.restore_prestashop(targets, prestashop_root=args.root)

    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
