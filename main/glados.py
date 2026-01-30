#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path

from common import prompt_team_count

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent


def run_script(script_path: Path, args: list) -> int:
    cmd = [sys.executable, str(script_path)] + args
    return subprocess.call(cmd)


def prompt_targets() -> str:
    print("Targets: all, linux, windows, or comma-separated hostnames")
    return input("Targets: ").strip() or "all"


def prompt_action(label: str, actions: list) -> str:
    print(label)
    for idx, action in enumerate(actions, start=1):
        print(f"{idx}. {action}")
    choice = input("Choice: ").strip()
    try:
        return actions[int(choice) - 1]
    except (ValueError, IndexError):
        return actions[0]


def interactive_menu(teams_count: int) -> int:
    while True:
        print("Aperture Science Red Team Orchestrator")
        print("1. Start C2 server")
        print("2. Credential spray")
        print("3. Deploy persistence")
        print("4. User management")
        print("5. Service degradation")
        print("6. Website defacement")
        print("7. Chaos mode")
        print("Q. Quit")

        choice = input("Choice: ").strip().upper()
        if choice == "1":
            run_script(ROOT_DIR / "payloads" / "portal_gun.py", ["--port", "8080"])
            continue
        if choice == "2":
            run_script(ROOT_DIR / "init_access" / "default_cred_spray.py", ["--teams", f"1-{teams_count}"])
            continue
        if choice == "3":
            targets = prompt_targets()
            run_script(SCRIPT_DIR / "persistence.py", ["--teams-count", str(teams_count), "--targets", targets])
            continue
        if choice == "4":
            targets = prompt_targets()
            action = prompt_action(
                "User management actions:",
                [
                    "pkill_users",
                    "create_themed_users",
                    "remove_themed_users",
                    "create_glados_admin",
                    "weaken_root_password",
                ],
            )
            run_script(
                SCRIPT_DIR / "user_management.py",
                ["--teams-count", str(teams_count), "--targets", targets, "--action", action],
            )
            continue
        if choice == "5":
            targets = prompt_targets()
            action = prompt_action(
                "Service degradation actions:",
                ["block_scoring", "unblock_scoring", "stop_http", "start_http", "stop_dns", "start_dns"],
            )
            run_script(
                SCRIPT_DIR / "service_degradation.py",
                ["--teams-count", str(teams_count), "--targets", targets, "--action", action],
            )
            continue
        if choice == "6":
            targets = prompt_targets()
            action = prompt_action("Defacement actions:", ["deface_prestashop", "restore_prestashop"])
            run_script(
                SCRIPT_DIR / "defacement.py",
                ["--teams-count", str(teams_count), "--targets", targets, "--action", action],
            )
            continue
        if choice == "7":
            targets = prompt_targets()
            action = prompt_action(
                "Chaos actions:", ["deploy_nyan_cat", "deploy_matrix_rain", "deploy_desktop_goose", "remove_chaos"]
            )
            run_script(
                SCRIPT_DIR / "chaos_mode.py",
                ["--teams-count", str(teams_count), "--targets", targets, "--action", action],
            )
            continue
        if choice == "Q":
            print("Goodbye.")
            return 0
        print("Invalid choice.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aperture Science Red Team Orchestrator")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--action", choices=[
        "c2",
        "credential_spray",
        "persistence",
        "user_management",
        "service_degradation",
        "defacement",
        "chaos_mode",
    ])
    parser.add_argument("--targets", default="all", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--subaction", help="Action for user/service/defacement/chaos")
    args = parser.parse_args()

    teams_count = prompt_team_count(args.teams_count)

    if not args.action:
        return interactive_menu(teams_count)

    if args.action == "c2":
        return run_script(ROOT_DIR / "payloads" / "portal_gun.py", ["--port", "8080"])
    if args.action == "credential_spray":
        return run_script(ROOT_DIR / "init_access" / "default_cred_spray.py", ["--teams", f"1-{teams_count}"])
    if args.action == "persistence":
        return run_script(SCRIPT_DIR / "persistence.py", ["--teams-count", str(teams_count), "--targets", args.targets])
    if args.action == "user_management":
        if not args.subaction:
            print("Provide --subaction for user_management.")
            return 1
        return run_script(
            SCRIPT_DIR / "user_management.py",
            ["--teams-count", str(teams_count), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "service_degradation":
        if not args.subaction:
            print("Provide --subaction for service_degradation.")
            return 1
        return run_script(
            SCRIPT_DIR / "service_degradation.py",
            ["--teams-count", str(teams_count), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "defacement":
        if not args.subaction:
            print("Provide --subaction for defacement.")
            return 1
        return run_script(
            SCRIPT_DIR / "defacement.py",
            ["--teams-count", str(teams_count), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "chaos_mode":
        if not args.subaction:
            print("Provide --subaction for chaos_mode.")
            return 1
        return run_script(
            SCRIPT_DIR / "chaos_mode.py",
            ["--teams-count", str(teams_count), "--targets", args.targets, "--action", args.subaction],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
