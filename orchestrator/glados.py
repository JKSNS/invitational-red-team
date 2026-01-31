#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import free_port, resolve_team_numbers
from lib.operations import TARGETS as OPS_TARGETS


def run_script(script_path: Path, args: list) -> int:
    cmd = [sys.executable, str(script_path)] + args
    return subprocess.call(cmd)


def safe_input(prompt: str) -> Optional[str]:
    try:
        return input(prompt)
    except EOFError:
        return None


def prompt_targets() -> Optional[str]:
    print("Targets: all, linux, windows, comma-separated hostnames, or numbers from the list")
    print("Targets list:")
    for idx, target in enumerate(OPS_TARGETS, start=1):
        print(f"  {idx}. {target.hostname} ({target.os_type})")
    print(f"  All: all | Linux: linux | Windows: windows | Back: B")
    while True:
        choice = safe_input("Targets: ")
        if choice is None:
            return None
        choice = choice.strip()
        if not choice:
            return "all"
        if choice.upper() == "B":
            return None
        lowered = choice.lower()
        if lowered in {"all", "linux", "windows"}:
            return lowered
        tokens = [token.strip() for token in lowered.split(",") if token.strip()]
        if tokens and all(token.isdigit() for token in tokens):
            indices = []
            for token in tokens:
                index = int(token)
                if index < 1 or index > len(OPS_TARGETS):
                    print("Invalid target number. Try again.")
                    break
                indices.append(index)
            else:
                hostnames = [OPS_TARGETS[i - 1].hostname for i in indices]
                return ",".join(hostnames)
            continue
        if tokens:
            return ",".join(tokens)
        print("Invalid input. Try again or use B to go back.")


def prompt_action(label: str, actions: list) -> Optional[str]:
    print(label)
    for idx, action in enumerate(actions, start=1):
        print(f"{idx}. {action}")
    print("B. Back")
    choice = safe_input("Choice: ")
    if choice is None:
        return None
    choice = choice.strip()
    if choice.upper() == "B":
        return None
    try:
        return actions[int(choice) - 1]
    except (ValueError, IndexError):
        return actions[0]


def format_teams_arg(teams: list[int]) -> str:
    return ",".join(str(team) for team in teams)


def interactive_menu(teams: list[int]) -> int:
    teams_arg = format_teams_arg(teams)
    while True:
        print("Aperture Science Red Team Orchestrator")
        print(f"Active teams: {teams}")
        print("1. Start C2 server")
        print("2. Credential spray")
        print("3. Deploy persistence")
        print("4. User management")
        print("5. Service degradation")
        print("6. Website defacement")
        print("7. Chaos mode")
        print("Q. Quit")

        choice = safe_input("Choice: ")
        if choice is None:
            print("Goodbye.")
            return 0
        choice = choice.strip().upper()
        if choice == "1":
            freed, message = free_port(8080, auto_install=True)
            if message:
                print(f"[+] C2 preflight: {message}")
            run_script(ROOT_DIR / "payloads" / "portal_gun.py", ["--port", "8080"])
            continue
        if choice == "2":
            run_script(ROOT_DIR / "init_access" / "default_cred_spray.py", ["--teams", teams_arg])
            continue
        if choice == "3":
            targets = prompt_targets()
            if targets is None:
                continue
            run_script(SCRIPT_DIR / "persistence.py", ["--teams", teams_arg, "--targets", targets])
            continue
        if choice == "4":
            targets = prompt_targets()
            if targets is None:
                continue
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
            if action is None:
                continue
            run_script(
                SCRIPT_DIR / "user_management.py",
                ["--teams", teams_arg, "--targets", targets, "--action", action],
            )
            continue
        if choice == "5":
            targets = prompt_targets()
            if targets is None:
                continue
            action = prompt_action(
                "Service degradation actions:",
                ["block_scoring", "unblock_scoring", "stop_http", "start_http", "stop_dns", "start_dns"],
            )
            if action is None:
                continue
            run_script(
                SCRIPT_DIR / "service_degradation.py",
                ["--teams", teams_arg, "--targets", targets, "--action", action],
            )
            continue
        if choice == "6":
            targets = prompt_targets()
            if targets is None:
                continue
            action = prompt_action("Defacement actions:", ["deface_prestashop", "restore_prestashop"])
            if action is None:
                continue
            run_script(
                SCRIPT_DIR / "defacement.py",
                ["--teams", teams_arg, "--targets", targets, "--action", action],
            )
            continue
        if choice == "7":
            targets = prompt_targets()
            if targets is None:
                continue
            action = prompt_action(
                "Chaos actions:", ["deploy_nyan_cat", "deploy_matrix_rain", "deploy_desktop_goose", "remove_chaos"]
            )
            if action is None:
                continue
            run_script(
                SCRIPT_DIR / "chaos_mode.py",
                ["--teams", teams_arg, "--targets", targets, "--action", action],
            )
            continue
        if choice == "Q":
            print("Goodbye.")
            return 0
        print("Invalid choice.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aperture Science Red Team Orchestrator")
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
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

    teams = resolve_team_numbers(args.teams, args.teams_count)

    if not args.action:
        return interactive_menu(teams)

    if args.action == "c2":
        freed, message = free_port(8080, auto_install=True)
        if message:
            print(f"[+] C2 preflight: {message}")
        return run_script(ROOT_DIR / "payloads" / "portal_gun.py", ["--port", "8080"])
    if args.action == "credential_spray":
        return run_script(ROOT_DIR / "init_access" / "default_cred_spray.py", ["--teams", format_teams_arg(teams)])
    if args.action == "persistence":
        return run_script(SCRIPT_DIR / "persistence.py", ["--teams", format_teams_arg(teams), "--targets", args.targets])
    if args.action == "user_management":
        if not args.subaction:
            print("Provide --subaction for user_management.")
            return 1
        return run_script(
            SCRIPT_DIR / "user_management.py",
            ["--teams", format_teams_arg(teams), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "service_degradation":
        if not args.subaction:
            print("Provide --subaction for service_degradation.")
            return 1
        return run_script(
            SCRIPT_DIR / "service_degradation.py",
            ["--teams", format_teams_arg(teams), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "defacement":
        if not args.subaction:
            print("Provide --subaction for defacement.")
            return 1
        return run_script(
            SCRIPT_DIR / "defacement.py",
            ["--teams", format_teams_arg(teams), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "chaos_mode":
        if not args.subaction:
            print("Provide --subaction for chaos_mode.")
            return 1
        return run_script(
            SCRIPT_DIR / "chaos_mode.py",
            ["--teams", format_teams_arg(teams), "--targets", args.targets, "--action", args.subaction],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
