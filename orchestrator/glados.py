#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import free_port, resolve_team_numbers
from lib.operations import AttackModules, PersistenceDeployer, RemoteExecutor, TARGETS as OPS_TARGETS


def run_script(script_path: Path, args: list) -> int:
    cmd = [sys.executable, str(script_path)] + args
    return subprocess.call(cmd)


def safe_input(prompt: str) -> Optional[str]:
    try:
        return input(prompt)
    except EOFError:
        try:
            if os.path.exists("/dev/tty"):
                with open("/dev/tty", "r", encoding="utf-8", errors="ignore") as tty:
                    sys.stdout.write(prompt)
                    sys.stdout.flush()
                    line = tty.readline()
                    return line.rstrip("\n") if line else None
        except OSError:
            return None
        return None


def prompt_targets() -> Optional[str]:
    print("Targets: all, linux, windows, comma-separated hostnames, or numbers from the list")
    print("Targets list:")
    for idx, target in enumerate(OPS_TARGETS, start=1):
        print(f"  {idx}. {target.hostname} ({target.os_type})")
    print("  All: all or A | Linux: linux | Windows: windows | Back: B")
    while True:
        choice = safe_input("Targets: ")
        if choice is None:
            return None
        choice = choice.strip()
        if not choice:
            return "all"
        if choice.upper() == "B":
            return None
        if choice.upper() == "A":
            return "all"
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


def load_ssh_pubkey() -> Optional[str]:
    candidates = [
        Path.home() / ".ssh" / "id_ed25519.pub",
        Path.home() / ".ssh" / "id_rsa.pub",
        Path.home() / ".ssh" / "id_ecdsa.pub",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.read_text(encoding="utf-8").strip()
    return None


def _summarize_failures(label: str, results: dict) -> None:
    failures = results.get("failed", [])
    if not failures:
        return
    print(f"[!] {label} failures ({len(failures)}):")
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


def _summarize_skips(label: str, results: dict) -> None:
    skipped = results.get("skipped", [])
    if not skipped:
        return
    print(f"[!] {label} skipped ({len(skipped)}):")
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


def _summarize_success_outputs(label: str, results: dict) -> None:
    successes = results.get("success", [])
    if not successes:
        return
    print(f"[+] {label} output ({len(successes)}):")
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
        else:
            print("      (no output)")


def _retry_failures(
    label: str,
    action,
    base_targets: list[str],
    results: dict,
    attempts: int = 1,
) -> dict:
    failures = results.get("failed", [])
    if not failures or attempts < 1:
        return results
    failed_targets = sorted({failure["target"] for failure in failures})
    if not failed_targets:
        return results
    print(f"[!] Retrying {label} on failed targets: {failed_targets}")
    retry_results = action(failed_targets)
    return retry_results


def run_init_sequence(teams: list[int]) -> None:
    pubkey = load_ssh_pubkey()
    if pubkey:
        os.environ["APERTURE_SSH_PUBKEY"] = pubkey
        print("[+] Init: loaded local SSH public key for glados")
    else:
        print("[!] Init: no local SSH public key found; skipping key install")
    targets = [target.hostname for target in OPS_TARGETS]
    executor = RemoteExecutor(teams)
    attacks = AttackModules(executor)
    deployer = PersistenceDeployer(executor)

    print("[+] Init: ensure access")
    results = attacks.ensure_remote_access(targets)
    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    _summarize_failures("ensure_access", results)
    _summarize_skips("ensure_access", results)
    results = _retry_failures("ensure_access", attacks.ensure_remote_access, targets, results)
    _summarize_failures("ensure_access retry", results)
    _summarize_skips("ensure_access retry", results)

    print("[+] Init: deploy persistence")
    results = deployer.deploy(targets)
    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    _summarize_failures("deploy_persistence", results)
    _summarize_skips("deploy_persistence", results)
    results = _retry_failures("deploy_persistence", deployer.deploy, targets, results)
    _summarize_failures("deploy_persistence retry", results)
    _summarize_skips("deploy_persistence retry", results)

    print("[+] Init: verify aperture artifacts")
    results = deployer.list_artifacts(targets)
    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    _summarize_success_outputs("aperture artifacts", results)
    _summarize_failures("aperture artifacts", results)
    _summarize_skips("aperture artifacts", results)

    print("[+] Init: create themed users")
    results = attacks.create_themed_users(targets)
    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    _summarize_failures("create_themed_users", results)
    _summarize_skips("create_themed_users", results)
    results = _retry_failures("create_themed_users", attacks.create_themed_users, targets, results)
    _summarize_failures("create_themed_users retry", results)
    _summarize_skips("create_themed_users retry", results)

    print("[+] Init: create glados admin")
    results = attacks.create_glados_admin(targets)
    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    _summarize_failures("create_glados_admin", results)
    _summarize_skips("create_glados_admin", results)
    results = _retry_failures("create_glados_admin", attacks.create_glados_admin, targets, results)
    _summarize_failures("create_glados_admin retry", results)
    _summarize_skips("create_glados_admin retry", results)

    print("[+] Init: install access maintenance tasks")
    results = attacks.install_access_tasks(targets)
    print(
        f"Success: {len(results['success'])}, "
        f"Failed: {len(results['failed'])}, "
        f"Skipped: {len(results.get('skipped', []))}"
    )
    _summarize_failures("install_access_tasks", results)
    _summarize_skips("install_access_tasks", results)
    results = _retry_failures("install_access_tasks", attacks.install_access_tasks, targets, results)
    _summarize_failures("install_access_tasks retry", results)
    _summarize_skips("install_access_tasks retry", results)


def interactive_menu(teams: list[int]) -> int:
    teams_arg = format_teams_arg(teams)
    while True:
        print("Aperture Science Red Team Orchestrator")
        print(f"Active teams: {teams}")
        print("1. Init competition")
        print("2. Start C2 server")
        print("3. Credential spray")
        print("4. Deploy persistence")
        print("5. User management")
        print("6. Service degradation")
        print("7. Website defacement")
        print("8. Chaos mode")
        print("9. Access maintenance")
        print("Q. Quit")

        choice = safe_input("Choice: ")
        if choice is None:
            print("Goodbye.")
            return 0
        choice = choice.strip().upper()
        if choice == "1":
            run_init_sequence(teams)
            continue
        if choice == "2":
            freed, message = free_port(8080, auto_install=True)
            if message:
                print(f"[+] C2 preflight: {message}")
            run_script(ROOT_DIR / "payloads" / "portal_gun.py", ["--port", "8080"])
            continue
        if choice == "3":
            targets = prompt_targets()
            if targets is None:
                continue
            run_script(
                ROOT_DIR / "init_access" / "default_cred_spray.py",
                ["--teams", teams_arg, "--targets", targets],
            )
            continue
        if choice == "4":
            targets = prompt_targets()
            if targets is None:
                continue
            run_script(SCRIPT_DIR / "persistence.py", ["--teams", teams_arg, "--targets", targets])
            continue
        if choice == "5":
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
        if choice == "6":
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
        if choice == "7":
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
        if choice == "8":
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
        if choice == "9":
            targets = prompt_targets()
            if targets is None:
                continue
            action = prompt_action(
                "Access maintenance actions:",
                ["ensure_access", "install_access_tasks"],
            )
            if action is None:
                continue
            run_script(
                SCRIPT_DIR / "access_maintenance.py",
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
        "access_maintenance",
        "init_competition",
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
        return run_script(
            ROOT_DIR / "init_access" / "default_cred_spray.py",
            ["--teams", format_teams_arg(teams), "--targets", args.targets],
        )
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
    if args.action == "access_maintenance":
        if not args.subaction:
            print("Provide --subaction for access_maintenance.")
            return 1
        return run_script(
            SCRIPT_DIR / "access_maintenance.py",
            ["--teams", format_teams_arg(teams), "--targets", args.targets, "--action", args.subaction],
        )
    if args.action == "init_competition":
        run_init_sequence(teams)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
