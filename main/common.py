#!/usr/bin/env python3
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional

TEAM_SUBNET_BASE = 200
TEAM_SUBNET_MIN = 200
TEAM_SUBNET_MAX = 212


def prompt_team_count(team_count: Optional[int] = None) -> int:
    if team_count:
        return team_count
    while True:
        raw = input("How many teams are playing (1-12)? ").strip()
        try:
            value = int(raw)
        except ValueError:
            print("Enter a number.")
            continue
        if value < 1 or value > (TEAM_SUBNET_MAX - TEAM_SUBNET_BASE):
            print(f"Enter a number between 1 and {TEAM_SUBNET_MAX - TEAM_SUBNET_BASE}.")
            continue
        return value


def build_team_numbers(team_count: int) -> List[int]:
    return list(range(1, team_count + 1))


def get_red_team_ip() -> str:
    env_ip = os.environ.get("RED_TEAM_IP")
    if env_ip:
        return env_ip

    result = subprocess.run(["ip", "a"], capture_output=True, text=True, check=False)
    candidates = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue
        match = re.match(r"inet ([0-9.]+)/", line)
        if not match:
            continue
        addr = match.group(1)
        if addr.startswith("127."):
            continue
        candidates.append(addr)

    if not candidates:
        return "127.0.0.1"

    preferred_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.")
    for prefix in preferred_prefixes:
        for addr in candidates:
            if addr.startswith(prefix):
                return addr

    return candidates[0]


def ensure_ssh_keypair() -> Path:
    ssh_dir = Path.home() / ".ssh"
    key_candidates = [
        ssh_dir / "id_ed25519",
        ssh_dir / "id_rsa",
        ssh_dir / "id_ecdsa",
    ]
    for key_path in key_candidates:
        if key_path.exists():
            return key_path

    print("No SSH key found.")
    response = input("Create a new SSH key now? [y/N]: ").strip().lower()
    if response != "y":
        raise RuntimeError("SSH key required but not created.")

    ssh_dir.mkdir(parents=True, exist_ok=True)
    key_path = ssh_dir / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", "aperture-red-team"],
        check=True,
    )
    return key_path
