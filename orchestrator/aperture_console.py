#!/usr/bin/env python3
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def main() -> int:
    glados = SCRIPT_DIR / "glados.py"
    print("Aperture console has been consolidated into glados.py.")
    print("Launching the orchestrator.")
    return os.execv(sys.executable, [sys.executable, str(glados), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
