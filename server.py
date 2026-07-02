#!/usr/bin/env python3
"""Entry point: run Flask dashboard and API."""
import sys
import runpy
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

if __name__ == "__main__":
    runpy.run_module("dementor_sca.server", run_name="__main__", alter_sys=True)
