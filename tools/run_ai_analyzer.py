#!/usr/bin/env python3
"""Run the AI analyzer with a JSON payload file and print stdout/stderr.

Usage:
  python tools/run_ai_analyzer.py [payload.json]

If no file is provided it will use tools/payload.json
"""
import sys
import json
import subprocess
from pathlib import Path

PAYLOAD_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tools/payload.json")

if not PAYLOAD_PATH.exists():
    print(f"Payload file not found: {PAYLOAD_PATH}", file=sys.stderr)
    sys.exit(1)

payload = PAYLOAD_PATH.read_text(encoding='utf-8')

# Call the analyzer script as a subprocess so we reproduce the exact behaviour
proc = subprocess.run([sys.executable, "server/services/ai_analyzer.py", payload], capture_output=True, text=True)

print("--- analyzer stdout ---")
print(proc.stdout)
print("--- analyzer stderr ---")
print(proc.stderr)

if proc.returncode != 0:
    print(f"Analyzer exited with code {proc.returncode}", file=sys.stderr)
    sys.exit(proc.returncode)
