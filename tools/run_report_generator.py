#!/usr/bin/env python3
"""Run the Python report generator with sample JSON files and print the result."""
import json
import subprocess
from pathlib import Path

scan_file = Path('tools/report_scan.json')
config_file = Path('tools/report_config.json')

if not scan_file.exists() or not config_file.exists():
    print('Missing tools/report_scan.json or tools/report_config.json', flush=True)
    raise SystemExit(1)

scan = scan_file.read_text(encoding='utf-8')
config = config_file.read_text(encoding='utf-8')

proc = subprocess.run(["python", "server/services/report_generator.py", scan, config], capture_output=True, text=True)
print('--- stdout ---')
print(proc.stdout)
print('--- stderr ---')
print(proc.stderr)
print('exit code', proc.returncode)
if proc.returncode != 0:
    raise SystemExit(proc.returncode)
