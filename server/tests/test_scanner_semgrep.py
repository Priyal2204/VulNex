import json
import subprocess
import unittest
from unittest.mock import patch

from server.services.scanner import SecurityScanner
import tempfile
import os

class TestScannerSemgrepParsing(unittest.TestCase):
    def test_semgrep_parsing_returns_vulnerability(self):
        # Sample semgrep JSON output structure
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.lang.security.sqlalchemy.injection",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 40},
                    "path": "example.py",
                    "extra": {
                        "message": "Possible SQL injection",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["89"]
                        }
                    }
                }
            ]
        }

        # Make subprocess.run return semgrep output with returncode 1 (findings)
        semgrep_completed = subprocess.CompletedProcess(args=['semgrep'], returncode=1, stdout=json.dumps(semgrep_output), stderr='')
        bandit_completed = subprocess.CompletedProcess(args=['bandit'], returncode=0, stdout=json.dumps({"results": []}), stderr='')

        def run_side_effect(cmd, capture_output=None, text=None):
            # cmd may be a list; choose based on first item
            if isinstance(cmd, (list, tuple)) and len(cmd) > 0:
                if 'semgrep' in cmd[0].lower():
                    return semgrep_completed
                if 'bandit' in cmd[0].lower():
                    return bandit_completed
            # default
            return semgrep_completed

        with patch('subprocess.run', side_effect=run_side_effect) as mock_run:
            # Create a temporary file so scanner will attempt to run semgrep on it
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.py')
            try:
                tmp.write(b"print('hello')\n")
                tmp.flush()
                tmp.close()

                scanner = SecurityScanner(scan_id='test-scan', upload_dir='uploads')
                results = scanner.scan_files([tmp.name])
            finally:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass

            # Expect one vulnerability parsed
            self.assertIsInstance(results, list)
            self.assertEqual(len(results), 1)

            vuln = results[0]
            # Check some expected keys and mapped values
            expected_filename = os.path.basename(tmp.name)
            self.assertEqual(vuln.get('filename'), expected_filename)
            self.assertEqual(vuln.get('detection_tool'), 'Semgrep')
            self.assertIn('Possible SQL injection', vuln.get('description', '') or vuln.get('description') == '')
            self.assertIsInstance(vuln.get('line_number'), int)

if __name__ == '__main__':
    unittest.main()
