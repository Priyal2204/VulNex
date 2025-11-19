#!/usr/bin/env python3
"""
Security scanner service that integrates multiple static analysis tools
"""

import json
import subprocess
import os
import sys
from typing import List, Dict, Any
from pathlib import Path

class SecurityScanner:
    def __init__(self, scan_id: str, upload_dir: str):
        self.scan_id = scan_id
        self.upload_dir = upload_dir
        self.results = []
        
    def scan_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Run all available scanners on the provided files"""
        all_results = []
        
        for file_path in file_paths:
            if not os.path.exists(file_path):
                continue
                
            # Determine file type and run appropriate scanners
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.py':
                # Run Bandit for Python files
                bandit_results = self._run_bandit(file_path)
                all_results.extend(bandit_results)
                
            # Run Semgrep for all supported languages
            semgrep_results = self._run_semgrep(file_path)
            all_results.extend(semgrep_results)
            
        return all_results
    
    def _run_bandit(self, file_path: str) -> List[Dict[str, Any]]:
        """Run Bandit scanner on Python files"""
        try:
            cmd = ['bandit', '-f', 'json', file_path]
            # Force UTF-8 decoding and replace undecodable bytes to avoid
            # UnicodeDecodeError on Windows consoles with non-UTF8 locales.
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
            
            if result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
                # Bandit may sometimes write to stderr or produce empty stdout;
                # prefer stdout but fallback to stderr. Also ignore empty output.
                output_text = (result.stdout or "").strip() or (result.stderr or "").strip()
                if not output_text:
                    return []

                try:
                    bandit_output = json.loads(output_text)
                except json.JSONDecodeError:
                    print(f"Failed to decode Bandit JSON output for {file_path}: {output_text}", file=sys.stderr)
                    return []

                return self._parse_bandit_results(bandit_output, file_path)
            else:
                print(f"Bandit failed on {file_path}: {result.stderr}", file=sys.stderr)
                return []
                
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error running Bandit: {e}", file=sys.stderr)
            return []
    
    def _run_semgrep(self, file_path: str) -> List[Dict[str, Any]]:
        """Run Semgrep scanner"""
        try:
            cmd = [
                'semgrep', 
                '--config=auto', 
                '--json', 
                '--no-git-ignore',
                file_path
            ]
            # Force UTF-8 decoding and replace undecodable bytes. Semgrep emits
            # UTF-8; on Windows the default encoding can be cp1252 which fails
            # when semgrep outputs characters outside that codepage.
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
            # semgrep returns exit code 0 when no findings, 1 when findings are found
            # and >1 on errors. Accept both 0 and 1 as successful runs to capture findings.
            if result.returncode in [0, 1]:
                # semgrep typically writes JSON to stdout; if empty try stderr as a fallback
                output_text = result.stdout.strip() or result.stderr.strip()
                if not output_text:
                    return []

                try:
                    semgrep_output = json.loads(output_text)
                except json.JSONDecodeError:
                    print(f"Failed to decode Semgrep JSON output for {file_path}: {output_text}", file=sys.stderr)
                    return []

                return self._parse_semgrep_results(semgrep_output, file_path)
            else:
                print(f"Semgrep failed on {file_path}: {result.stderr}", file=sys.stderr)
                return []
                
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error running Semgrep: {e}", file=sys.stderr)
            return []
    
    def _parse_bandit_results(self, bandit_output: Dict, file_path: str) -> List[Dict[str, Any]]:
        """Parse Bandit JSON output into standardized format"""
        results = []
        
        for result in bandit_output.get('results', []):
            description = result.get('issue_text', '')
            recommendation = self._get_bandit_recommendation(result.get('test_id', ''), result)

            vulnerability = {
                'filename': os.path.basename(file_path),
                'line_number': result.get('line_number', 0),
                'vulnerability_type': result.get('test_name', 'Unknown'),
                'severity': self._map_bandit_severity(result.get('issue_severity', 'LOW')),
                'confidence': self._map_bandit_confidence(result.get('issue_confidence', 'LOW')),
                'description': f"{description}\n\nRecommendation:\n{recommendation}",
                'cwe_id': self._extract_cwe_from_bandit(result),
                'code_snippet': result.get('code', ''),
                'detection_tool': 'Bandit',
                'raw_result': result
            }
            results.append(vulnerability)

        return results
    
    def _parse_semgrep_results(self, semgrep_output: Dict, file_path: str) -> List[Dict[str, Any]]:
        """Parse Semgrep JSON output into standardized format"""
        results = []
        
        for result in semgrep_output.get('results', []):
            description = result.get('extra', {}).get('message', '')
            recommendation = self._get_semgrep_recommendation(result)

            vulnerability = {
                'filename': os.path.basename(file_path),
                'line_number': result.get('start', {}).get('line', 0),
                'vulnerability_type': result.get('check_id', 'Unknown').split('.')[-1],
                'severity': self._map_semgrep_severity(result.get('extra', {}).get('severity', 'INFO')),
                'confidence': 85,  # Default confidence for Semgrep
                'description': f"{description}\n\nRecommendation:\n{recommendation}",
                'cwe_id': self._extract_cwe_from_semgrep(result),
                'code_snippet': self._extract_code_snippet(file_path, result),
                'detection_tool': 'Semgrep',
                'raw_result': result
            }
            results.append(vulnerability)

        return results
    
    def _map_bandit_severity(self, severity: str) -> str:
        """Map Bandit severity to standardized levels"""
        mapping = {
            'HIGH': 'high',
            'MEDIUM': 'medium', 
            'LOW': 'low'
        }
        return mapping.get(severity.upper(), 'low')
    
    def _map_bandit_confidence(self, confidence: str) -> int:
        """Map Bandit confidence to numeric scale"""
        mapping = {
            'HIGH': 90,
            'MEDIUM': 70,
            'LOW': 50
        }
        return mapping.get(confidence.upper(), 50)
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standardized levels"""
        mapping = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        return mapping.get(severity.upper(), 'low')
    
    def _extract_cwe_from_bandit(self, result: Dict) -> str:
        """Extract CWE ID from Bandit result"""
        # Bandit doesn't always provide CWE, map common test IDs
        test_id = result.get('test_id', '')
        cwe_mapping = {
            'B101': 'CWE-95',   # assert_used
            'B102': 'CWE-78',   # exec_used
            'B103': 'CWE-78',   # set_bad_file_permissions
            'B104': 'CWE-319',  # hardcoded_bind_all_interfaces
            'B105': 'CWE-798',  # hardcoded_password_string
            'B106': 'CWE-798',  # hardcoded_password_funcarg
            'B107': 'CWE-798',  # hardcoded_password_default
            'B108': 'CWE-377',  # hardcoded_tmp_directory
            'B110': 'CWE-703',  # try_except_pass
            'B112': 'CWE-703',  # try_except_continue
            'B201': 'CWE-78',   # flask_debug_true
            'B301': 'CWE-502',  # pickle
            'B302': 'CWE-502',  # marshal
            'B303': 'CWE-327',  # md5
            'B304': 'CWE-327',  # ciphers
            'B305': 'CWE-327',  # cipher_modes
            'B306': 'CWE-327',  # mktemp_q
            'B307': 'CWE-78',   # eval
            'B308': 'CWE-327',  # mark_safe
            'B309': 'CWE-78',   # httpsconnection
            'B310': 'CWE-601',  # urllib_urlopen
            'B311': 'CWE-330',  # random
            'B312': 'CWE-78',   # telnetlib
            'B313': 'CWE-79',   # xml_bad_cElementTree
            'B314': 'CWE-79',   # xml_bad_ElementTree
            'B315': 'CWE-79',   # xml_bad_expatreader
            'B316': 'CWE-79',   # xml_bad_expatbuilder
            'B317': 'CWE-79',   # xml_bad_sax
            'B318': 'CWE-79',   # xml_bad_minidom
            'B319': 'CWE-79',   # xml_bad_pulldom
            'B320': 'CWE-79',   # xml_bad_etree
            'B321': 'CWE-78',   # ftplib
            'B322': 'CWE-78',   # input
            'B323': 'CWE-276',  # unverified_context
            'B324': 'CWE-327',  # hashlib_new_insecure_functions
            'B325': 'CWE-377',  # tempnam
            'B401': 'CWE-78',   # import_telnetlib
            'B402': 'CWE-78',   # import_ftplib
            'B403': 'CWE-502',  # import_pickle
            'B404': 'CWE-78',   # import_subprocess_popen
            'B405': 'CWE-79',   # import_xml_etree
            'B406': 'CWE-79',   # import_xml_sax
            'B407': 'CWE-79',   # import_xml_expat
            'B408': 'CWE-79',   # import_xml_minidom
            'B409': 'CWE-79',   # import_xml_pulldom
            'B410': 'CWE-79',   # import_lxml
            'B411': 'CWE-330',  # import_random
            'B501': 'CWE-295',  # request_with_no_cert_validation
            'B502': 'CWE-295',  # ssl_with_bad_version
            'B503': 'CWE-295',  # ssl_with_bad_defaults
            'B504': 'CWE-295',  # ssl_with_no_version
            'B505': 'CWE-327',  # weak_cryptographic_key
            'B506': 'CWE-78',   # yaml_load
            'B507': 'CWE-78',   # ssh_no_host_key_verification
            'B601': 'CWE-78',   # paramiko_calls
            'B602': 'CWE-78',   # subprocess_popen_with_shell_equals_true
            'B603': 'CWE-78',   # subprocess_without_shell_equals_false
            'B604': 'CWE-78',   # any_other_function_with_shell_equals_true
            'B605': 'CWE-78',   # start_process_with_a_shell
            'B606': 'CWE-78',   # start_process_with_no_shell
            'B607': 'CWE-78',   # start_process_with_partial_path
            'B608': 'CWE-89',   # hardcoded_sql_expressions
            'B609': 'CWE-78',   # linux_commands_wildcard_injection
            'B610': 'CWE-89',   # django_extra_used
            'B611': 'CWE-89',   # django_rawsql_used
            'B701': 'CWE-20',   # jinja2_autoescape_false
            'B702': 'CWE-693',  # use_of_mako_templates
            'B703': 'CWE-693',  # django_mark_safe
        }
        return cwe_mapping.get(test_id, '')
    
    def _extract_cwe_from_semgrep(self, result: Dict) -> str:
        """Extract CWE ID from Semgrep result"""
        # Try to extract CWE from metadata or rule ID
        metadata = result.get('extra', {}).get('metadata', {})
        
        # Check for CWE in metadata
        if 'cwe' in metadata:
            cwe_list = metadata['cwe']
            if isinstance(cwe_list, list) and cwe_list:
                return f"CWE-{cwe_list[0]}"
        
        # Check for OWASP mapping
        if 'owasp' in metadata:
            owasp_list = metadata['owasp']
            if isinstance(owasp_list, list) and owasp_list:
                # Map common OWASP categories to CWE
                owasp_to_cwe = {
                    'A01:2021': 'CWE-22',   # Broken Access Control
                    'A02:2021': 'CWE-327',  # Cryptographic Failures
                    'A03:2021': 'CWE-79',   # Injection
                    'A04:2021': 'CWE-639',  # Insecure Design
                    'A05:2021': 'CWE-1026', # Security Misconfiguration
                    'A06:2021': 'CWE-1104', # Vulnerable Components
                    'A07:2021': 'CWE-287',  # Identification and Authentication Failures
                    'A08:2021': 'CWE-345',  # Software and Data Integrity Failures
                    'A09:2021': 'CWE-778',  # Security Logging and Monitoring Failures
                    'A10:2021': 'CWE-918',  # Server-Side Request Forgery
                }
                return owasp_to_cwe.get(owasp_list[0], '')
        
        return ''
    
    def _extract_code_snippet(self, file_path: str, result: Dict) -> str:
        """Extract code snippet from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            start_line = result.get('start', {}).get('line', 1) - 1
            end_line = result.get('end', {}).get('line', start_line + 1) - 1

            # Get a few lines of context
            context_start = max(0, start_line - 2)
            context_end = min(len(lines), end_line + 3)

            snippet_lines = []
            for i in range(context_start, context_end):
                line_num = i + 1
                line_content = lines[i].rstrip()
                snippet_lines.append(f"{line_num:3d}: {line_content}")

            return '\n'.join(snippet_lines)

        except (IOError, UnicodeDecodeError):
            return result.get('extra', {}).get('lines', '')

    def _get_bandit_recommendation(self, test_id: str, result: Dict) -> str:
        """Get detailed recommendation for Bandit findings"""
        recommendations = {
            'B101': 'Avoid using assert statements for security checks. Use proper input validation and error handling instead.',
            'B102': 'Avoid using exec() as it can execute arbitrary code. Use safer alternatives like ast.literal_eval() for evaluating expressions.',
            'B103': 'Set secure file permissions. Use restrictive permissions (e.g., 0o600) for sensitive files.',
            'B104': 'Avoid binding to all network interfaces (0.0.0.0) in production. Bind to specific interfaces or use environment configuration.',
            'B105': 'Remove hardcoded passwords. Use environment variables or secure configuration management.',
            'B106': 'Remove hardcoded passwords from function arguments. Use environment variables or secure configuration management.',
            'B107': 'Avoid hardcoded password defaults. Use environment variables or secure configuration management.',
            'B108': 'Use secure temporary file creation methods like tempfile.mkstemp() instead of hardcoding paths.',
            'B110': 'Implement proper error handling instead of using bare try-except. Log errors and handle specific exceptions.',
            'B201': 'Disable Flask debug mode in production. Set debug=False for production environments.',
            'B301': 'Avoid using pickle for deserialization. Use safer alternatives like JSON.',
            'B303': 'Avoid using MD5 for cryptographic purposes. Use secure hashing algorithms like SHA-256.',
            'B304': 'Use strong encryption algorithms. Prefer AES over older ciphers.',
            'B307': 'Avoid using eval() as it can execute arbitrary code. Use ast.literal_eval() for safe evaluation.',
            'B308': 'Be cautious with mark_safe() in templates. Properly escape user input to prevent XSS.',
            'B311': 'Use secrets module instead of random for security-critical operations.',
            'B322': 'Replace input() with getpass() for passwords or secure input methods.',
            'B324': 'Use secure hash functions. Prefer SHA-256 or better.',
            'B501': 'Enable SSL certificate validation. Never disable verify=False in requests.',
            'B502': 'Use secure SSL/TLS versions. Avoid deprecated SSL/TLS versions.',
            'B506': 'Use yaml.safe_load() instead of yaml.load(). The latter can execute arbitrary code.',
            'B608': 'Use parameterized queries or ORM methods instead of string formatting for SQL queries.',
            'B701': 'Enable Jinja2 autoescape for all templates to prevent XSS attacks.',
        }

        generic_recommendation = 'Review the code for security implications and apply secure coding practices.'
        return recommendations.get(test_id, generic_recommendation)

    def _get_semgrep_recommendation(self, result: Dict) -> str:
        """Get detailed recommendation for Semgrep findings"""
        vuln_type = result.get('check_id', '').lower()
        metadata = result.get('extra', {}).get('metadata', {})

        if 'sql' in vuln_type or 'injection' in vuln_type:
            return 'Use parameterized queries (prepared statements) instead of string concatenation. Example:\n```python\ncursor.execute("SELECT * FROM users WHERE id = %s", [user_id])\n```'
        elif 'xss' in vuln_type:
            return 'Properly escape all user-controlled data before displaying it in HTML. Use template engine escape mechanisms or HTML sanitization libraries.'
        elif 'command' in vuln_type or 'os.system' in vuln_type:
            return 'Use subprocess.run() with shell=False and pass command arguments as a list to prevent command injection:\n```python\nsubprocess.run(["ls", "-l"], shell=False)\n```'
        elif 'hardcoded' in vuln_type or 'password' in vuln_type:
            return 'Move sensitive data to environment variables or a secure configuration management system:\n```python\nimport os\npassword = os.environ.get("DB_PASSWORD")\n```'
        elif 'open' in vuln_type:
            return 'Validate file paths and use secure file handling practices. Consider using pathlib for safer path manipulation:\n```python\nfrom pathlib import Path\npath = Path(user_input).resolve()\nif path.is_relative_to(safe_root):\n    with path.open() as f:\n        ...\n```'

        return 'Review the code for security implications and consider using secure coding practices appropriate for your use case.'

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scanner.py <scan_id> <file_path1> [file_path2] ...", file=sys.stderr)
        sys.exit(1)
    
    scan_id = sys.argv[1]
    file_paths = sys.argv[2:]
    
    scanner = SecurityScanner(scan_id, "uploads")
    results = scanner.scan_files(file_paths)
    
    # Only JSON to stdout
    json_output = json.dumps(results, ensure_ascii=False, indent=2)
    sys.stdout.buffer.write(json_output.encode("utf-8"))
    sys.stdout.buffer.write(b"\n")


