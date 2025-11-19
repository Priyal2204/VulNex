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
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
                bandit_output = json.loads(result.stdout)
                return self._parse_bandit_results(bandit_output, file_path)
            else:
                print(f"Bandit failed on {file_path}: {result.stderr}")
                return []
                
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error running Bandit: {e}")
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
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                semgrep_output = json.loads(result.stdout)
                return self._parse_semgrep_results(semgrep_output, file_path)
            else:
                print(f"Semgrep failed on {file_path}: {result.stderr}")
                return []
                
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error running Semgrep: {e}")
            return []
    
    def _parse_bandit_results(self, bandit_output: Dict, file_path: str) -> List[Dict[str, Any]]:
        """Parse Bandit JSON output into standardized format"""
        results = []
        
        for result in bandit_output.get('results', []):
            vulnerability = {
                'filename': os.path.basename(file_path),
                'line_number': result.get('line_number', 0),
                'vulnerability_type': result.get('test_name', 'Unknown'),
                'severity': self._map_bandit_severity(result.get('issue_severity', 'LOW')),
                'confidence': self._map_bandit_confidence(result.get('issue_confidence', 'LOW')),
                'description': result.get('issue_text', ''),
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
            vulnerability = {
                'filename': os.path.basename(file_path),
                'line_number': result.get('start', {}).get('line', 0),
                'vulnerability_type': result.get('check_id', 'Unknown').split('.')[-1],
                'severity': self._map_semgrep_severity(result.get('extra', {}).get('severity', 'INFO')),
                'confidence': 85,  # Default confidence for Semgrep
                'description': result.get('extra', {}).get('message', ''),
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

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scanner.py <scan_id> <file_path1> [file_path2] ...")
        sys.exit(1)
    
    scan_id = sys.argv[1]
    file_paths = sys.argv[2:]
    
    scanner = SecurityScanner(scan_id, "uploads")
    results = scanner.scan_files(file_paths)
    
    # Output results as JSON
    print(json.dumps(results, indent=2))
