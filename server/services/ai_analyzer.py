#!/usr/bin/env python3
"""
Robust AI fixer that prefers Hugging Face router and only uses Gemini if it actually works.
Outputs a JSON with 'ai_analysis' and 'suggested_fix' (both strings) and 'ai_diagnostics' for debugging.
"""

import os
import sys
import json
import time
import requests
from typing import Optional, Tuple, Dict, Any, List

# Config from env
HF_KEY = os.getenv("HUGGINGFACE_API_KEY")
GEMINI_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5")
USE_GEMINI = os.getenv("USE_GEMINI", "true").lower() not in ("0", "false", "no")
# HuggingFace router base (preferred)
HF_ROUTER_BASE = "https://router.huggingface.co/hf-inference/models"

# Candidate HF models to try (in order). Keep conservative/public choices first.
HF_MODEL_CANDIDATES = [
    "gpt2",                        # tiny but robust
    "EleutherAI/gpt-neo-2.7B",     # bigger, often available
    "bigscience/bloom",            # fallback
    # add other team-approved models if you have access
]

HEADERS_HF = {"Content-Type": "application/json"}
if HF_KEY:
    HEADERS_HF["Authorization"] = f"Bearer {HF_KEY}"

# Retry helper
def safe_post(url: str, headers: Dict[str, str], json_body: Dict[str, Any], timeout: int = 25) -> Tuple[Optional[requests.Response], Optional[str]]:
    """Send POST and return (response, error_text) with exceptions handled."""
    try:
        resp = requests.post(url, headers=headers, json=json_body, timeout=timeout)
        return resp, None
    except requests.RequestException as e:
        return None, str(e)

class AIFixer:
    def __init__(self):
        self.hf_base = HF_ROUTER_BASE
        self.hf_candidates = HF_MODEL_CANDIDATES
        self.use_gemini = USE_GEMINI and bool(GEMINI_KEY)
        self.gemini_key = GEMINI_KEY
        self.gemini_model = GEMINI_MODEL
        # Diagnostics to return for dev debugging
        self.diagnostics: Dict[str, Any] = {}

    # ---------- Gemini ----------
    def _call_gemini(self, instruction: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """Call Gemini if available. Return text or None, and diagnostic dict."""
        diag: Dict[str, Any] = {}
        if not self.use_gemini:
            diag["status"] = "skipped"
            return None, diag

        # Use query param key flow (works only if the key/project has access)
        # Try v1 then v1beta2 endpoints to be robust
        tried_urls = []
        body = {
            "prompt": {
                "text": instruction
            },
            "temperature": 0.2,
            "maxOutputTokens": 512
        }

        base_paths = [
            "https://generativelanguage.googleapis.com/v1",
            "https://generativelanguage.googleapis.com/v1beta2"
        ]

        # construct model variant(s)
        model_variants = [self.gemini_model, self.gemini_model.replace("models/", ""), self.gemini_model + ""]  # minor variants
        for bp in base_paths:
            for mv in model_variants:
                url = f"{bp}/models/{mv}:generate?key={self.gemini_key}"
                tried_urls.append(url)
                resp, err = safe_post(url, {"Content-Type": "application/json"}, body)
                if err:
                    diag.setdefault("tries", []).append({"url": url, "error": err})
                    continue
                diag.setdefault("tries", []).append({"url": url, "status_code": resp.status_code, "text_snippet": (resp.text[:500] if resp.text else "")})
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text}
                    # attempt to parse typical shapes
                    if isinstance(data, dict):
                        # check for candidates / output / text
                        if "candidates" in data and isinstance(data["candidates"], list) and data["candidates"]:
                            content = data["candidates"][0]
                            # content may hold structured parts
                            if isinstance(content, dict):
                                # some Gemini shapes: content->text or content->parts
                                if "content" in content and isinstance(content["content"], list):
                                    # best-effort join
                                    text_parts = []
                                    for p in content["content"]:
                                        if isinstance(p, dict):
                                            text_parts.append(p.get("text") or p.get("content") or "")
                                        else:
                                            text_parts.append(str(p))
                                    text = "\n".join(filter(None, text_parts)).strip()
                                    diag["source"] = "gemini_candidates_content"
                                    return text, diag
                                if "text" in content:
                                    diag["source"] = "gemini_candidates_text"
                                    return content.get("text", ""), diag
                        if "output" in data and isinstance(data["output"], list):
                            text = "".join([o.get("content", "") if isinstance(o, dict) else str(o) for o in data["output"]])
                            diag["source"] = "gemini_output"
                            return text.strip(), diag
                        if "text" in data:
                            diag["source"] = "gemini_text"
                            return data.get("text", ""), diag
                    # fallback return raw text
                    try:
                        return resp.text.strip(), diag
                    except Exception:
                        return None, diag
                else:
                    # non-200: keep trying
                    continue

        diag["status"] = "no_success"
        diag["tried_urls"] = tried_urls
        return None, diag

    # ---------- Hugging Face ----------
    def _call_hf_router(self, model: str, instruction: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """Call HuggingFace router with a model name. Return text or None and diag info."""
        diag: Dict[str, Any] = {"model": model}
        url = f"{self.hf_base}/{model}"
        payload = {
            "inputs": instruction,
            "parameters": {
                "max_new_tokens": 512,
                "temperature": 0.2,
                "do_sample": False
            }
        }
        resp, err = safe_post(url, HEADERS_HF, payload)
        if err:
            diag["error"] = err
            return None, diag
        diag["status_code"] = resp.status_code
        text_snippet = (resp.text[:800] + "...") if resp.text and len(resp.text) > 800 else resp.text
        diag["text_snippet"] = text_snippet
        # handle 200
        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                # sometimes HF returns raw text; return it
                return resp.text.strip(), diag

            # common shapes:
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and "generated_text" in data[0]:
                return data[0]["generated_text"].strip(), diag
            if isinstance(data, dict):
                # router sometimes returns {'generated_text': '...'}
                if "generated_text" in data:
                    return data["generated_text"].strip(), diag
                # other shapes: return entire dict as string
                return json.dumps(data)[:4000], diag
            return str(data)[:4000], diag
        # handle retries for 503
        if resp.status_code == 503:
            diag["note"] = "503_model_loading; will retry once"
            # sleep short and retry
            time.sleep(3)
            resp2, err2 = safe_post(url, HEADERS_HF, payload)
            if err2:
                diag["retry_error"] = err2
                return None, diag
            diag["retry_status"] = getattr(resp2, "status_code", None)
            if getattr(resp2, "status_code", None) == 200:
                try:
                    data2 = resp2.json()
                    if isinstance(data2, list) and data2 and "generated_text" in data2[0]:
                        return data2[0]["generated_text"].strip(), diag
                    if isinstance(data2, dict) and "generated_text" in data2:
                        return data2["generated_text"].strip(), diag
                    return resp2.text.strip(), diag
                except Exception:
                    return resp2.text.strip(), diag
        # non-200: return None with diag
        return None, diag

    # ---------- High level ----------
    def _build_prompt(self, description: str, code_snippet: str) -> str:
        """Construct a focused instruction for fix + recommendation JSON output."""
        # We instruct the model to return JSON where possible to make parsing deterministic
        prompt = (
            "You are a security-savvy developer. Given the short vulnerability description and code, "
            "produce two items: 'fix' (a corrected code snippet or concrete instructions to fix) and "
            "'recommendation' (short explanation why and any important caveats). Return **ONLY** a JSON object "
            "with keys: fix, recommendation. Keep code fenced with triple backticks if you include code. "
            "If you cannot produce code, populate fix with a clear step list.\n\n"
            "Description:\n"
            f"{description}\n\n"
            "Code:\n"
            f"{code_snippet}\n\n"
            "Return example:\n"
            "{\"fix\": \"```python\\n# fixed code here\\n```\", \"recommendation\": \"Use parameterized queries...\"}\n"
        )
        return prompt

    def get_fix_and_recommendation(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry. Returns dict with ai_analysis, suggested_fix, diagnostics."""
        description = vuln.get("description") or vuln.get("vulnerabilityType") or "Vulnerability"
        code_snippet = vuln.get("codeSnippet") or vuln.get("code_snippet") or vuln.get("code", "")

        prompt = self._build_prompt(description, code_snippet)

        # 1) Try Gemini (if enabled) — but only if it actually works
        gem_text = None
        gem_diag = None
        if self.use_gemini:
            gem_text, gem_diag = self._call_gemini(prompt)
            self.diagnostics["gemini"] = gem_diag
            if gem_text:
                parsed = self._safe_parse_json_like(gem_text)
                return {
                    "ai_analysis": gem_text,
                    "suggested_fix": parsed.get("fix") or gem_text,
                    "ai_model_used": f"Gemini:{self.gemini_model}",
                    "ai_diagnostics": {"gemini": gem_diag}
                }

        # 2) Try Hugging Face candidates in order
        hf_diag_list: List[Dict[str, Any]] = []
        for candidate in self.hf_candidates:
            text, diag = self._call_hf_router(candidate, prompt)
            hf_diag_list.append({"model": candidate, **diag})
            # If text returned, try parse and return
            if text:
                parsed = self._safe_parse_json_like(text)
                return {
                    "ai_analysis": text,
                    "suggested_fix": parsed.get("fix") or text,
                    "ai_model_used": f"HuggingFace:{candidate}",
                    "ai_diagnostics": {"huggingface_tried": hf_diag_list, "gemini": gem_diag}
                }

        # 3) No model produced a good response — return fallback suggestions (simple deterministic suggestions)
        fallback_analysis = self._fallback_explanation(description, code_snippet)
        # include diagnostics
        diag = {"gemini": gem_diag, "hf_candidates": hf_diag_list}
        return {
            "ai_analysis": fallback_analysis,
            "suggested_fix": self._fallback_fix(description, code_snippet),
            "ai_model_used": "Fallback",
            "ai_diagnostics": diag
        }

    # ---------- Helpers ----------
    def _safe_parse_json_like(self, text: str) -> Dict[str, str]:
        """
        Try to extract JSON object from text. If cannot, return {'fix': text, 'recommendation': ''}
        """
        text = text.strip()
        # try direct JSON parse
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return {k: str(v) for k, v in obj.items()}
        except Exception:
            pass

        # try to find first { ... } block
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start:end+1]
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    return {k: str(v) for k, v in obj.items()}
            except Exception:
                pass

        # fallback: return whole text as 'fix'
        return {"fix": text, "recommendation": ""}

    def _fallback_explanation(self, description: str, code: str) -> str:
        """A minimal deterministic explanation for common vuln types; used when no model works."""
        ll = description.lower()
        if "sql" in ll or "sql injection" in ll:
            return ("This code appears to build SQL queries by concatenating user input. "
                    "Use parameterized queries (prepared statements) or ORM filtering to avoid SQL injection.")
        if "subprocess" in ll or "shell" in ll or "command injection" in ll:
            return ("This code executes shell commands with user-controlled input. "
                    "Avoid shell=True and use argument lists or validate & sanitize input; prefer library functions.")
        if "md5" in ll or "weak" in ll:
            return ("This code uses MD5 (or weak crypto) for sensitive hashing; switch to bcrypt/scrypt/argon2 or hashlib.scrypt.")
        if "pickle" in ll or "deserialize" in ll:
            return ("This code deserializes untrusted input (pickle). Use JSON or another safe format; do not unpickle untrusted data.")
        return "Fallback analysis: please inspect the code and apply secure coding best practices."

    def _fallback_fix(self, description: str, code: str) -> str:
        """Return a short suggested fix string if models fail."""
        ll = description.lower()
        if "sql" in ll:
            return ("Use parameterized queries. Example (sqlite3):\n\n"
                    "```python\ncur.execute('SELECT id, username FROM users WHERE username LIKE ?', (f'%{q}%',))\n```\n")
        if "subprocess" in ll or "shell" in ll:
            return ("Avoid shell=True; pass the command as an array. Example:\n\n"
                    "```python\n# Unsafe: subprocess.call(cmd, shell=True)\nsubprocess.call(['ping', '-c', '1', target])\n```\n")
        if "md5" in ll:
            return ("Use bcrypt/argon2 for password hashing. Example:\n\n"
                    "```python\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n```\n")
        if "pickle" in ll:
            return ("Replace pickle with json for untrusted data. Example:\n\n"
                    "```python\nimport json\nobj = json.loads(data_str)\n```\n")
        return "No automatic fix available. Review the vulnerability and apply secure coding practices."

# ---------- CLI handler ----------
def main():
    if len(sys.argv) < 2:
        print("Usage: python ai_analyzer.py '<vulnerability_json>'", file=sys.stderr)
        sys.exit(1)
    try:
        raw = sys.argv[1]
        vuln = json.loads(raw)
    except Exception as e:
        print(f"Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    ai = AIFixer()
    out = ai.get_fix_and_recommendation(vuln)
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()