#!/usr/bin/env python3
"""Simple HuggingFace token checker for the HF router + StarCoder model.

Usage: set HUGGINGFACE_API_KEY in your PowerShell session, then run:
  python tools/hf_token_check.py

This will POST a tiny code snippet to bigcode/starcoder and print status + body.
"""
import os
import requests
import sys

MODEL = "bigcode/starcoder"
API_BASE = "https://router.huggingface.co/hf-inference"

def main():
    token = os.environ.get("HUGGINGFACE_API_KEY")
    if not token:
        print("NO_TOKEN: set HUGGINGFACE_API_KEY in your environment", file=sys.stderr)
        sys.exit(1)

    url = f"{API_BASE}/{MODEL}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "inputs": "def hello():\n    print(\"hello world\")\n",
        "parameters": {"max_new_tokens": 64}
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        print("HTTP/Status:", r.status_code)
        # Print a reasonably sized slice of body to avoid huge dumps
        text = r.text
        print(text[:4000])
        # If it's JSON, try to show parsed keys
        try:
            j = r.json()
            print("\nJSON keys:", list(j.keys()) if isinstance(j, dict) else type(j))
        except Exception:
            pass
    except Exception as e:
        print("ERROR: ", e, file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
