# utils.py

import os
import re
import json
import bleach
import requests

API_KEY = os.getenv("LLM_API_KEY")
LLM_ENDPOINT = "https://api.example-llm.com/v1/chat/completions"

ALLOWED_LANGUAGES = [
    ("python", "Python"),
    ("javascript", "JavaScript"),
    ("java", "Java"),
    ("c", "C"),
    ("cpp", "C++"),
    ("csharp", "C#"),
    ("go", "Go"),
    ("rust", "Rust"),
    ("php", "PHP"),
    ("ruby", "Ruby"),
    ("typescript", "TypeScript"),
]


def sanitize_input(text: str) -> str:
    cleaned = bleach.clean(text, tags=[], strip=True)
    cleaned = re.sub(r"\\x00", "", cleaned)
    return cleaned


def scan_code_with_llm(language: str, code: str):

    prompt = f"""
You are a senior application security engineer.

Analyze the following {language} source code.

Tasks:
1. Detect vulnerabilities
2. Map them to CWE and CVE references if applicable
3. Explain the security risk
4. Provide a secure patch or fix

Return structured JSON:

{{
  "vulnerabilities": [
    {{
      "type": "",
      "cwe": "",
      "cve": "",
      "description": "",
      "fix": ""
    }}
  ]
}}

Code:
{code}
"""

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama-3.3-70b-instruct",
        "messages": [
            {"role": "system", "content": "You are a secure code analysis engine."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    r = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=30)

    if r.status_code != 200:
        return {"error": "LLM request failed"}

    try:
        data = r.json()
        response_text = data["choices"][0]["message"]["content"]
        return json.loads(response_text)
    except Exception:
        return {"error": "Invalid response from LLM"}


