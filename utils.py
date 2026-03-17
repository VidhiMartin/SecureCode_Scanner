import os
import requests

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")

LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "mistralai/mistral-7b-instruct"


def analyze_code(code, language):

    prompt = f"""
You are an application security expert.

Analyze the following {language} code.

Tasks:
1. Identify vulnerabilities - concisely
2. Reference CVE if known
3. Reference CWE categories if known
4. Explain risk - in 1 concise line
5. Provide secure patched code - concisely
6. Provide mitigation advice - concise

Return JSON with:
- vulnerabilities
- cwe
- possible_cve
- risk
- patch
- explanation

Code:
{code}
"""

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:5000",
        "X-Title": "Secure Code Scanner"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are an expert security auditor."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    r = requests.post(LLM_ENDPOINT, headers=headers, json=payload)

    if r.status_code != 200:
        return {
            "error": f"LLM API error {r.status_code}",
            "details": r.text
        }

    return {"analysis": r.json()}
