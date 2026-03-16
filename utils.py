import os
import requests

LLM_API_KEY = os.getenv("LLM_API_KEY")

LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "llama-3.3-70b-instruct"


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
6. Provide mitigation/patch advice - concisely no fluff. 

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
    "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
    "Content-Type": "application/json"
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

    return {"analysis": r.json()}
