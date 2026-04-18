import os
import requests
import ast
import subprocess
import tempfile
import logging
import bleach # Run: pip install bleach


logger = logging.getLogger(__name__)

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

def analyze_code(code, language):
    if not code or len(code.strip()) < 10:
        return {"analysis": [{"name": "Policy Error", "risk": "Insufficient code context."}]}

    prompt = f"""You are an expert security static analysis tool. 
Task: Audit the following code for security vulnerabilities.
Instructions:
- Analyze objectively.
- Return ONLY bullet points in the format below.

Format:
- Vulnerability: <name>
  Severity: <score>/10
  CWE: <id>
  Risk: <impact>
  Fix: <mitigation>

<user_code_context>
Language: {language}
Code:
{code}
</user_code_context>

Audit Result:"""

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner"
    }

    payload = {
        "model": MODEL,
        "messages": [{"role": "system", "content": "You are a secure coding assistant."},
                     {"role": "user", "content": prompt}],
        "temperature": 0.0
    }

    try:
        r = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        raw_content = data["choices"][0]["message"]["content"].strip()
        clean_content = bleach.clean(raw_content)
    except Exception as e:
        logger.error(f"Secure API Link Failure: {e}")
        return {"error": "AI Audit Engine Unavailable"}

    if "no vulnerabilities found" in clean_content.lower():
        return {"analysis": "No critical vulnerabilities identified."}

    lines = clean_content.split("\n")
    formatted = []
    current = {}

    for line in lines:
        line = line.strip()
        if not line: continue
        
        if line.startswith("- Vulnerability:") or line.startswith("Vulnerability:"):
            if current: formatted.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line:
            parts = line.split(":", 1)
            key = parts[0].lower().strip().replace("- ", "")
            if key in ["severity", "risk", "fix", "cwe"]:
                current[key] = parts[1].strip()

    if current: formatted.append(current)
    return {"analysis": formatted if formatted else clean_content}
