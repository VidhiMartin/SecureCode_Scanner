import os
import requests
import ast
import subprocess
import tempfile
import logging

logger = logging.getLogger(__name__)

# Checks both possible variable names
LLM_API_KEY = os.getenv("OPENROUTER_API_KEY") or os.getenv("LLM_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return None

def validate_code(code, language):
    try:
        language = language.lower()
        if language == "python":
            ast.parse(code)
            return True
        elif language in ["javascript", "typescript"]:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".js") as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["node", "--check", fname])
            os.unlink(fname)
            return ok
        return None 
    except Exception:
        return False

def analyze_code(code, language):
    if not code or len(code.strip()) < 3:
        return {"analysis": [{"name": "Error", "risk": "Code snippet too short."}]}

    is_valid = validate_code(code, language)
    if is_valid is False:
         return {"analysis": [{"name": "Syntax Warning", "risk": "Invalid syntax detected.", "severity": "Low"}]}

    prompt = f"""Analyze this {language} code for security vulnerabilities.
Return ONLY bullet points in this format:
- Vulnerability: <name>
  Severity: <score>/10
  CVE/CWE: <id>
  Risk: <impact>
  Fix: <mitigation>

If none, return: No vulnerabilities found.

Code:
{code}"""

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        # Updated to your actual Vercel domain
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Secure Code Scanner"
    }

    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1
    }

    try:
        r = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=25)
        r.raise_for_status()
        data = r.json()
        content = data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.error(f"API Request Failed: {e}")
        return {"error": "AI Engine unavailable", "details": str(e)}

    if "no vulnerabilities found" in content.lower():
        return {"analysis": "No vulnerabilities found"}

    lines = content.split("\n")
    formatted = []
    current = {}

    for line in lines:
        line = line.strip()
        if not line: continue
        
        if line.startswith("- Vulnerability:") or line.startswith("Vulnerability:"):
            if current: formatted.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line:
            key, val = line.split(":", 1)
            key = key.lower().strip().replace("- ", "")
            if key in ["severity", "risk", "fix"] or "cwe" in key:
                current[key if "cwe" not in key else "cwe"] = val.strip()

    if current: formatted.append(current)
    return {"analysis": formatted if formatted else content}
