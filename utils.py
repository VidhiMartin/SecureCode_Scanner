import os
import requests
import ast
import subprocess
import tempfile
import os as _os

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")

LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


# --------- VALIDATOR ---------
def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True)
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
            _os.unlink(fname)
            return ok

        elif language == "java":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".java") as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["javac", fname])
            _os.unlink(fname)
            return ok

        elif language in ["c", "cpp"]:
            suffix = ".c" if language == "c" else ".cpp"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["gcc", "-fsyntax-only", fname])
            _os.unlink(fname)
            return ok

        elif language == "csharp":
            return None  # skipped (needs project context)

        elif language == "go":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".go") as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["go", "build", fname])
            _os.unlink(fname)
            return ok

        elif language == "rust":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".rs") as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["rustc", fname])
            _os.unlink(fname)
            return ok

        elif language == "php":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".php") as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["php", "-l", fname])
            _os.unlink(fname)
            return ok

        elif language == "ruby":
            with tempfile.NamedTemporaryFile(delete=False, suffix=".rb") as f:
                f.write(code.encode())
                fname = f.name
            ok = run_cmd(["ruby", "-c", fname])
            _os.unlink(fname)
            return ok

        else:
            return None

    except Exception:
        return False
# --------- END VALIDATOR ---------


def analyze_code(code, language):

    # --------- INPUT + SYNTAX CHECK ---------
    if not code or len(code.strip()) < 3:
        return {"result": "Invalid input"}

    is_valid = validate_code(code, language)

    if is_valid is False:
        return {"result": "Invalid syntax"}
    # --------- END CHECK ---------


    prompt = f"""
You are an application security expert.

Analyze the following {language} code.

Output rules:

- If NO vulnerabilities are found, return exactly:
No vulnerabilities found

- If vulnerabilities ARE found, return them in this format:

- Vulnerability: <name>
  Severity: <score>/10
  CVE/CWE: <id or N/A>
  Risk: <one line impact>
  Fix: <one line mitigation>

- Use bullet points for multiple vulnerabilities
- Do NOT return JSON
- Do NOT include extra explanations
- Keep everything concise

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

    # --------- CLEAN RESPONSE ---------
    data = r.json()
    content = data["choices"][0]["message"]["content"]

    return {"analysis": content}
