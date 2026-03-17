import os
import requests
import ast
import subprocess
import tempfile
import os as _os  # avoid conflict

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")

LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


# --------- ADDED: validator ---------
def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True)
        return result.returncode == 0
    except Exception:
        return None  # tool missing


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
            return None  # skip (requires project context)

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
# --------- END ADDED ---------


def analyze_code(code, language):

    # --------- ADDED: input + syntax checks ---------
    if not code or len(code.strip()) < 3:
        return {"result": "Invalid input"}

    is_valid = validate_code(code, language)

    if is_valid is False:
        return {"result": "Invalid syntax"}
    # --------- END ADDED ---------


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
- explanation (in one line)

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

    # --------- CHANGED: clean response ---------
    data = r.json()
    content = data["choices"][0]["message"]["content"]

    return {"analysis": content}
    # --------- END CHANGE ---------
