import os
import requests
import json
import logging
import re

logger = logging.getLogger(__name__)

# --- Environment Configuration ---
LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

def analyze_code(code, language):
    """
    Performs a Deep Security Audit using NVIDIA Nemotron via OpenRouter.
    Ensures strict JSON output for frontend compatibility.
    """
    if not code or len(code.strip()) < 10:
        return {
            "analysis": [{
                "name": "Policy Error", 
                "risk": "Insufficient code context for a meaningful security audit.", 
                "severity": "N/A", 
                "fix": "Provide a more complete code snippet."
            }]
        }

    # Strict System Prompt to force structured JSON output
    prompt = f"""You are an automated vulnerability scanner. 
Audit this {language} code for security flaws (e.g., SQL Injection, XSS, CSRF, insecure configuration).

IMPORTANT: You must output ONLY a valid JSON object. 
If no vulnerabilities are found, return a single entry in the list stating the code is clean.

Required JSON Structure:
{{
  "analysis": [
    {{
      "name": "vulnerability name",
      "severity": "score/10",
      "cwe": "CWE ID",
      "risk": "description of impact",
      "fix": "specific remediation"
    }}
  ]
}}

Code to Audit:
{code}"""

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a specialized security agent. Your output must be 100% valid JSON only. No prose, no markdown, no conversational text."},
            {"role": "user", "content": prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1 # Prevents "stuck" logic on complex syntax
    }

    try:
        r = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        content = data["choices"][0]["message"]["content"].strip()
        
        # Strip Markdown wrappers (JSON code blocks) if the LLM includes them
        if content.startswith("```"):
            content = re.sub(r'^```[a-z]*\n?|```$', '', content, flags=re.MULTILINE).strip()
            
        parsed_result = json.loads(content)

        # SANITY CHECK: Detect and fix empty or malformed model responses
        if not parsed_result.get("analysis") or not parsed_result["analysis"][0].get("name"):
            return {
                "analysis": [{
                    "name": "Audit Engine Verification Error",
                    "severity": "N/A",
                    "cwe": "N/A",
                    "risk": "The engine recognized the syntax but failed to populate the report keys correctly.",
                    "fix": "Re-run the scan or check the source code for unclosed string literals."
                }]
            }

        return parsed_result
        
    except Exception as e:
        logger.error(f"Secure API Link Failure: {e}")
        return {"error": "AI Audit Engine Unavailable. Check your OpenRouter API credits and connectivity."}
