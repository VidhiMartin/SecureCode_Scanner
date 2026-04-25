import os
import requests
import json
import logging
import re
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Environment Configuration ---
LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

def analyze_code(code: str, language: str) -> Dict[str, Any]:
    """
    Performs a Deep Security Audit. 
    Returns a clean, flat JSON object for the detected vulnerability.
    """
    
    # 1. Injection Prevention
    sanitized_code = code.replace("</code_to_audit>", "[TAG_ESCAPED]")

    # 2. Hardened Prompt 
    # We removed the "analysis" wrapper and the list brackets [] from the schema.
    prompt = f"""[SYSTEM MANDATE]
1. You are a Static Analysis Security Engine.
2. If the code contradicts the language "{language}", return: {{"error_code": "LANGUAGE_MISMATCH"}}
3. Audit the code and return ONLY ONE flat JSON object representing the most severe vulnerability.
4. DO NOT include "status", "analysis" keys, or square brackets.

<code_to_audit>
Language: {language}
Content:
{sanitized_code}
</code_to_audit>

Expected Schema (Output this format exactly):
{{
  "name": "vulnerability name",
  "severity": "score/10",
  "cwe": "CWE ID",
  "vulnerable_code": "the exact line of code from the input",
  "risk": "concise one line impact description",
  "fix": "concise one line mitigation step"
}}"""

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system", 
                "content": "You are a security backend. You only return a single flat JSON object. No wrappers, no status, no arrays."
            },
            {
                "role": "user", 
                "content": "Audit: eval(user_input)" 
            },
            {
                "role": "assistant", 
                "content": json.dumps({
                    "name": "Arbitrary Code Execution",
                    "severity": "10/10",
                    "cwe": "CWE-94",
                    "vulnerable_code": "eval(user_input)",
                    "risk": "Allows execution of malicious scripts.",
                    "fix": "Avoid dynamic execution."
                })
            },
            {"role": "user", "content": prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1
    }

    try:
        response = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=45)
        response.raise_for_status()
        
        raw_content = response.json()["choices"][0]["message"]["content"].strip()
        
        match = re.search(r'(\{.*\})', raw_content, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        else:
            raise ValueError("Invalid AI Response Format")

    except Exception as e:
        logger.error(f"Analysis Engine Error: {type(e).__name__}")
        return {
            "error_code": "AI_ENGINE_OFFLINE",
            "details": str(e)
        }
