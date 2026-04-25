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
    Synchronized with app.py to provide consistent error structures without 'status' fields.
    """
    
    # 1. Injection Prevention: Sanitize code to prevent escaping the XML tags
    sanitized_code = code.replace("</code_to_audit>", "[TAG_ESCAPED]")

    # 2. Hardened Prompt 
    # Removed "status" requirement and added "vulnerable_code" field
    prompt = f"""[SYSTEM MANDATE]
1. You are a Static Analysis Security Engine.
2. If the code content clearly contradicts the specified language "{language}", 
   return: {{"error_code": "LANGUAGE_MISMATCH"}}
3. Otherwise, audit the code for vulnerabilities.
4. Output ONLY valid JSON containing an "analysis" array. DO NOT include a "status" field.

<code_to_audit>
Language: {language}
Content:
{sanitized_code}
</code_to_audit>

Expected Schema:
{{
  "analysis": [
    {{
      "name": "vulnerability name",
      "severity": "score/10",
      "cwe": "CWE ID",
      "vulnerable_code": "exact snippet or line of code from the input that is risky",
      "risk": "impact description",
      "fix": "mitigation steps"
    }}
  ]
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
                "content": "You are a security backend. You only return JSON with an 'analysis' key. Do not include a 'status' field in your response."
            },
            # Updated Few-Shot example to anchor the new response format
            {
                "role": "user", 
                "content": "Audit this (Language: python): eval(user_input)" 
            },
            {
                "role": "assistant", 
                "content": json.dumps({
                    "analysis": [{
                        "name": "Arbitrary Code Execution",
                        "severity": "10/10",
                        "cwe": "CWE-94",
                        "vulnerable_code": "eval(user_input)",
                        "risk": "Use of eval() allows execution of malicious scripts.",
                        "fix": "Use literal_eval or avoid dynamic execution."
                    }]
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
        
        # Robust JSON extraction using Regex
        match = re.search(r'(\{.*\})', raw_content, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        else:
            raise ValueError("Invalid AI Response Format")

    except requests.exceptions.Timeout:
        return {
            "error_code": "TIMEOUT",
            "audit_summary": "The security engine timed out."
        }
    except Exception as e:
        logger.error(f"Analysis Engine Error: {type(e).__name__}")
        return {
            "error_code": "AI_ENGINE_OFFLINE",
            "audit_summary": f"The AI service is currently unavailable: {str(e)}"
        }
