import os
import requests
import json
import logging
import re

logger = logging.getLogger(__name__)

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

def analyze_code(code, language):
    if not code or len(code.strip()) < 10:
        return {"analysis": [{"name": "Policy Error", "risk": "Insufficient code context.", "severity": "N/A", "fix": "Add more code."}]}

    prompt = f"""You are an expert security static analysis tool. 
Task: Audit the following code for security vulnerabilities.
Instructions: Return ONLY a JSON object with a key "analysis" containing a list of vulnerability objects.

Each object must follow this structure:
{{
  "name": "vulnerability name",
  "severity": "score/10",
  "cwe": "CWE ID",
  "risk": "impact description",
  "fix": "mitigation steps"
}}

<user_code_context>
Language: {language}
Code:
{code}
</user_code_context>"""

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a secure coding assistant that only outputs valid JSON."},
            {"role": "user", "content": prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.0
    }

    try:
        r = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        content = data["choices"][0]["message"]["content"].strip()
        
        # FIX: Strip Markdown wrappers if the LLM includes them
        if content.startswith("```"):
            content = re.sub(r'^```[a-z]*\n?|```$', '', content, flags=re.MULTILINE).strip()
            
        return json.loads(content)
        
    except Exception as e:
        logger.error(f"Secure API Link Failure: {e}")
        return {"error": "AI Audit Engine Unavailable"}
