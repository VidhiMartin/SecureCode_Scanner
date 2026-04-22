import os
import json
import re
import logging
from flask import Flask, render_template, request, jsonify, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import firebase_admin
from firebase_admin import credentials, auth

# Configuration & Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Rate Limiter: 100 requests/hour per IP
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

# Enterprise Constants
TENANT_ID = "Enterprise-Test-avvoo"
MAX_CODE_SIZE = 50000  # 50KB character limit
MALICIOUS_PATTERNS = [
    r"os\.system\(", r"subprocess\.", r"eval\(", r"exec\(", 
    r"socket\.", r"__import__", r"getattr\(", r"chmod"
]

# Firebase Admin Setup
firebase_key = os.getenv("FIREBASE_KEY")
if not firebase_admin._apps:
    try:
        if firebase_key.strip().startswith('{'):
            cred_dict = json.loads(firebase_key)
            if "private_key" in cred_dict:
                cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
            cred = credentials.Certificate(cred_dict)
        else:
            cred = credentials.Certificate(firebase_key)
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Security Environment Initialized")
    except Exception as e:
        logger.error(f"Security Initialization Failed: {e}")

def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ")[1]
        decoded = auth.verify_id_token(token, check_revoked=False)
        if decoded.get('firebase', {}).get('tenant') != TENANT_ID:
            logger.warning("Unauthorized Tenant Access Attempt")
            return None
        return decoded
    except Exception as e:
        logger.error(f"JWT Verification Failed: {e}")
        return None

def validate_language_match(code, lang):
    """Basic heuristic to detect language mismatch."""
    code = code.lower()
    if lang == "python":
        if "function " in code or "var " in code or "const " in code:
            return False, "Snippet appears to be JavaScript/TypeScript, but environment is Python."
    if lang in ["javascript", "typescript"]:
        if "def " in code and ":" in code:
            return False, "Snippet appears to be Python, but environment is JS/TS."
    if lang == "java":
        if "public class" not in code and "System.out" not in code:
            # More of a warning, but for enterprise we enforce structure
            pass
    return True, ""

@app.route("/")
def home():
    return redirect("/scanner")

@app.route("/scanner")
def scanner():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan():
    user = get_current_user()
    if not user:
        return jsonify({"error": "AUTH_FAILURE", "message": "Invalid or expired security token."}), 401

    language = request.form.get("language", "").lower()
    code = request.form.get("code", "")

    # 1. Size Validation
    if len(code) > MAX_CODE_SIZE:
        return jsonify({"error": "SIZE_EXCEEDED", "message": f"Payload too large (Max: {MAX_CODE_SIZE} chars)."}), 413

    # 2. Malicious Input Detection
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            logger.error(f"MALICIOUS_INPUT DETECTED from {user['email']}")
            return jsonify({"error": "MALICIOUS_INPUT", "message": "Prohibited system-level patterns detected."}), 403

    # 3. Language Mismatch
    is_match, msg = validate_language_match(code, language)
    if not is_match:
        return jsonify({"error": "LANGUAGE_MISMATCH", "message": msg}), 422

    if not code.strip():
        return jsonify({"error": "EMPTY_INPUT", "message": "No code provided."}), 400

    try:
        # This represents your actual LLM analysis logic
        from utils import analyze_code 
        result = analyze_code(code, language)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Audit Engine Error: {e}")
        return jsonify({"error": "ENGINE_FAULT", "message": "Internal analysis error."}), 500

if __name__ == "__main__":
    app.run(debug=True)
