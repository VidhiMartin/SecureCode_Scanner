import os
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import analyze_code

import firebase_admin
from firebase_admin import credentials, auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# =========================
# Enterprise Rate Limiting
# =========================
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    strategy="fixed-window"
)

# =========================
# Firebase Init (Vercel Fixed)
# =========================
firebase_key = os.getenv("FIREBASE_KEY")
TENANT_ID = "Enterprise-Test-avvoo"

if not firebase_admin._apps:
    try:
        if not firebase_key:
            logger.error("CRITICAL: FIREBASE_KEY missing.")
        else:
            if firebase_key.strip().startswith('{'):
                cred_dict = json.loads(firebase_key)
                if "private_key" in cred_dict:
                    cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
                cred = credentials.Certificate(cred_dict)
            else:
                cred = credentials.Certificate(firebase_key)
            
            firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin initialized successfully.")
    except Exception as e:
        logger.error(f"Firebase Init Failed: {str(e)}")

# =========================
# Security Settings
# =========================
MAX_CODE_LENGTH = 50000 
ALLOWED_LANGUAGES = {
    "python", "javascript", "java", "c", "cpp",
    "csharp", "go", "rust", "php", "ruby", "typescript"
}

def sanitize_input(code):
    if not code:
        return ""
    code = code.strip()
    if len(code) > MAX_CODE_LENGTH:
        raise ValueError("Payload too large. Max 50KB.")
    code = code.replace("\x00", "")
    for line in code.splitlines():
        if len(line) > 2000:
            raise ValueError("Extreme line length detected.")
    return code

def get_current_user():
    # Fix: Ensure case-insensitive header access
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ")[1]
        decoded = auth.verify_id_token(token)
        
        # MULTI-TENANCY ENFORCEMENT
        token_tenant = decoded.get('firebase', {}).get('tenant')
        if token_tenant != TENANT_ID:
            logger.warning(f"Tenant Isolation Violation: Received {token_tenant}, expected {TENANT_ID}")
            return None
            
        return decoded
    except Exception as e:
        logger.warning(f"Auth Shield: Token Rejected - {str(e)}")
        return None

# =========================
# Routes
# =========================
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
        return jsonify({"error": "Unauthorized Access Detected"}), 401

    try:
        language = request.form.get("language", "").lower()
        code = request.form.get("code", "")

        if language not in ALLOWED_LANGUAGES:
            return jsonify({"error": "Unsupported Language Profile"}), 400

        clean_code = sanitize_input(code)
        logger.info(f"Scan initiated by {user.get('uid')} for {language}")
        
        result = analyze_code(clean_code, language)
        return jsonify(result)

    except ValueError as ve:
        return jsonify({"error": "Security Restriction", "details": str(ve)}), 403
    except Exception as e:
        logger.error(f"System Fault: {str(e)}")
        return jsonify({"error": "Internal System Failure", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)
