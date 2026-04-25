import os
import json
import re
import logging
import pyotp
import qrcode
import io
import base64
from flask import Flask, render_template, request, jsonify, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import firebase_admin
from firebase_admin import credentials, auth, firestore
from utils import analyze_code

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

TENANT_ID = "Enterprise-Test-avvoo"
MAX_CODE_SIZE = 50000 

# --- Firebase Admin Initialization ---
firebase_key = os.getenv("FIREBASE_KEY")
db = None 

if not firebase_admin._apps:
    try:
        if firebase_key and firebase_key.strip().startswith('{'):
            cred_dict = json.loads(firebase_key)
            if "private_key" in cred_dict:
                cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
            cred = credentials.Certificate(cred_dict)
        else:
            cred = credentials.Certificate(firebase_key)
        firebase_admin.initialize_app(cred)
        # INITIALIZE FIRESTORE HERE
        db = firestore.client()
        logger.info("Firebase & Firestore Initialized Successfully")
    except Exception as e:
        logger.error(f"FATAL: Firebase Initialization Failed: {e}")

# --- MFA ROUTES ---

@app.route('/mfa/setup', methods=['POST'])
def mfa_setup():
    try:
        data = request.get_json()
        email = data.get("email")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        secret = pyotp.random_base32()
        db.collection("users").document(email).set({
            "mfa_secret": secret,
            "mfa_enabled": False
        }, merge=True)
        
        totp = pyotp.totp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name="SecureCodeScanner")
        
        img = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        
        return jsonify({"qr_code": qr_b64})
    except Exception as e:
        logger.error(f"MFA Setup Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    try:
        data = request.get_json()
        email = data.get("email")
        code = data.get("code")
        
        user_doc = db.collection("users").document(email).get()
        if not user_doc.exists:
            return jsonify({"success": False, "message": "User configuration missing"}), 404
        
        secret = user_doc.to_dict().get("mfa_secret")
        totp = pyotp.TOTP(secret)
        
        if totp.verify(code):
            db.collection("users").document(email).update({"mfa_enabled": True})
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "Invalid code"}), 401
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/mfa/status', methods=['POST'])
def mfa_status():
    try:
        data = request.get_json()
        email = data.get("email")
        user_doc = db.collection("users").document(email).get()
        if user_doc.exists and user_doc.to_dict().get("mfa_enabled"):
            return jsonify({"enabled": True})
        return jsonify({"enabled": False})
    except:
        return jsonify({"enabled": False})

# --- SCANNER LOGIC (KEPT INTACT) ---

def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ")[1]
        decoded = auth.verify_id_token(token, check_revoked=False)
        if decoded.get('firebase', {}).get('tenant') != TENANT_ID:
            return None
        return decoded
    except Exception as e:
        return None

def validate_language_match(code, lang):
    code_lower = code.lower()
    if lang == "python":
        if "const " in code_lower or "let " in code_lower or "console.log" in code_lower:
            return False, "Snippet appears to be JavaScript/TypeScript, but environment is Python."
    if lang in ["javascript", "typescript"]:
        if "def " in code_lower and ":" in code_lower:
            return False, "Snippet appears to be Python, but environment is set to JavaScript/TypeScript."
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
    try:
        user = get_current_user()
        if not user:
            return jsonify({"status": "REJECTED", "error_code": "AUTH_FAILURE"}), 401
        language = request.form.get("language", "").lower()
        code = request.form.get("code", "")
        if len(code) > MAX_CODE_SIZE:
            return jsonify({"status": "REJECTED", "error_code": "SIZE_EXCEEDED"}), 413
        is_match, msg = validate_language_match(code, language)
        if not is_match:
            return jsonify({"status": "REJECTED", "error_code": "LANGUAGE_MISMATCH", "audit_summary": msg}), 422
        result = analyze_code(code, language)
        return jsonify(result)
    except Exception as e:
        logger.error(f"CRITICAL ROUTE FAULT: {e}")
        return jsonify({"status": "FAULT", "error_code": "SERVER_ERROR"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
