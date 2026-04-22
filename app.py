import os
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import analyze_code

import firebase_admin
from firebase_admin import credentials, auth

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

TENANT_ID = "Enterprise-Test-avvoo"
firebase_key = os.getenv("FIREBASE_KEY")

if not firebase_admin._apps:
    try:
        if firebase_key:
            if firebase_key.strip().startswith('{'):
                cred_dict = json.loads(firebase_key)
                if "private_key" in cred_dict:
                    cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
                cred = credentials.Certificate(cred_dict)
            else:
                cred = credentials.Certificate(firebase_key)
            firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin initialized.")
    except Exception as e:
        logger.error(f"Firebase Init Failed: {e}")

def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ")[1]
        # Ensure we check the tenant ID specifically
        decoded = auth.verify_id_token(token, check_revoked=True)
        if decoded.get('firebase', {}).get('tenant') != TENANT_ID:
            logger.warning("Tenant Mismatch")
            return None
        return decoded
    except Exception as e:
        logger.warning(f"Auth Rejected: {e}")
        return None

@app.route("/")
def home(): return redirect("/scanner")

@app.route("/scanner")
def scanner(): return render_template("index.html")

@app.route("/login")
def login_page(): return render_template("login.html")

@app.route("/signup")
def signup_page(): return render_template("signup.html")

@app.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    language = request.form.get("language", "").lower()
    code = request.form.get("code", "")
    
    if not code:
        return jsonify({"error": "Empty payload"}), 400

    try:
        result = analyze_code(code, language)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "System Fault", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
