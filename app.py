import os
import re
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect
from utils import analyze_code

import firebase_admin
from firebase_admin import credentials, auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# =========================
# Firebase Init (Vercel Fixed)
# =========================
firebase_key = os.getenv("FIREBASE_KEY")

if not firebase_admin._apps:
    try:
        if not firebase_key:
            logger.error("FIREBASE_KEY environment variable is missing!")
        else:
            if firebase_key.startswith('{'):
                cred_dict = json.loads(firebase_key)
                # CRITICAL: Fix Vercel's newline mangling in the private key
                if "private_key" in cred_dict:
                    cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
                cred = credentials.Certificate(cred_dict)
            else:
                cred = credentials.Certificate(firebase_key)
            if "private_key" in cred_dict:
                cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
                
            firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {e}")

# =========================
# Security settings
# =========================
MAX_CODE_LENGTH = 40000
ALLOWED_LANGUAGES = {
    "python", "javascript", "java", "c", "cpp",
    "csharp", "go", "rust", "php", "ruby", "typescript"
}

# =========================
# Helpers
# =========================
def sanitize_input(code):
    code = code.strip()
    if len(code) > MAX_CODE_LENGTH:
        raise ValueError("Code exceeds allowed size.")
    return code.replace("\x00", "")

def get_current_user():
    # Retrieve header (Vercel sometimes lowercases this to 'authorization')
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("No valid Bearer token in headers.")
        return None

    try:
        token = auth_header.split(" ")[1]
        decoded = auth.verify_id_token(token)
        return decoded
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
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
def login():
    return render_template("login.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/scan", methods=["POST"])
def scan():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized. Please log in again."}), 401

    try:
        language = request.form.get("language", "").lower()
        code = request.form.get("code", "")

        if language not in ALLOWED_LANGUAGES:
            return jsonify({"error": f"Language '{language}' not supported."}), 400

        code = sanitize_input(code)
        result = analyze_code(code, language)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute") # Specific limit for bruteforce protection
def login():

if __name__ == "__main__":
    app.run(debug=True)
