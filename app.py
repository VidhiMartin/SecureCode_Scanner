import os
import re
import json
from flask import Flask, render_template, request, jsonify, redirect
from utils import analyze_code

import firebase_admin
from firebase_admin import credentials, auth

app = Flask(__name__)

# =========================
# Firebase Init (FIXED)
# =========================
firebase_key = os.getenv("FIREBASE_KEY")

if not firebase_admin._apps:
    if not firebase_key:
        raise Exception("FIREBASE_KEY not set in environment")

    cred = credentials.Certificate(json.loads(firebase_key))
    firebase_admin.initialize_app(cred)

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
    code = code.replace("\x00", "")
    return code

def get_current_user():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    try:
        token = auth_header.split(" ")[1]
        decoded = auth.verify_id_token(token)
        return decoded
    except Exception:
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

# ---------- SCAN ----------
@app.route("/scan", methods=["POST"])
def scan():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        language = request.form.get("language", "").lower()
        code = request.form.get("code", "")

        if language not in ALLOWED_LANGUAGES:
            return jsonify({"error": "Unsupported language"}), 400

        code = sanitize_input(code)
        result = analyze_code(code, language)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# Run
# =========================
if __name__ == "__main__":
    app.run()
