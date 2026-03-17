import os
import re
from flask import Flask, render_template, request, jsonify, session, redirect, flash
from supabase import create_client
from utils import analyze_code

app = Flask(__name__)

# =========================
# Config / Initialization
# =========================
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

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


def is_strong_password(password):
    return re.match(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$',
        password
    )


def is_valid_email(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)


def login_required():
    return "user" in session

# =========================
# Routes
# =========================
@app.route("/")
def home():
    if not login_required():
        return redirect("/login")
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not is_valid_email(email):
            flash("Invalid email format")
            return redirect("/login")

        try:
            res = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            if res.user:
                session["user"] = res.user.id
                return redirect("/")
            else:
                flash("Invalid credentials")

        except Exception as e:
            flash(str(e))

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not is_valid_email(email):
            flash("Invalid email format")
            return redirect("/signup")

        if not is_strong_password(password):
            flash("Password must be 8+ chars with upper, lower, number, special char")
            return redirect("/signup")

        try:
            res = supabase.auth.sign_up({
                "email": email,
                "password": password
            })

            flash("Check your email to verify your account")
            return redirect("/login")

        except Exception as e:
            flash(str(e))

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


@app.route("/scan", methods=["POST"])
def scan():
    if not login_required():
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
