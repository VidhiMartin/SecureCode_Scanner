import os
import re
from flask import Flask, render_template, request, jsonify
from utils import analyze_code

app = Flask(__name__)

# Security settings
MAX_CODE_LENGTH = 20000
ALLOWED_LANGUAGES = {
    "python", "javascript", "java", "c", "cpp",
    "csharp", "go", "rust", "php", "ruby", "typescript"
}

def sanitize_input(code):
    code = code.strip()

    # prevent extremely long payloads
    if len(code) > MAX_CODE_LENGTH:
        raise ValueError("Code exceeds allowed size.")

    # remove null bytes
    code = code.replace("\x00", "")

    return code


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
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


if __name__ == "__main__":
    app.run()
