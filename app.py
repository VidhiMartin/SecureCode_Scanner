import os
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import firebase_admin
from firebase_admin import credentials, auth

# Initialize Logging to see why the 401 is happening in your terminal
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Constants
TENANT_ID = "Enterprise-Test-avvoo"

# Firebase Initialization
firebase_key = os.getenv("FIREBASE_KEY")
if not firebase_admin._apps:
    try:
        # Handle both stringified JSON and file paths
        if firebase_key.strip().startswith('{'):
            cred_dict = json.loads(firebase_key)
            # Fix newline issues in private keys
            if "private_key" in cred_dict:
                cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
            cred = credentials.Certificate(cred_dict)
        else:
            cred = credentials.Certificate(firebase_key)
        
        # Initialize without a fixed tenant to allow the verify_id_token to find it
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin Auth Initialized Successfully")
    except Exception as e:
        logger.error(f"FATAL: Firebase Init Failed: {e}")

def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("Auth Failure: Missing or malformed Bearer header")
        return None
    
    try:
        token = auth_header.split(" ")[1]
        
        # 1. Verify the token. 
        # We set check_revoked=False to eliminate the 400ms lag you're seeing.
        decoded_token = auth.verify_id_token(token, check_revoked=False)
        
        # 2. Inspect the Tenant ID in the payload
        # In Identity Platform, the tenant ID is nested in the 'firebase' claim
        token_tenant = decoded_token.get('firebase', {}).get('tenant')
        
        if token_tenant != TENANT_ID:
            logger.error(f"SECURITY ALERT: Tenant Mismatch. Expected {TENANT_ID}, got {token_tenant}")
            return None
            
        return decoded_token
    except Exception as e:
        logger.error(f"Token Verification Failed: {str(e)}")
        return None

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
def scan():
    user = get_current_user()
    if not user:
        # This is where your 401 is coming from
        return jsonify({"error": "Unauthorized: Invalid Security Token"}), 401

    language = request.form.get("language", "python")
    code = request.form.get("code", "")

    if not code:
        return jsonify({"error": "No code provided for analysis"}), 400

    # Logic for your scanner would go here
    return jsonify({
        "status": "success",
        "user": user['email'],
        "analysis": "No critical vulnerabilities found in the provided snippet."
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
