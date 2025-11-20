from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
from datetime import datetime
import csv
import os
import time

# Import detection and prevention logic
from detector import detect_attack
from preventer import apply_prevention

app = Flask(__name__)
# Enable CORS for the frontend, though Flask serves it directly, this is good practice
CORS(app)

# --- Configuration ---
LOG_FILE = "logs/requests.csv" # Stores all incoming traffic
ALERTS = "logs/alerts.log"  # Stores high-value events (logins, form posts)
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "honeypot-frontend")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")

# Ensure logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# --------------------- LOG FUNCTION ---------------------
def log_request(ip, path, method, ua, query, attack_type, status_code=200):
    """Appends all request data to the CSV log file."""
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf8") as f:
            writer = csv.writer(f)
            # Write header if file is empty
            if f.tell() == 0:
                writer.writerow(["timestamp", "ip", "method", "path", "ua", "query", "attack_type", "status"])
            writer.writerow([
                datetime.now().isoformat(), 
                ip, 
                method, 
                path, 
                ua, 
                str(query), 
                attack_type, 
                status_code
            ])
    except Exception as e:
        print(f"Error writing to CSV log: {e}")

# --------------------- BEFORE REQUEST (Active Defense) -------------------
@app.before_request
def process_request():
    """
    Runs before processing any route. Detects attacks and applies prevention (tarpitting/blocking).
    """
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "N/A")
    path = request.path
    query = dict(request.args)

    # 1. Detect attack type
    attack_type = detect_attack(path, ua, query, request)

    # 2. Apply prevention (temp ban, blacklist, tarpit)
    blocked = apply_prevention(ip, attack_type)

    # 3. Log the request (this happens regardless of the block status)
    # We will log the block status later if needed, but for before_request, we log the intent
    log_request(ip, path, request.method, ua, query, attack_type)

    if blocked:
        # If blocked, abort with 403 (Forbidden)
        log_request(ip, path, request.method, ua, query, attack_type, status_code=403)
        abort(403)

# --------------------- ROUTES (Frontend Serving) ---------------------------

@app.route('/')
def index():
    """Serves the main index.html file of the React application."""
    try:
        return send_from_directory(FRONTEND_DIR, "index.html")
    except FileNotFoundError:
        return "Honeypot frontend files not found. Ensure the React build is in the 'honeypot-frontend' directory.", 500

@app.route('/<path:path>')
def files(path):
    """Serves all other static files (JS, CSS, etc.) from the React application."""
    try:
        return send_from_directory(FRONTEND_DIR, path)
    except FileNotFoundError:
        abort(404) # Return 404 for any requested file that does not exist

# --------------------- LOGGING ENDPOINT (Credential Catcher) ---------------------------

@app.route('/log', methods=["POST"])
def log_event():
    """
    Receives and logs high-value events (credentials, specific pageviews) from the frontend.
    """
    if not request.is_json:
        # Basic validation
        return jsonify({"status": "error", "message": "Invalid content type"}), 400

    data = request.json
    ip = request.remote_addr

    # Write the high-value event data to the alerts log for security review
    with open(ALERTS, "a") as f:
        f.write(f"[{datetime.now()}] IP: {ip} | EVENT: {data}\n")
        
    # Crucially, we always return "ok" even if the data is fake, so the frontend continues
    return jsonify({"status": "ok"})

# ---------------------------------------------------------
if __name__ == "__main__":
    # Flask is configured to run on port 5000, matching the React client's default expectation.
    print(f"Starting Honeypot Server on http://0.0.0.0:5000")
    print(f"Frontend Directory: {FRONTEND_DIR}")
    app.run(host="0.0.0.0", port=5000)