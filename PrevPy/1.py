from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
import json, hashlib, math, re
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Path to backend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load lists
def load_list(filename):
    path = os.path.join(BASE_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(x.strip().lower() for x in f if x.strip())
    except FileNotFoundError:
        return set()

COMMON = load_list("common_passwords.txt")
USERS = load_list("usernames.txt")

# Entropy calculation
def entropy(p):
    s = 0
    if re.search(r"[a-z]", p): s += 26
    if re.search(r"[A-Z]", p): s += 26
    if re.search(r"[0-9]", p): s += 10
    if re.search(r"[^a-zA-Z0-9]", p): s += 32
    return 0 if s == 0 else round(len(p) * math.log2(s), 2)

# Log checks safely
def log_check(p, flags):
    log_path = os.path.join(BASE_DIR, "checks_log.json")
    try:
        with open(log_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {"total_checks": 0, "history": []}

    data["total_checks"] += 1
    data["history"].append({
        "hash": hashlib.sha256(p.encode()).hexdigest(),
        "time": datetime.utcnow().isoformat(),
        "flags": flags
    })

    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data["total_checks"]

# Serve frontend templates
FRONTEND_DIR = os.path.join(BASE_DIR, "../frontend")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# API endpoint
@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    p = data.get("password", "")
    flags = {
        "common_password": p.lower() in COMMON,
        "username_match": p.lower() in USERS
    }
    checks = log_check(p, flags)
    e = entropy(p)
    return jsonify({
        "entropy": e,
        "strength": min(int(e / 80 * 100), 100),
        "coverage": len(COMMON) + len(USERS),
        "checks_done": checks,
        "flags": flags
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
