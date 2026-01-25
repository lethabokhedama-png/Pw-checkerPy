from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json, math, re
from datetime import datetime
import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "../frontend/templates")
STATIC_DIR = os.path.join(BASE_DIR, "../frontend/static")

# Create Flask app
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)

# Load password and username lists
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

# ---------------- Debug log_check ----------------
LOG_FILE = os.path.join(BASE_DIR, "checks_log.json")

def load_log():
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        return {"total_checks": 0, "history": [], "entries": []}
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Ensure proper structure
    if not isinstance(data, dict):
        data = {"total_checks": 0, "history": [], "entries": []}
    if "total_checks" not in data:
        data["total_checks"] = 0
    if "history" not in data:
        data["history"] = []
    if "entries" not in data:
        data["entries"] = []
    # Make entries unique
    data["entries"] = list(dict.fromkeys(data["entries"]))
    return data

def log_check(password, flags):
    data = load_log()
    data["total_checks"] += 1
    entry = {
        "time": datetime.utcnow().isoformat(),
        "password": password,  # raw password for debug
        "username": password if password.lower() in USERS else None,
        "flags": flags
    }
    data["history"].append(entry)

    # Add to entries only if not already there
    if password not in data["entries"]:
        data["entries"].append(password)

    # Console debug
    print(f"[DEBUG] {entry}")

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    return data["total_checks"]
# --------------------------------------------------

# Routes
@app.route("/")
def index():
    return render_template("index.html")

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
    app.run(host="0.0.0.0", port=8000)