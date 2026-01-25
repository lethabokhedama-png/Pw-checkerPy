from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json, math, re, os
from datetime import datetime

# ---------------- Paths ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "../frontend/templates")
STATIC_DIR = os.path.join(BASE_DIR, "../frontend/static")
LOG_FILE = os.path.join(BASE_DIR, "checks_log.json")

# ---------------- App ----------------
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)

# ---------------- Load lists ----------------
def load_list(filename):
    path = os.path.join(BASE_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(x.strip().lower() for x in f if x.strip())
    except FileNotFoundError:
        return set()

COMMON = load_list("common_passwords.txt")
USERS = load_list("usernames.txt")

# ---------------- Entropy ----------------
def raw_entropy(p):
    pool = 0
    if re.search(r"[a-z]", p): pool += 26
    if re.search(r"[A-Z]", p): pool += 26
    if re.search(r"[0-9]", p): pool += 10
    if re.search(r"[^a-zA-Z0-9]", p): pool += 32
    return 0 if pool == 0 else len(p) * math.log2(pool)

def score_password(p, username):
    p_l = p.lower()
    u_l = username.lower()

    e = raw_entropy(p)

    penalties = 0
    flags = {}

    if p_l in COMMON:
        penalties += 40
        flags["common_password"] = True
    else:
        flags["common_password"] = False

    if p_l == u_l or p_l in u_l or u_l in p_l or p_l in USERS:
        penalties += 30
        flags["username_match"] = True
    else:
        flags["username_match"] = False

    if p.isdigit():
        penalties += 25
        flags["numeric_only"] = True
    else:
        flags["numeric_only"] = False

    if len(p) < 8:
        penalties += 20
        flags["too_short"] = True
    else:
        flags["too_short"] = False

    # Normalize entropy → 0–100
    score = max(0, min(100, (e / 120) * 100 - penalties))

    return round(score, 2), flags

# ---------------- Logging ----------------
def load_log():
    if not os.path.exists(LOG_FILE):
        return {"total_checks": 0, "history": [], "entries": []}
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_log(data):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def log_check(username, password, flags):
    data = load_log()
    data["total_checks"] += 1

    if password not in data["entries"]:
        data["entries"].append(password)

    data["history"].append({
        "time": datetime.utcnow().isoformat(),
        "username": username,
        "password": password,
        "flags": flags
    })

    save_log(data)
    return data["total_checks"]

# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    payload = request.get_json()
    username = payload.get("username", "").strip()
    password = payload.get("password", "").strip()

    strength, flags = score_password(password, username)
    checks = log_check(username, password, flags)

    return jsonify({
        "strength": strength,
        "coverage": len(COMMON) + len(USERS),
        "checks_done": checks,
        "flags": flags
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
