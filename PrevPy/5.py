from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json, math, re, os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "../frontend/templates")
STATIC_DIR = os.path.join(BASE_DIR, "../frontend/static")
LOG_FILE = os.path.join(BASE_DIR, "checks_log.json")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)

def load_list(name):
    try:
        with open(os.path.join(BASE_DIR, name), "r", encoding="utf-8") as f:
            return set(x.strip().lower() for x in f if x.strip())
    except FileNotFoundError:
        return set()

COMMON = load_list("common_passwords.txt")
USERS = load_list("usernames.txt")

def raw_entropy(p):
    pool = 0
    if re.search(r"[a-z]", p): pool += 26
    if re.search(r"[A-Z]", p): pool += 26
    if re.search(r"[0-9]", p): pool += 10
    if re.search(r"[^a-zA-Z0-9]", p): pool += 32
    return 0 if pool == 0 else len(p) * math.log2(pool)

def strength_score(password, flags):
    score = min(raw_entropy(password), 100)

    if flags["common_password"]:
        score = 5
    if password.isdigit():
        score -= 30
    if re.search(r"(123|abc|qwerty)", password.lower()):
        score -= 30
    if flags["password_is_username"]:
        score = 0

    return max(0, min(round(score, 2), 100))

def load_log():
    if not os.path.exists(LOG_FILE):
        return {"total_checks": 0, "history": []}
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_log(data):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def log_check(username, password, flags):
    data = load_log()
    data["total_checks"] += 1
    data["history"].append({
        "time": datetime.utcnow().isoformat(),
        "username": username,
        "password": password,
        "flags": flags
    })
    save_log(data)
    return data["total_checks"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    d = request.get_json()
    username = d.get("username", "").strip().lower()
    password = d.get("password", "").strip()

    flags = {
        "username_exists": username in USERS,
        "password_is_username": password.lower() in USERS,
        "common_password": password.lower() in COMMON
    }

    score = strength_score(password, flags)
    checks = log_check(username, password, flags)

    return jsonify({
        "strength": score,
        "checks_done": checks,
        "flags": flags
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)