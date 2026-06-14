"""
PassCheck — Password Strength Analyser
Backend: Flask + CORS
"""

from __future__ import annotations

import json
import math
import os
import re
from datetime import datetime, timezone
from typing import TypedDict

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# ─── Paths ───────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "../frontend/templates")
STATIC_DIR = os.path.join(BASE_DIR, "../frontend/static")
LOG_FILE = os.path.join(BASE_DIR, "checks_log.json")

# ─── App ─────────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)

# ─── Word lists ──────────────────────────────────────────────────────────────

def _load_word_list(filename: str) -> frozenset[str]:
    """Load a newline-delimited word list, returning a frozen lowercase set."""
    path = os.path.join(BASE_DIR, filename)
    try:
        with open(path, encoding="utf-8") as f:
            return frozenset(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return frozenset()


COMMON_PASSWORDS: frozenset[str] = _load_word_list("common_passwords.txt")
KNOWN_USERNAMES: frozenset[str] = _load_word_list("usernames.txt")

# ─── Types ───────────────────────────────────────────────────────────────────

class PasswordFlags(TypedDict):
    common_password: bool
    username_match: bool
    numeric_only: bool
    too_short: bool
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool

class ScoreResult(TypedDict):
    strength: float
    label: str
    flags: PasswordFlags
    entropy: float

# ─── Scoring ─────────────────────────────────────────────────────────────────

_MAX_ENTROPY = 120.0   # bits — full-random 20-char alphanumeric+symbol string


def _character_pool(password: str) -> int:
    """Return the size of the character pool used by *password*."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    return pool


def _raw_entropy(password: str) -> float:
    pool = _character_pool(password)
    return 0.0 if pool == 0 else len(password) * math.log2(pool)


def _strength_label(score: float) -> str:
    if score >= 80:
        return "Strong"
    if score >= 55:
        return "Moderate"
    if score >= 30:
        return "Weak"
    return "Very Weak"


def analyse_password(password: str, username: str) -> ScoreResult:
    """
    Return a strength score (0–100) and a dict of boolean flags.

    Penalties are applied for common patterns, username overlap, numeric-only
    passwords, and passwords shorter than 8 characters.
    """
    p_lower = password.lower()
    u_lower = username.lower()

    entropy = _raw_entropy(password)

    # ── Flags ────────────────────────────────────────────────────────────────
    flags: PasswordFlags = {
        "common_password": p_lower in COMMON_PASSWORDS,
        "username_match": bool(
            u_lower and (p_lower == u_lower or u_lower in p_lower or p_lower in u_lower)
        ) or p_lower in KNOWN_USERNAMES,
        "numeric_only": password.isdigit(),
        "too_short": len(password) < 8,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }

    # ── Penalties ────────────────────────────────────────────────────────────
    penalty = 0
    if flags["common_password"]:
        penalty += 40
    if flags["username_match"]:
        penalty += 30
    if flags["numeric_only"]:
        penalty += 25
    if flags["too_short"]:
        penalty += 20

    # ── Normalise to 0–100 ───────────────────────────────────────────────────
    raw_score = (entropy / _MAX_ENTROPY) * 100 - penalty
    strength = round(max(0.0, min(100.0, raw_score)), 2)

    return ScoreResult(
        strength=strength,
        label=_strength_label(strength),
        flags=flags,
        entropy=round(entropy, 2),
    )

# ─── Log helpers ─────────────────────────────────────────────────────────────

def _load_log() -> dict:
    if not os.path.exists(LOG_FILE):
        return {"total_checks": 0, "unique_passwords": [], "history": []}
    with open(LOG_FILE, encoding="utf-8") as f:
        return json.load(f)


def _save_log(data: dict) -> None:
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _record_check(username: str, password: str, result: ScoreResult) -> int:
    """Append a check to the log and return the new total check count."""
    data = _load_log()
    data["total_checks"] += 1

    if password not in data["unique_passwords"]:
        data["unique_passwords"].append(password)

    data["history"].append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "password": password,
        "strength": result["strength"],
        "label": result["label"],
        "flags": result["flags"],
    })

    _save_log(data)
    return data["total_checks"]

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    payload = request.get_json(silent=True) or {}
    username: str = str(payload.get("username", "")).strip()
    password: str = str(payload.get("password", "")).strip()

    if not password:
        return jsonify({"error": "Password is required."}), 400

    result = analyse_password(password, username)
    total_checks = _record_check(username, password, result)

    return jsonify({
        "strength": result["strength"],
        "label": result["label"],
        "entropy": result["entropy"],
        "flags": result["flags"],
        "meta": {
            "coverage": len(COMMON_PASSWORDS) + len(KNOWN_USERNAMES),
            "checks_done": total_checks,
        },
    })


@app.route("/stats", methods=["GET"])
def stats():
    data = _load_log()
    return jsonify({
        "total_checks": data.get("total_checks", 0),
        "unique_passwords_checked": len(data.get("unique_passwords", [])),
    })


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)