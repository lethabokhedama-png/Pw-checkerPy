# PassCheck

**Entropy-based password strength analyser** — self-hosted, no third-party data sharing.

PassCheck scores passwords by calculating their Shannon entropy, then applies calibrated penalties for common attack vectors: known wordlists, username overlap, numeric-only patterns, and short length. Results are logged locally for audit purposes.

---

## Project structure

```
passcheck/
├── backend/
│   ├── app.py                  # Flask application
│   ├── checks_log.json         # Auto-created at runtime
│   ├── common_passwords.txt    # Wordlist — one password per line
│   └── usernames.txt           # Known usernames — one per line
├── frontend/
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/style.css
│       └── js/main.js
├── requirements.txt
└── README.md
```

---

## Setup

### 1. Clone / copy the project

```bash
git clone <your-repo> passcheck
cd passcheck
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Add wordlists (optional but recommended)

Place one entry per line:

- `backend/common_passwords.txt` — e.g. the [SecLists top 10k](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt)
- `backend/usernames.txt` — known or leaked usernames relevant to your context

PassCheck works without these files; wordlist checks will simply report clean.

### 5. Run

```bash
cd backend
python app.py
```

Open [http://localhost:8000](http://localhost:8000).

---

## API

### `POST /check`

Analyse a password.

**Request body**

```json
{
  "username": "alice",
  "password": "correct-horse-battery"
}
```

**Response**

```json
{
  "strength": 74.3,
  "label": "Moderate",
  "entropy": 104.1,
  "flags": {
    "too_short": false,
    "numeric_only": false,
    "common_password": false,
    "username_match": false,
    "has_lower": true,
    "has_upper": false,
    "has_digit": false,
    "has_symbol": true
  },
  "meta": {
    "coverage": 12543,
    "checks_done": 17
  }
}
```

| Field | Description |
|---|---|
| `strength` | Score 0–100 |
| `label` | `Very Weak` / `Weak` / `Moderate` / `Strong` |
| `entropy` | Raw Shannon entropy in bits |
| `flags` | Per-check boolean results |
| `meta.coverage` | Total entries loaded from wordlists |
| `meta.checks_done` | Cumulative checks since server start |

---

### `GET /stats`

Return aggregate counters.

```json
{
  "total_checks": 42,
  "unique_passwords_checked": 31
}
```

---

## Scoring logic

```
entropy = len(password) × log₂(character_pool_size)

penalties:
  common password found in wordlist  → −40 pts
  password overlaps username          → −30 pts
  digits only                         → −25 pts
  fewer than 8 characters             → −20 pts

score = clamp((entropy / 120) × 100 − penalties, 0, 100)
```

Strength bands:

| Score | Label |
|---|---|
| 0–29 | Very Weak |
| 30–54 | Weak |
| 55–79 | Moderate |
| 80–100 | Strong |

---

## Privacy

All analysis and logging happens on your server. Passwords are written to `checks_log.json` in plaintext — review your threat model before deploying to a shared or public environment. For production use, consider hashing logged passwords or disabling logging entirely.

---

## License

MIT