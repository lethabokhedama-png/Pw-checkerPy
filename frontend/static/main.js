/**
 * PassCheck — client-side logic
 *
 * Responsibilities:
 *  - Analyse button → POST /check, render results
 *  - Toggle password visibility
 *  - Load /stats on mount
 *  - Colour-code meter + score based on strength
 */

"use strict";

// ─── Config ──────────────────────────────────────────────────────────────────

const API_BASE = "";   // same origin; change if backend is on a different host

// Strength bands → colour tokens (must match CSS vars)
const BANDS = [
  { max: 30,  colour: "#ff4560", label: "Very Weak" },
  { max: 55,  colour: "#ff9a3c", label: "Weak"      },
  { max: 80,  colour: "#ffd166", label: "Moderate"  },
  { max: 101, colour: "#39ff8f", label: "Strong"    },
];

// Human-readable descriptions for each server flag
const FLAG_META = {
  too_short:       { text: "≥ 8 characters",       wantFalse: true  },
  numeric_only:    { text: "Not digits only",        wantFalse: true  },
  common_password: { text: "Not a common password", wantFalse: true  },
  username_match:  { text: "Doesn't match username",wantFalse: true  },
  has_lower:       { text: "Lowercase letter",      wantFalse: false },
  has_upper:       { text: "Uppercase letter",      wantFalse: false },
  has_digit:       { text: "Number",                wantFalse: false },
  has_symbol:      { text: "Special character",     wantFalse: false },
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const usernameEl  = $("username");
const passwordEl  = $("password");
const analyseBtn  = $("analyse-btn");
const toggleVis   = $("toggle-vis");
const eyeShow     = $("eye-show");
const eyeHide     = $("eye-hide");
const resultsEl   = $("results");
const scoreNumber = $("score-number");
const strengthLbl = $("strength-label");
const entropyNote = $("entropy-note");
const meterFill   = $("meter-fill");
const meterWrap   = $("meter-wrap");
const checksGrid  = $("checks-grid");
const statLabel   = $("stat-label");

// ─── Utilities ────────────────────────────────────────────────────────────────

function bandFor(score) {
  return BANDS.find(b => score < b.max) ?? BANDS.at(-1);
}

function setLoading(on) {
  analyseBtn.disabled = on;
  analyseBtn.classList.toggle("loading", on);
}

// ─── Render results ──────────────────────────────────────────────────────────

function renderResults(data) {
  const { strength, label, entropy, flags } = data;
  const band = bandFor(strength);

  // Score + label
  scoreNumber.textContent = strength.toFixed(0);
  scoreNumber.style.color = band.colour;
  strengthLbl.textContent = label;
  entropyNote.textContent = `${entropy} bits entropy`;

  // Meter
  meterFill.style.width      = `${strength}%`;
  meterFill.style.background = band.colour;
  meterFill.style.boxShadow  = `0 0 8px ${band.colour}`;
  meterWrap.setAttribute("aria-valuenow", strength);

  // Checks grid
  checksGrid.innerHTML = Object.entries(FLAG_META).map(([key, meta]) => {
    const flagVal = flags[key];
    // "pass" means the check is satisfied (wantFalse inverts the flag meaning)
    const pass = meta.wantFalse ? !flagVal : flagVal;
    return `
      <div class="check-item ${pass ? "pass" : "fail"}">
        <span class="check-dot"></span>
        <span class="check-label">${meta.text}</span>
      </div>`;
  }).join("");

  // Show panel
  resultsEl.hidden = false;
}

// ─── API calls ────────────────────────────────────────────────────────────────

async function analyse() {
  const username = usernameEl.value.trim();
  const password = passwordEl.value;

  if (!password) {
    passwordEl.focus();
    return;
  }

  setLoading(true);

  try {
    const res  = await fetch(`${API_BASE}/check`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error ?? `Server error ${res.status}`);
    }

    const data = await res.json();
    renderResults(data);

    // Refresh stat pill
    statLabel.textContent = `${data.meta.checks_done.toLocaleString()} checks run`;
  } catch (err) {
    console.error("PassCheck error:", err);
    alert(`Something went wrong: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

async function loadStats() {
  try {
    const res  = await fetch(`${API_BASE}/stats`);
    const data = await res.json();
    statLabel.textContent = `${data.total_checks.toLocaleString()} checks run`;
  } catch {
    statLabel.textContent = "offline";
  }
}

// ─── Event listeners ─────────────────────────────────────────────────────────

analyseBtn.addEventListener("click", analyse);

passwordEl.addEventListener("keydown", e => {
  if (e.key === "Enter") analyse();
});

usernameEl.addEventListener("keydown", e => {
  if (e.key === "Enter") passwordEl.focus();
});

toggleVis.addEventListener("click", () => {
  const isHidden = passwordEl.type === "password";
  passwordEl.type    = isHidden ? "text" : "password";
  eyeShow.style.display = isHidden ? "none"  : "";
  eyeHide.style.display = isHidden ? ""      : "none";
  toggleVis.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
});

// ─── Init ─────────────────────────────────────────────────────────────────────

loadStats();