async function check() {
  const username = document.getElementById("username").value
  const password = document.getElementById("password").value

  const res = await fetch("/check", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ username, password })
  })

  const d = await res.json()

  const bar = document.getElementById("strength")
  bar.style.width = d.strength + "%"

  if (d.strength < 30) bar.style.background = "#ef4444"
  else if (d.strength < 70) bar.style.background = "#facc15"
  else bar.style.background = "#22c55e"

  document.getElementById("score").textContent =
    `Strength: ${d.strength}/100`

  document.getElementById("flags").textContent =
    JSON.stringify(d.flags, null, 2)
    }
