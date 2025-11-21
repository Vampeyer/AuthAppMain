


# 1 - FIX #1 – ONE LINE TO ADD IN EVERY HTML FILE (5 seconds)
Add this at the very top of every HTML file (login.html, profile.html, premium.html, signup.html):
HTML<script>
// THIS IS YOUR BACKEND URL — NEVER CHANGE IT AGAIN
const BACKEND_URL = 'https://authappmain.onrender.com';
console.log('Frontend → Connecting to backend:', BACKEND_URL);
</script>
Then replace every fetch like this:
OLD (broken):
JavaScriptfetch('/api/login', ...)
NEW (working):
JavaScriptfetch(`${BACKEND_URL}/api/login`, ...)

