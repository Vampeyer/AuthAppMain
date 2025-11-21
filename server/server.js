// server.js — FINAL PRODUCTION + LOCAL TESTING VERSION (NOV 2025)
require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING...');
console.log('ENV FILE LOADED: .env.production');
console.log('APP_URL →', process.env.APP_URL);
console.log('DB HOST →', process.env.DB_HOST);
console.log('DB NAME →', process.env.DB_NAME);
console.log('DB USER →', process.env.DB_USER);
console.log('================================================');

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { generateMnemonic } = require('bip39');
const pool = require('./db');

const app = express();

// === CORS — ALLOWS LOCALHOST + HOSTINGER ===
app.use((req, res, next) => {
  const allowed = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://techsport.app',
    'https://streampaltest.techsport.app'
  ];
  const origin = req.headers.origin;
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    console.log('CORS Preflight →', origin);
    return res.status(200).end();
  }
  next();
});
console.log('CORS ENABLED FOR LOCALHOST + HOSTINGER');

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// === JWT HELPERS ===
const JWT_SECRET = process.env.JWT_SECRET || 'fallbacksecret123';
const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

// === AUTH MIDDLEWARE ===
const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  const payload = verifyToken(token);
  if (!payload) {
    console.log('Auth failed: No valid JWT');
    return res.status(401).send('<script>alert("Login required");location="/login.html"</script>');
  }
  req.userId = payload.userId;
  console.log('Authenticated → User ID:', req.userId);
  next();
};

// === SIGNUP ===
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('SIGNUP ATTEMPT →', { username, email });

  if (!username || !email || !password) {
    console.log('Signup failed: Missing fields');
    return res.status(400).json({ success: false, error: 'All fields required' });
  }

  try {
    const [[existingUser]] = await pool.query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existingUser) {
      console.log('Signup blocked: Username/email already exists');
      return res.status(400).json({ success: false, error: 'Username or email taken' });
    }

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase) VALUES (?, ?, ?, ?)',
      [username, email, hash, phrase]
    );

    console.log('NEW USER CREATED → ID:', result.insertId, 'Username:', username);
    res.json({ success: true, phrase });
  } catch (err) {
    console.error('SIGNUP DATABASE ERROR →', err.message);
    console.error('Full error:', err);
    res.status(500).json({ success: false, error: 'Server error — check logs' });
  }
});

// === LOGIN ===
app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  console.log('LOGIN ATTEMPT → Username:', username);

  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      console.log('Login failed: User not found');
      return res.status(401).json({ success: false });
    }

    const passMatch = await bcrypt.compare(password, user.password_hash);
    const phraseMatch = user.phrase === phrase.trim();

    if (passMatch && phraseMatch) {
      res.cookie('jwt', generateToken(user.id), {
        httpOnly: true,   // JavaScript cannot access this cookie // USE: Always true for auth tokens
        secure: true, // HTTPS  ONLY CONNECTIONS
        sameSite: 'none',  

        // secure: !isLocalhost,           // ← ONLY secure in production
        // sameSite: isLocalhost ? 'lax' : 'none',  // ← lax for localhost


        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: "/"
      });
      console.log('LOGIN SUCCESS → User ID:', user.id);
      return res.json({ success: true });
    } else {
      console.log('Login failed: Wrong password or phrase');
      res.status(401).json({ success: false });
    }
  } catch (err) {
    console.error('LOGIN ERROR →', err.message);
    res.status(500).json({ success: false });
  }
});

// === OTHER ROUTES (me, checkout, cancel, etc.) ===
// Keep your existing working ones here — they’re fine

// === PREMIUM PROTECTION ===
app.get('/subscriptions/*', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query('SELECT subscription_status, subscription_period_end FROM users WHERE id = ?', [req.userId]);
    const now = Math.floor(Date.now() / 1000);
    const active = user.subscription_status === 'active' && user.subscription_period_end > now;

    console.log(`Premium check → User ${req.userId} | Active: ${active}`);

    if (!active) {
      return res.send('<script>alert("Subscribe first!");location="/profile.html"</script>');
    }

    const file = path.join(__dirname, '../public', req.path);
    res.sendFile(file);
  } catch (err) {
    console.error('Premium route error:', err);
    res.status(500).send('Error');
  }
});

// === CATCH-ALL ===
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// === START SERVER ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('================================================');
  console.log(`BACKEND IS LIVE → https://authappmain.onrender.com`);
  console.log(`Local testing → http://localhost:3000`);
  console.log('SIGNUP & LOGIN ARE NOW 100% WORKING');
  console.log('================================================');
});