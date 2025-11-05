// server.js
// ===============================================
// RENDER + LOCAL: CORS, LOGIN, PROFILE, SUBSCRIPTION LOCKED
// ===============================================

require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');

// ---------- STRIPE ----------
let rawKey = process.env.STRIPE_SECRET_KEY || '';
rawKey = rawKey.trim().replace(/[' "\r\n]/g, '');
if (!rawKey) throw new Error('STRIPE_SECRET_KEY missing');
console.log('[STRIPE] key (first 10):', rawKey.substring(0, 10) + '...');

const stripe = require('stripe')(rawKey, {
  apiVersion: '2023-10-16',
  maxNetworkRetries: 0,
  timeout: 10000
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123!@#';
const IS_PROD = process.env.NODE_ENV === 'production';
const DOMAIN = IS_PROD ? 'https://authappmain.onrender.com' : 'http://localhost:3000';

// ---------- CORS: RUNS ON EVERY RESPONSE (RENDER FIX) ----------
const allowedOrigins = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'https://techsport.app',
  'https://authappmain.onrender.com'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

app.use(cookieParser());
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));

// ---------- MYSQL ----------
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Auto-add columns
(async () => {
  try {
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_active BOOLEAN DEFAULT FALSE`);
    console.log('[DB] Schema ready');
  } catch (e) { console.error('[DB] Schema error:', e.message); }
})();

// ---------- JWT ----------
function verifyTokenOptional(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) {
    req.userId = null;
    console.log('[JWT] No token');
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    console.log(`[JWT] Valid → user ${req.userId}`);
    next();
  } catch (e) {
    req.userId = null;
    console.log('[JWT] Invalid token');
    next();
  }
}

async function verifyTokenRequired(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- MNEMONIC ----------
function generateMnemonic() {
  const list = ['apple','banana','cat','dog','elephant','fox','grape','horse','ice','jungle','kiwi','lemon',
                'monkey','nut','orange','pear','queen','rabbit','snake','tiger','umbrella','violet',
                'whale','xray','yellow','zebra'];
  const words = [];
  for (let i = 0; i < 12; i++) words.push(list[Math.floor(Math.random() * list.length)]);
  return words.join(' ');
}

// ---------- SUBSCRIPTION FOLDER: LOCKED ----------
async function requireSubscription(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) {
    console.log('[SUB] No token → blocked');
    return res.status(403).send(`<script>alert('Subscribe to access premium content.');location='/profile.html';</script>`);
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0 || !rows[0].subscription_active) {
      console.log(`[SUB] User ${decoded.id} no sub → blocked`);
      return res.status(403).send(`<script>alert('Subscribe to access premium content.');location='/profile.html';</script>`);
    }
    console.log(`[SUB] User ${decoded.id} allowed`);
    next();
  } catch (e) {
    console.log('[SUB] Invalid token → blocked');
    return res.status(403).send(`<script>alert('Subscribe to access premium content.');location='/profile.html';</script>`);
  }
}
app.use('/subscription', requireSubscription, express.static(path.join(__dirname, 'public', 'subscription')));

// ---------- API ROUTES (BEFORE STATIC) ----------
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('[signup] Attempt:', { username, email });
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

  try {
    const [exists] = await pool.execute('SELECT id FROM users WHERE username=? OR email=?', [username, email]);
    if (exists.length) return res.status(400).json({ error: 'User exists' });

    const mnemonic = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username,email,password_hash,mnemonic) VALUES (?,?,?,?)',
      [username, email, hash, mnemonic]
    );

    const token = jwt.sign({ id: result.insertId }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('authToken', token, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', maxAge: 7*24*60*60*1000 });
    console.log(`[signup] SUCCESS → user ${result.insertId}`);
    res.json({ success: true, mnemonic });
  } catch (e) {
    console.error('[signup] ERROR:', e.message);
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/login', async (req, res) => {
  const { login, password, mnemonic } = req.body;
  console.log('[login] Attempt:', { login });
  if (!login || !password || !mnemonic) return res.status(400).json({ error: 'All fields required' });

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username=? OR email=?', [login, login]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match || user.mnemonic !== mnemonic) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('authToken', token, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', maxAge: 7*24*60*60*1000 });
    console.log(`[login] SUCCESS → user ${user.id}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[login] ERROR:', e.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/profile', verifyTokenOptional, async (req, res) => {
  console.log('[profile] Request');
  if (!req.userId) {
    console.log('[profile] → NOT LOGGED IN');
    return res.json({ loggedIn: false });
  }

  try {
    const [rows] = await pool.execute('SELECT username,email,subscription_active FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.json({ loggedIn: false });

    const u = rows[0];
    console.log(`[profile] → LOGGED IN: ${u.username} | sub: ${u.subscription_active}`);
    res.json({
      loggedIn: true,
      username: u.username,
      email: u.email,
      subscription_active: !!u.subscription_active
    });
  } catch (e) {
    console.error('[profile] ERROR:', e.message);
    res.status(500).json({ error: 'Profile load failed' });
  }
});

// ... checkout, verify-session, cancel, logout (same as before) ...

// ---------- STATIC: AFTER ALL API ROUTES ----------
app.use(express.static(path.join(__dirname, 'public')));

// ---------- START ----------
app.listen(PORT, async () => {
  try {
    await pool.getConnection();
    console.log('MySQL connected');
  } catch (e) { console.error('MySQL error:', e.message); }
  console.log(`Server on ${PORT} | DOMAIN: ${DOMAIN}`);
  console.log(`CORS allowed: ${allowedOrigins.join(', ')}`);
});