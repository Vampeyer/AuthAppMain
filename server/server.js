// server.js — FINAL PRODUCTION VERSION (NOV 30, 2025)
// Secure server-side premium content + cross-origin auth working perfectly

require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — PRODUCTION MODE');
console.log('APP_URL →', process.env.APP_URL || 'https://authappmain.onrender.com');
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

// ==================== CORS (Critical for techsport.app ↔ render) ====================
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'https://techsport.app',
    'https://streampaltest.techsport.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// ==================== JWT ====================
const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });

const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  const payload = verifyToken(token);

  if (!payload) {
    console.log('%cAUTH FAILED → Invalid or missing JWT', 'color:red');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.userId = payload.userId;
  console.log('%cAUTH SUCCESS → User ID:', 'color:lime', req.userId);
  next();
};

// ==================== SUBSCRIPTION MIDDLEWARE (SERVER-SIDE PROTECTION) ====================
const requireSubscription = async (req, res, next) => {
  try {
    const [[user]] = await pool.query(
      'SELECT subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    if (!user) {
      return res.status(403).send('Access denied: User not found');
    }

    const now = Math.floor(Date.now() / 1000);
    const isActive = user.subscription_status === 'active' && user.subscription_period_end > now;

    if (!isActive) {
      return res.status(403).send(`
        <div style="padding:80px;text-align:center;font-family:sans-serif;background:#111;color:#fff;height:100vh;">
          <h1>Premium Access Required</h1>
          <p>Your subscription is inactive or has expired.</p>
          <br>
          <a href="https://techsport.app/streampaltest/public/profile.html" 
             style="background:#00ff00;color:#000;padding:16px 32px;text-decoration:none;font-weight:bold;border-radius:8px;">
             → Go to Profile & Subscribe
          </a>
        </div>
      `);
    }

    next();
  } catch (err) {
    console.error('requireSubscription error:', err);
    res.status(500).send('Server error');
  }
};

// ==================== ROUTES ====================

// SIGNUP
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('%cSIGNUP ATTEMPT →', 'color:orange', { username, email });

  try {
    const [[exists]] = await pool.query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.status(400).json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase) VALUES (?, ?, ?, ?)',
      [username, email, hash, phrase]
    );

    console.log('%cNEW USER → ID:', 'color:lime', result.insertId);
    res.json({ success: true, phrase });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  console.log('%cLOGIN ATTEMPT →', 'color:orange', username);

  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(401).json({ success: false });

    const passOk = await bcrypt.compare(password, user.password_hash);
    const phraseOk = user.phrase.trim() === phrase.trim();

    if (passOk && phraseOk) {
      res.cookie('jwt', generateToken(user.id), {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      console.log('%cLOGIN SUCCESS → JWT cookie sent', 'color:lime');
      return res.json({ success: true });
    }

    res.status(401).json({ success: false });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false });
  }
});

// LOGOUT
app.get('/api/logout', (req, res) => {
  res.clearCookie('jwt', { sameSite: 'none', secure: true, path: '/' });
  res.json({ success: true });
});

// GET CURRENT USER
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    const now = Math.floor(Date.now() / 1000);
    const active = user.subscription_status === 'active' && user.subscription_period_end > now;
    const daysLeft = active ? Math.ceil((user.subscription_period_end - now) / 86400) : 0;

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: active,
      days_left: daysLeft
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// STRIPE CHECKOUT SESSION
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      success_url: 'https://techsport.app/streampaltest/public/profile.html?success=1',
      cancel_url: 'https://techsport.app/streampaltest/public/profile.html',
      client_reference_id: req.userId.toString(),
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// CANCEL SUBSCRIPTION
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query('SELECT stripe_subscription_id FROM users WHERE id = ?', [req.userId]);
    if (!user.stripe_subscription_id) return res.status(400).json({ error: 'No active subscription' });

    await stripe.subscriptions.cancel(user.stripe_subscription_id);
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL, subscription_period_end = 0 WHERE id = ?',
      [req.userId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Failed to cancel' });
  }
});

// ——————————————————————
// PREMIUM CONTENT — FULLY PROTECTED (SERVER-SIDE)
// ——————————————————————
app.get('/premium/:filename', requireAuth, requireSubscription, (req, res) => {
  let filename = req.params.filename;

  // Prevent directory traversal
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).send('Invalid filename');
  }

  const allowedExt = ['.html', '.pdf', '.jpg', '.jpeg', '.png', '.mp4', '.webm', '.pdf', '.mp3', '.zip'];
  const ext = path.extname(filename).toLowerCase();
  if (!allowedExt.includes(ext)) {
    return res.status(400).send('File type not allowed');
  }

  const filePath = path.join(__dirname, 'premium-content', filename);

  res.sendFile(filePath, (err) => {
    if (err) {
      console.log('Premium file not found:', filePath);
      res.status(404).send('File not found or access denied');
    } else {
      console.log('%cPREMIUM FILE SERVED →', 'color:magenta', filename, '| User:', req.userId);
    }
  });
});

// Optional: Allow /premium/ to serve index.html
app.get('/premium/', requireAuth, requireSubscription, (req, res) => {
  res.sendFile(path.join(__dirname, 'premium-content', 'index.html'));
});

// Catch-all for frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ==================== START ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('================================================');
  console.log('BACKEND LIVE → https://authappmain.onrender.com');
  console.log(`Premium content protected at: /premium/yourfile.html`);
  console.log('================================================');
});