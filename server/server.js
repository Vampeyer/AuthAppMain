// server.js — FINAL WORKING VERSION (premium content fully protected)
require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — FULLY WORKING WITH LOGS');
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

// ==================== CORS ====================
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

  if (req.method === 'OPTIONS') return res.status(200).end();
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
    console.log('%cAUTH FAILED → No valid JWT', 'color:red');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.userId = payload.userId;
  console.log('%cAUTH SUCCESS → User ID:', 'color:lime', req.userId);
  next();
};

// ==================== ROUTES ====================

// SIGNUP
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('%cSIGNUP ATTEMPT →', 'color:orange', { username, email });

  try {
    const [[exists]] = await pool.query('SELECT 1 FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.status(400).json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase) VALUES (?, ?, ?, ?)',
      [username, email, hash, phrase]
    );

    console.log('%cNEW USER CREATED → ID:', 'color:lime', result.insertId);
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
      console.log('%cLOGIN SUCCESS', 'color:lime');
      return res.json({ success: true });
    } else {
      console.log('%cLOGIN FAILED', 'color:red');
      res.status(401).json({ success: false });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false });
  }
});

app.get('/api/logout', (req, res) => {
  res.clearCookie('jwt', { sameSite: 'none', secure: true, path: '/' });
  res.json({ success: true });
});

// PROFILE + AUTO-EXPIRE
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    const now = Math.floor(Date.now() / 1000);
    let active = user.subscription_status === 'active' && user.subscription_period_end > now;

    if (user.subscription_status === 'active' && user.subscription_period_end <= now) {
      await pool.query('UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL, subscription_period_end = 0 WHERE id = ?', [req.userId]);
      active = false;
    }

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

// CREATE CHECKOUT SESSION
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
  console.log('%cCHECKOUT START → User ID:', 'color:purple', req.userId, price_id);

  try {
    const [[user]] = await pool.query('SELECT stripe_customer_id, email FROM users WHERE id = ?', [req.userId]);
    let customerId = user.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customerId, req.userId]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      mode: 'subscription',
      success_url: 'https://techsport.app/streampaltest/public/profile.html?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://techsport.app/streampaltest/public/profile.html?cancel=true',
      metadata: { userId: req.userId.toString(), priceId: price_id }
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// RECOVER SESSION AFTER PAYMENT
app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'No session_id' });

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['subscription'] });

    const userId = session.metadata?.userId;
    if (!userId) return res.status(400).json({ error: 'No user' });

    let sub = session.subscription;
    if (typeof sub === 'string') sub = await stripe.subscriptions.retrieve(sub);

    let periodEnd = sub.current_period_end;
    if (!periodEnd || periodEnd <= 0) {
      const priceId = session.metadata?.priceId;
      const now = Math.floor(Date.now() / 1000);
      if (priceId === 'price_1SIBPkFF2HALdyFkogiGJG5w') periodEnd = now + 7 * 86400;
      else if (priceId === 'price_1SIBCzFF2HALdyFk7vOxByGq') periodEnd = now + 30 * 86400;
      else if (priceId === 'price_1SXOVuFF2HALdyFk95SThAcM') periodEnd = now + 365 * 86400;
    }

    await pool.query(
      'UPDATE users SET subscription_status = "active", subscription_period_end = ?, stripe_subscription_id = ? WHERE id = ?',
      [periodEnd, sub.id, userId]
    );

    res.cookie('jwt', generateToken(userId), {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// CANCEL SUBSCRIPTION
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query('SELECT stripe_subscription_id FROM users WHERE id = ?', [req.userId]);
    if (!user.stripe_subscription_id) return res.status(400).json({ error: 'No subscription' });

    await stripe.subscriptions.cancel(user.stripe_subscription_id);
    await pool.query('UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL, subscription_period_end = 0 WHERE id = ?', [req.userId]);

    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// ——————————————————————
// 100% PROTECTED PREMIUM CONTENT
// ——————————————————————
const requireSubscription = async (req, res, next) => {
  try {
    const [[user]] = await pool.query(
      'SELECT subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    const now = Math.floor(Date.now() / 1000);
    const active = user && user.subscription_status === 'active' && user.subscription_period_end > now;

    if (!active) {
      return res.status(403).send(`
        <div style="padding:60px;text-align:center;font-family:sans-serif;background:#f8f8f8;height:100vh;">
          <h1>Subscription Required</h1>
          <p>You need an active subscription to view premium content.</p>
          <a href="https://techsport.app/streampaltest/public/profile.html" style="color:#0066cc;font-size:18px;">Go to Profile & Subscribe</a>
        </div>
      `);
    }
    next();
  } catch (err) {
    console.error('requireSubscription error:', err);
    res.status(500).send('Server error');
  }
};

// Single protected route for all premium files
app.get('/premium/:filename', requireAuth, requireSubscription, (req, res) => {
  const filename = req.params.filename;

  // Security: only allow safe filenames
  if (!/^[a-zA-Z0-9._-]+(\.html|\.pdf|\.jpg|\.jpeg|\.png|\.mp4|\.webm)$/i.test(filename)) {
    return res.status(400).send('Invalid filename');
  }

  const filePath = path.join(__dirname, 'premium-content', filename);

  res.sendFile(filePath, (err) => {
    if (err) {
      console.log('Premium file not found:', filePath);
      res.status(404).send('File not found');
    }
  });
});

// Catch-all for public pages
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('BACKEND IS LIVE — WITH DEBUG LOGS');
  console.log(`Listening on port ${PORT}`);
});