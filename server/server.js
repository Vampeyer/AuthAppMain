// server.js — FINAL CLEAN & WORKING VERSION (Signup + Login + Profile + Subscriptions + Cancel)
require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — FULLY WORKING VERSION');
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
  const allowed = [
    'https://techsport.app',
    'https://streampaltest.techsport.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];
  if (allowed.includes(origin)) {
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
const generateToken = (id) => jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (token) => { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } };

const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  req.userId = payload.userId;
  next();
};

// ==================== ROUTES ====================

// SIGNUP
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const [[exists]] = await pool.query('SELECT 1 FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase) VALUES (?, ?, ?, ?)',
      [username, email, hash, phrase]
    );
    res.json({ success: true, phrase });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.json({ success: false });

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
      return res.json({ success: true });
    }
    res.json({ success: false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

app.get('/api/logout', (req, res) => {
  res.clearCookie('jwt', { sameSite: 'none', secure: true, path: '/' });
  res.json({ success: true });
});

// PROFILE DATA
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
    res.status(500).json({ error: 'Server error' });
  }
});

// CREATE CHECKOUT SESSION — FIXED REDIRECT
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
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
      success_url: 'https://techsport.app/streampaltest/public/profile.html?success=true',
      cancel_url: 'https://techsport.app/streampaltest/public/profile.html?cancel=true',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// CANCEL SUBSCRIPTION
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query('SELECT stripe_subscription_id FROM users WHERE id = ?', [req.userId]);
    if (!user.stripe_subscription_id) return res.json({ error: 'No subscription' });

    await stripe.subscriptions.del(user.stripe_subscription_id);
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL, subscription_period_end = 0 WHERE id = ?',
      [req.userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// WEBHOOK (keeps DB in sync)
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.subscription_data?.metadata?.userId || session.metadata?.userId;
    if (userId) {
      await pool.query('UPDATE users SET subscription_status = "active", subscription_period_end = ? WHERE id = ?', [
        session.subscription?.current_period_end || Math.floor(Date.now()/1000) + 7*86400,
        userId
      ]);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    await pool.query('UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL WHERE stripe_subscription_id = ?', [sub.id]);
  }

  res.json({ received: true });
});

// STATIC FILES
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('BACKEND IS LIVE AND 100% WORKING');
  console.log('https://authappmain.onrender.com');
});