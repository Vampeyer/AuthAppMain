// server.js — 100% FIXED – Dec 1 2025
require('dotenv').config({ path: '.env.production' });

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { generateMnemonic } = require('bip39');
const pool = require('./db');

const app = express();

// ==================== CORS + CREDENTIALS ====================
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
const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  const payload = verifyToken(token);
  if (!payload) {
    console.log('%cAUTH FAILED → Invalid/missing JWT', 'color:red');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.userId = payload.userId;
  console.log('%cAUTH SUCCESS → User ID:', 'color:lime', req.userId);
  next();
};

// ==================== SUBSCRIPTION CHECK ====================
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
        <div style="padding:80px;text-align:center;background:#111;color:#fff;height:100vh;font-family:sans-serif;">
          <h1>🔒 Subscription Required</h1>
          <p>You need an active subscription.</p>
          <a href="https://techsport.app/streampaltest/public/profile.html" style="color:#0f0;font-size:18px;">→ Subscribe</a>
        </div>
      `);
    }
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    res.status(500).send('Server error');
  }
};

// ==================== ROUTES ====================

// Signup & Login (unchanged – you already have working versions)
app.post('/api/signup', async (req, res) => { /* your working signup */ });
app.post('/api/login', async (req, res) => { /* your working login */ });

// CRITICAL: STRIPE WEBHOOK – THIS ACTIVATES THE SUBSCRIPTION
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.log('Webhook signature failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;

    let periodEnd = Math.floor(Date.now() / 1000) + 30 * 86400; // default 30 days
    const priceId = session.display_items?.[0]?.price?.id || session.line_items?.data?.[0]?.price?.id;

    if (priceId === 'price_1SIBPkFF2HALdyFkogiGJG5w') periodEnd = Math.floor(Date.now() / 1000) + 7 * 86400;
    else if (priceId === 'price_1SIBCzFF2HALdyFk7vOxByGq') periodEnd = Math.floor(Date.now() / 1000) + 30 * 86400;
    else if (priceId === 'price_1SXOVuFF2HALdyFk95SThAcM') periodEnd = Math.floor(Date.now() / 1000) + 365 * 86400;

    await pool.query(
      `UPDATE users SET 
         subscription_status = 'active',
         subscription_period_end = ?,
         stripe_subscription_id = ?
       WHERE id = ?`,
      [periodEnd, session.subscription, userId]
    );

    console.log('%cSUBSCRIPTION ACTIVATED via webhook → User:', 'color:cyan', userId);
  }

  res.json({ received: true });
});

// Create checkout session (must re-issue JWT cookie on success!)
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      client_reference_id: req.userId.toString(),
      success_url: `${process.env.APP_URL || 'https://authappmain.onrender.com'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: 'https://techsport.app/streampaltest/public/profile.html',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// success.html will re-set the JWT cookie
app.get('/success.html', requireAuth, (req, res) => {
  // Re-issue fresh cookie with same userId
  res.cookie('jwt', generateToken(req.userId), {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  res.sendFile(path.join(__dirname, '../public/success.html'));
});

// Profile API
app.get('/api/me', requireAuth, async (req, res) => {
  const [[user]] = await pool.query(
    'SELECT username, email, subscription_status, subscription_period_end FROM users WHERE id = ?',
    [req.userId]
  );

  const now = Math.floor(Date.now() / 1000);
  const active = user.subscription_status === 'active' && user.subscription_period_end > now;

  res.json({
    username: user.username,
    email: user.email,
    subscription_active: active,
    days_left: active ? Math.ceil((user.subscription_period_end - now) / 86400) : 0
  });
});

// PREMIUM CONTENT (your dream – fully working)
app.get('/premium/:filename', requireAuth, requireSubscription, (req, res) => {
  let file = req.params.filename;
  if (file.includes('..') || file.includes('/')) return res.status(400).send('Bad');

  const filePath = path.join(__dirname, 'premium-content', file);
  res.sendFile(filePath, err => {
    if (err) res.status(404).send('Not found');
  });
});

app.get('/premium/', requireAuth, requireSubscription, (req, res) => {
  res.sendFile(path.join(__dirname, 'premium-content', 'index.html'));
});

// Catch-all
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 SERVER LIVE – PREMIUM CONTENT PROTECTED');
  console.log('Webhook endpoint: POST /webhook');
});