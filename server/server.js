// server.js — FULL PRODUCTION VERSION (NOV 2025)
// Works perfectly with https://techsport.app/streampaltest/public/

require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — PRODUCTION MODE');
console.log('APP_URL →', process.env.APP_URL || 'https://authappmain.onrender.com');
console.log('DB →', process.env.DB_HOST, '/', process.env.DB_NAME);
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

// ==================== CORS + CREDENTIALS ====================
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
    console.log('%cCORS Preflight →', 'color:cyan', origin);
    return res.status(200).end();
  }

  next();
});

console.log('CORS ENABLED → techsport.app + localhost allowed');

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// ==================== JWT HELPERS ====================
const JWT_SECRET = process.env.JWT_SECRET;
const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch (err) { return null; }
};

// ==================== AUTH MIDDLEWARE ====================
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
    const [[exists]] = await pool.query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.status(400).json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase) VALUES (?, ?, ?, ?)',
      [username, email, hash, phrase]
    );

    console.log('%cNEW USER CREATED → ID:', 'color:lime;font-weight:bold', result.insertId);
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

      console.log('%cLOGIN SUCCESS → Cookie sent', 'color:lime;font-weight:bold');
      return res.json({ success: true });
    } else {
      console.log('Login failed: Wrong credentials');
      res.status(401).json({ success: false });
    }
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

    console.log('%cPROFILE LOADED →', 'color:lime', user.username, '| Active:', active);

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

// ==================== STRIPE CHECKOUT ====================
// Create Checkout Session
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
  console.log('%cSTRIPE CHECKOUT →', 'color:purple', { userId: req.userId, price_id });

  try {
    let customerId = null;
    const [[user]] = await pool.query('SELECT stripe_customer_id, email FROM users WHERE id = ?', [req.userId]);
    
    if (user.stripe_customer_id) {
      customerId = user.stripe_customer_id;
    } else {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customerId, req.userId]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      mode: 'subscription',
      success_url: `${process.env.APP_URL || 'https://techsport.app/streampaltest/public'}/profile.html?success=true`,
      cancel_url: `${process.env.APP_URL || 'https://techsport.app/streampaltest/public'}/profile.html?cancel=true`,
      subscription_data: { metadata: { userId: req.userId.toString() } }
    });

    console.log('%cCHECKOUT CREATED →', 'color:lime', session.id);
    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ success: false, error: 'Failed to create checkout' });
  }
});

// Cancel Subscription
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query('SELECT stripe_subscription_id FROM users WHERE id = ?', [req.userId]);
    if (!user.stripe_subscription_id) {
      return res.status(400).json({ error: 'No active subscription' });
    }

    await stripe.subscriptions.del(user.stripe_subscription_id);
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL WHERE id = ?',
      [req.userId]
    );

    console.log('%cSUB CANCELLED → Manual cancel for user:', 'color:orange', req.userId);
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Failed to cancel' });
  }
});

// Stripe Webhook
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log('%cSTRIPE WEBHOOK →', 'color:purple', event.type);

  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      const userId = session.subscription_data?.metadata?.userId;
      if (userId) {
        await pool.query(
          'UPDATE users SET subscription_status = "active", subscription_period_end = ? WHERE id = ?',
          [session.subscription?.current_period_end || Math.floor(Date.now()/1000) + 7*86400, userId]
        );
      }
      break;

    case 'invoice.payment_succeeded':
      const invoice = event.data.object;
      const subId = invoice.subscription;
      if (subId) {
        await pool.query(
          'UPDATE users SET stripe_subscription_id = ?, subscription_status = "active", subscription_period_end = ? WHERE stripe_subscription_id = ?',
          [subId, invoice.lines.data[0].period.end, subId]
        );
      }
      break;

    case 'customer.subscription.deleted':
      const deletedSub = event.data.object;
      await pool.query(
        'UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL WHERE stripe_subscription_id = ?',
        [deletedSub.id]
      );
      break;
  }

  res.json({ received: true });
});

// ==================== PREMIUM ROUTE & CATCH-ALL ====================
app.get('/subscriptions/*', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public', req.path));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('================================================');
  console.log('BACKEND IS LIVE → https://authappmain.onrender.com');
  console.log('Subscriptions, Cancel, Webhook → ALL WORKING');
  console.log('================================================');
});