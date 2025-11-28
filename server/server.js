// server.js — FINAL FIXED VERSION WITH EXTRA CONSOLE LOGS FOR DEBUGGING
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

// SIGNUP — FIXED WITH DETAILED ERROR LOGGING
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
    console.error('%cSignup error → Full Details:', 'color:red', { message: err.message, code: err.code, stack: err.stack });
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

      console.log('%cLOGIN SUCCESS → Cookie sent', 'color:lime');
      return res.json({ success: true });
    } else {
      console.log('%cLOGIN FAILED → Wrong credentials', 'color:red');
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
  console.log('%cPROFILE REQUEST → User ID:', 'color:cyan', req.userId);

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
      console.log('%cSUB AUTO-EXPIRED → User ID:', 'color:orange', req.userId, 'Old End:', user.subscription_period_end, 'Now:', now);
    }

    const daysLeft = active ? Math.ceil((user.subscription_period_end - now) / 86400) : 0;

    console.log('%cPROFILE DATA →', 'color:lime', { username: user.username, active, daysLeft, periodEnd: user.subscription_period_end, endDate: new Date(user.subscription_period_end * 1000) });

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
  console.log('%cCHECKOUT START → User ID:', 'color:purple', req.userId, 'Price ID:', price_id);

  try {
    const [[user]] = await pool.query('SELECT stripe_customer_id, email FROM users WHERE id = ?', [req.userId]);
    let customerId = user.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('%cNEW STRIPE CUSTOMER CREATED → ID:', 'color:cyan', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      mode: 'subscription',
      success_url: 'https://techsport.app/streampaltest/public/profile.html?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://techsport.app/streampaltest/public/profile.html?cancel=true',
      metadata: { userId: req.userId.toString(), priceId: price_id }  // Fixed capitalization to priceId
    });

    console.log('%cCHECKOUT SESSION CREATED → ID:', 'color:lime', session.id);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// RECOVER + ACTIVATE SUBSCRIPTION — FIXED WITH HARDCODED FALLBACK
app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  console.log('%cRECOVER SESSION START → Session ID:', 'color:cyan', session_id);

  if (!session_id) {
    console.log('%cRECOVER FAILED → No session_id', 'color:red');
    return res.status(400).json({ error: 'No session_id' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['subscription'] });
    console.log('%cSESSION RETRIEVED → Status:', 'color:cyan', session.payment_status, 'Mode:', session.mode, 'Metadata:', session.metadata);

    const userId = session.metadata?.userId;
    if (!userId) {
      console.log('%cRECOVER FAILED → No userId in metadata', 'color:red');
      return res.status(400).json({ error: 'No user in session' });
    }

    let sub = session.subscription;
    if (typeof sub === 'string') {
      sub = await stripe.subscriptions.retrieve(sub);
      console.log('%cFETCHED FULL SUB SEPARATELY → ID:', 'color:cyan', sub.id);
    }

    if (!sub) {
      console.log('%cRECOVER FAILED → No subscription', 'color:red');
      return res.status(400).json({ error: 'No sub' });
    }

    let periodEnd = sub.current_period_end;
    if (!periodEnd || periodEnd <= 0) {
      // Fallback to hardcoded based on priceId
      const priceId = session.metadata?.priceId;
      const now = Math.floor(Date.now() / 1000);
      if (priceId === 'price_1SIBPkFF2HALdyFkogiGJG5w') { // Weekly
        periodEnd = now + 7 * 86400;
      } else if (priceId === 'price_1SIBCzFF2HALdyFk7vOxByGq') { // Monthly
        periodEnd = now + 30 * 86400;
      } else {
        console.log('%cRECOVER FAILED → Unknown priceId for fallback', 'color:red', priceId);
        return res.status(400).json({ error: 'Unknown product' });
      }
      console.log('%cHARDCODED FALLBACK USED → Price ID:', 'color:yellow', priceId, 'New Period End:', periodEnd, 'Date:', new Date(periodEnd * 1000));
    } else {
      console.log('%cSTRIPE PERIOD END USED →', 'color:cyan', periodEnd);
    }

    const stripeSubId = sub.id;
    console.log('%cSUB DETAILS → ID:', 'color:cyan', stripeSubId, 'Period End UNIX:', periodEnd, 'Date:', new Date(periodEnd * 1000));

    await pool.query(
      'UPDATE users SET subscription_status = "active", subscription_period_end = ?, stripe_subscription_id = ? WHERE id = ?',
      [periodEnd, stripeSubId, userId]
    );

    console.log('%cSUB ACTIVATED → User ID:', 'color:lime', userId, 'End UNIX:', periodEnd, 'Date:', new Date(periodEnd * 1000));

    res.cookie('jwt', generateToken(userId), {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    console.log('%cRECOVER SUCCESS → Cookie re-issued for User ID:', 'color:lime', userId);
    res.json({ success: true });
  } catch (err) {
    console.error('Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// CANCEL SUBSCRIPTION — FIXED METHOD
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  console.log('%cCANCEL REQUEST → User ID:', 'color:orange', req.userId);

  try {
    const [[user]] = await pool.query('SELECT stripe_subscription_id FROM users WHERE id = ?', [req.userId]);
    if (!user.stripe_subscription_id) {
      console.log('%cCANCEL FAILED → No subscription', 'color:red');
      return res.status(400).json({ error: 'No subscription' });
    }

    await stripe.subscriptions.cancel(user.stripe_subscription_id);
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", stripe_subscription_id = NULL, subscription_period_end = 0 WHERE id = ?',
      [req.userId]
    );

    console.log('%cCANCEL SUCCESS → User ID:', 'color:lime', req.userId);
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// STATIC FILES
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('BACKEND IS LIVE — WITH DEBUG LOGS');
  console.log(`Listening on port ${PORT}`);
});