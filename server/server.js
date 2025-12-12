// server.js — UPDATED FOR HEADER JWT + SUBSCRIPTIONS FOLDER WITH CONDITIONAL RESPONSES
require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — FULLY WORKING WITH LOGS');
console.log('================================================');

const express = require('express');
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
app.use(express.static(path.join(__dirname, '../public')));

// ==================== JWT ====================
const JWT_SECRET = process.env.JWT_SECRET;
const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('%cAUTH FAILED → No token for path:', 'color:red', req.path);
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Login Required</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login</a> to access this content.</p>
      `);
    } else {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }
  const token = authHeader.split(' ')[1];
  const payload = verifyToken(token);
  if (!payload) {
    console.log('%cAUTH FAILED → Invalid token for path:', 'color:red', req.path);
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Login Required</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login</a> to access this content.</p>
      `);
    } else {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }
  req.userId = payload.userId;
  console.log('%cAUTH SUCCESS → User ID:', 'color:lime', req.userId, 'for path:', req.path);
  next();
};

// ==================== PROTECTED SUBSCRIPTIONS FOLDER ====================
app.use('/subscriptions', requireAuth, async (req, res, next) => {
  try {
    const [[user]] = await pool.query(
      'SELECT subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );
    const now = Math.floor(Date.now() / 1000);
    if (user.subscription_status !== 'active' || user.subscription_period_end <= now) {
      console.log('%cACCESS DENIED → No active subscription for path:', 'color:red', req.path);
      if (req.accepts('html')) {
        return res.status(403).send(`
          <h1>Subscription Required</h1>
          <p>You need an active subscription to access this content. <a href="https://techsport.app/streampaltest/public/profile.html">Subscribe here</a>.</p>
        `);
      } else {
        return res.status(403).json({ error: 'No active subscription' });
      }
    }
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    if (req.accepts('html')) {
      res.status(500).send('<h1>Server Error</h1><p>Please try again later.</p>');
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
}, express.static(path.join(__dirname, 'subscriptions')));

// ==================== ROUTES ====================

// SIGNUP — FIXED WITH DETAILED ERROR LOGGING + TOKEN IN RESPONSE
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

    const token = generateToken(result.insertId);

    console.log('%cNEW USER CREATED → ID:', 'color:lime', result.insertId);
    res.json({ success: true, phrase, token });
  } catch (err) {
    console.error('%cSignup error → Full Details:', 'color:red', { message: err.message, code: err.code, stack: err.stack });
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// LOGIN + TOKEN IN RESPONSE
app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  console.log('%cLOGIN ATTEMPT →', 'color:orange', username);

  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(401).json({ success: false });

    const passOk = await bcrypt.compare(password, user.password_hash);
    const phraseOk = user.phrase.trim() === phrase.trim();

    if (passOk && phraseOk) {
      const token = generateToken(user.id);
      console.log('%cLOGIN SUCCESS → Token generated', 'color:lime');
      return res.json({ success: true, token });
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
      await pool.query('UPDATE users SET subscription_status = "inactive", subscription_period_end = 0 WHERE id = ?', [req.userId]);
      active = false;
    }

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: active,
      days_left: active ? Math.ceil((user.subscription_period_end - now) / 86400) : 0
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CHECKOUT — SINGLE PAYMENT MODE
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
  console.log('%cCHECKOUT START → Price ID:', 'color:cyan', price_id, 'User ID:', req.userId);

  try {
    const [[user]] = await pool.query('SELECT stripe_customer_id FROM users WHERE id = ?', [req.userId]);
    let customerId = user.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ metadata: { userId: req.userId.toString() } });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('%cNEW CUSTOMER CREATED → ID:', 'color:cyan', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      mode: 'payment',
      success_url: `https://techsport.app/streampaltest/public/profile.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `https://techsport.app/streampaltest/public/profile.html?cancel=true`,
      metadata: { userId: req.userId.toString(), priceId: price_id }
    });

    console.log('%cCHECKOUT SESSION CREATED → ID:', 'color:lime', session.id);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// RECOVER + ACTIVATE ACCESS — FIXED WITH HARDCODED PERIOD + TOKEN IN RESPONSE
app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  console.log('%cRECOVER SESSION START → Session ID:', 'color:cyan', session_id);

  if (!session_id) {
    console.log('%cRECOVER FAILED → No session_id', 'color:red');
    return res.status(400).json({ error: 'No session_id' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    console.log('%cSESSION RETRIEVED → Status:', 'color:cyan', session.payment_status, 'Mode:', session.mode, 'Metadata:', session.metadata);

    const userId = session.metadata?.userId;
    if (!userId) {
      console.log('%cRECOVER FAILED → No userId in metadata', 'color:red');
      return res.status(400).json({ error: 'No user in session' });
    }

    if (session.payment_status !== 'paid') {
      console.log('%cRECOVER FAILED → Payment not paid', 'color:red');
      return res.status(400).json({ error: 'Payment not completed' });
    }

    const priceId = session.metadata?.priceId;
    const now = Math.floor(Date.now() / 1000);
    let periodEnd = 0;

    if (priceId === 'price_1SIBPkFF2HALdyFkogiGJG5w') { // Weekly
      periodEnd = now + 7 * 86400;
    } else if (priceId === 'price_1SIBCzFF2HALdyFk7vOxByGq') { // Monthly
      periodEnd = now + 30 * 86400;
    } else if (priceId === 'price_1SXOVuFF2HALdyFk95SThAcM') { // Yearly
      periodEnd = now + 365 * 86400;
    } else {
      console.log('%cRECOVER FAILED → Unknown priceId', 'color:red', priceId);
      return res.status(400).json({ error: 'Unknown product' });
    }

    console.log('%cACCESS DETAILS → Period End UNIX:', 'color:cyan', periodEnd, 'Date:', new Date(periodEnd * 1000));

    await pool.query(
      'UPDATE users SET subscription_status = "active", subscription_period_end = ? WHERE id = ?',
      [periodEnd, userId]
    );

    console.log('%cACCESS ACTIVATED → User ID:', 'color:lime', userId, 'End UNIX:', periodEnd, 'Date:', new Date(periodEnd * 1000));

    const token = generateToken(userId);
    console.log('%cRECOVER SUCCESS → Token generated for User ID:', 'color:lime', userId);
    res.json({ success: true, token });
  } catch (err) {
    console.error('Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// CANCEL ACCESS — RESET DB (KEEP FOR MANUAL RESET)
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  console.log('%cCANCEL REQUEST → User ID:', 'color:orange', req.userId);

  try {
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", subscription_period_end = 0 WHERE id = ?',
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
/* 
W - sub 'price_1SIBPkFF2HALdyFkogiGJG5w' 
W single price_1SYeXVFF2HALdyFkMR0pVo2u


M sub  - price_1SIBCzFF2HALdyFk7vOxByGq
M single -  price_1SYeY3FF2HALdyFk8znKF3un

Y sub price_1SXOVuFF2HALdyFk95SThAcM
Y single - price_1SYeZVFF2HALdyFkxBfvFuTJ

*/