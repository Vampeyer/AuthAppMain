// server.js — RECURRING SUBSCRIPTION MODEL WITH STRIPE
require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — RECURRING SUBSCRIPTION SYSTEM');
console.log('================================================');

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { generateMnemonic } = require('bip39');
const pool = require('./db');
const { checkRateLimit, recordFailure, clearAttempts } = require('./fail2ban');

const app = express();

app.use(cookieParser());

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
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_EXPIRY = '20m';
const COOKIE_MAX_AGE = 20 * 60 * 1000;

const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

const requireAuth = (req, res, next) => {
  let token = null;

  if (req.cookies && req.cookies.auth_token) {
    token = req.cookies.auth_token;
  }
  else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Login Required</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login</a>.</p>
      `);
    }
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const payload = verifyToken(token);
  if (!payload) {
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Session Expired</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login again</a>.</p>
      `);
    }
    return res.status(401).json({ error: 'Invalid token' });
  }

  req.userId = payload.userId;
  next();
};

const setAuthCookie = (res, token) => {
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: COOKIE_MAX_AGE,
    path: '/'
  });
};

// PROTECTED PREMIUM CONTENT
app.use('/subscriptions', requireAuth, async (req, res, next) => {
  try {
    const [[user]] = await pool.query('SELECT subscription_status FROM users WHERE id = ?', [req.userId]);
    if (user.subscription_status !== 'active') {
      if (req.accepts('html')) {
        return res.status(403).send(`
          <h1>Subscription Required</h1>
          <p><a href="https://techsport.app/streampaltest/public/profile.html">Subscribe here</a>.</p>
        `);
      }
      return res.status(403).json({ error: 'Active subscription required' });
    }
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    res.status(500).send('<h1>Server Error</h1>');
  }
}, express.static(path.join(__dirname, 'subscriptions')));

// ROUTES

app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const [[exists]] = await pool.query('SELECT 1 FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.status(400).json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase, subscription_status) VALUES (?, ?, ?, ?, "inactive")',
      [username, email, hash, phrase]
    );

    const token = generateToken(result.insertId);
    setAuthCookie(res, token);

    res.json({ success: true, phrase, token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  const ip = req.ip;

  const limit = checkRateLimit(ip);
  if (limit.banned) {
    return res.status(429).json({ success: false, error: `Too many attempts. Try again in ${limit.remaining}s.` });
  }

  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || !(await bcrypt.compare(password, user.password_hash)) || user.phrase.trim() !== phrase.trim()) {
      recordFailure(ip);
      return res.status(401).json({ success: false });
    }

    clearAttempts(ip);
    const token = generateToken(user.id);
    setAuthCookie(res, token);
    res.json({ success: true, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false });
  }
});

// CREATE RECURRING CHECKOUT SESSION
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;

  try {
    const [[user]] = await pool.query('SELECT email, stripe_customer_id FROM users WHERE id = ?', [req.userId]);
    let customer;

    if (user.stripe_customer_id) {
      customer = await stripe.customers.retrieve(user.stripe_customer_id);
    } else {
      customer = await stripe.customers.create({
        email: user.email,
        metadata: { userId: req.userId.toString() }
      });
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customer.id, req.userId]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      mode: 'subscription',
      success_url: `https://techsport.app/streampaltest/public/profile.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `https://techsport.app/streampaltest/public/profile.html?cancel=true`,
      metadata: { userId: req.userId.toString() }
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// RECOVER SESSION & ACTIVATE SUBSCRIPTION
app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'No session_id' });

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid' && session.mode === 'subscription') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    const userId = session.metadata?.userId;
    if (!userId) return res.status(400).json({ error: 'No user in session' });

    // Activate subscription in DB
    await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [userId]);

    const token = generateToken(userId);
    setAuthCookie(res, token);
    res.json({ success: true, token });
  } catch (err) {
    console.error('Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// PROFILE — SHOW ACTIVE / INACTIVE ONLY
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status FROM users WHERE id = ?',
      [req.userId]
    );

    // Optional: Sync with Stripe — if user has active sub in Stripe but not in DB, activate
    if (user.subscription_status !== 'active' && user.stripe_customer_id) {
      const subs = await stripe.subscriptions.list({ customer: user.stripe_customer_id, status: 'active' });
      if (subs.data.length > 0) {
        await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [req.userId]);
        user.subscription_status = 'active';
      }
    }

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: user.subscription_status === 'active'
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CANCEL SUBSCRIPTION IN STRIPE + DB
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query('SELECT stripe_customer_id FROM users WHERE id = ?', [req.userId]);

    if (user.stripe_customer_id) {
      const subs = await stripe.subscriptions.list({ customer: user.stripe_customer_id, status: 'active' });
      for (const sub of subs.data) {
        await stripe.subscriptions.update(sub.id, { cancel_at_period_end: true });
      }
    }

    await pool.query('UPDATE users SET subscription_status = "inactive" WHERE id = ?', [req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('auth_token', { httpOnly: true, secure: true, sameSite: 'none', path: '/' });
  res.json({ success: true });
});

app.post('/api/access-premium', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).send('<h1>Login Required</h1><p><a href="/login.html">Login</a></p>');

  const payload = verifyToken(token);
  if (!payload) return res.status(401).send('<h1>Session Expired</h1><p><a href="/login.html">Login again</a></p>');

  try {
    const [[user]] = await pool.query('SELECT subscription_status FROM users WHERE id = ?', [payload.userId]);
    if (user.subscription_status !== 'active') {
      return res.status(403).send('<h1>Subscription Required</h1><p><a href="/profile.html">Subscribe</a></p>');
    }

    setAuthCookie(res, token);
    res.redirect('/subscriptions/premium.html');
  } catch (err) {
    console.error('Access premium error:', err);
    res.status(500).send('<h1>Server Error</h1>');
  }
});


// ==================== STRIPE WEBHOOK ====================
app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET; // Add this to your .env

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle relevant events
  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode === 'subscription' && session.metadata?.userId) {
          await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [session.metadata.userId]);
          console.log('✅ Webhook: Activated subscription via checkout.session.completed');
        }
        break;
      }
      case 'invoice.paid': {
        const invoice = event.data.object;
        if (invoice.subscription && invoice.customer) {
          // Find user by stripe_customer_id
          const [[user]] = await pool.query('SELECT id FROM users WHERE stripe_customer_id = ?', [invoice.customer]);
          if (user) {
            await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [user.id]);
            console.log('✅ Webhook: Kept active on renewal (invoice.paid)');
          }
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const [[user]] = await pool.query('SELECT id FROM users WHERE stripe_customer_id = ?', [sub.customer]);
        if (user) {
          await pool.query('UPDATE users SET subscription_status = "inactive" WHERE id = ?', [user.id]);
          console.log('❌ Webhook: Deactivated subscription (deleted)');
        }
        break;
      }
      // Optional: handle payment failures
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        if (invoice.subscription && invoice.customer) {
          const [[user]] = await pool.query('SELECT id FROM users WHERE stripe_customer_id = ?', [invoice.customer]);
          if (user) {
            await pool.query('UPDATE users SET subscription_status = "inactive" WHERE id = ?', [user.id]);
            console.log('⚠️ Webhook: Marked inactive due to payment failure');
          }
        }
        break;
      }
      default:
        console.log(`Unhandled webhook event type: ${event.type}`);
    }
  } catch (err) {
    console.error('Webhook handling error:', err);
  }

  res.json({ received: true });
});








app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 RECURRING SUBSCRIPTION BACKEND LIVE on port ${PORT}`);
});