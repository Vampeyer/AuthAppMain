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
    console.log('BACK: Token from cookie in requireAuth');
  } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
    console.log('BACK: Token from header in requireAuth');
  }

  if (!token) {
    console.log('BACK: No token in requireAuth for path:', req.path);
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
    console.log('BACK: Invalid token in requireAuth for path:', req.path);
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Session Expired</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login again</a>.</p>
      `);
    }
    return res.status(401).json({ error: 'Invalid token' });
  }

  req.userId = payload.userId;
  console.log('BACK: Auth success - User ID:', req.userId, 'for path:', req.path);
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
  console.log('BACK: Set auth cookie');
};

// PROTECTED PREMIUM CONTENT
app.use('/subscriptions', requireAuth, async (req, res, next) => {
  try {
    const [[user]] = await pool.query('SELECT subscription_status FROM users WHERE id = ?', [req.userId]);
    console.log('BACK: Subscription check - status:', user.subscription_status, 'for user ID:', req.userId);
    if (user.subscription_status !== 'active') {
      console.log('BACK: Access denied - no active sub for path:', req.path);
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
    console.error('BACK: Subscription check error:', err);
    res.status(500).send('<h1>Server Error</h1>');
  }
}, express.static(path.join(__dirname, 'subscriptions')));

// ROUTES

app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('BACK: Signup attempt - username:', username, 'email:', email);

  try {
    const [[exists]] = await pool.query('SELECT 1 FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.status(400).json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase, subscription_status) VALUES (?, ?, ?, ?, "inactive")',
      [username, email, hash, phrase]
    );
    console.log('BACK: New user created - ID:', result.insertId);

    const token = generateToken(result.insertId);
    setAuthCookie(res, token);

    res.json({ success: true, phrase, token });
  } catch (err) {
    console.error('BACK: Signup error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  const ip = req.ip;
  console.log('BACK: Login attempt - username:', username, 'IP:', ip);

  const limit = checkRateLimit(ip);
  if (limit.banned) {
    console.log('BACK: Rate limit exceeded for IP:', ip);
    return res.status(429).json({ success: false, error: `Too many attempts. Try again in ${limit.remaining}s.` });
  }

  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      recordFailure(ip);
      console.log('BACK: Login failed - no user');
      return res.status(401).json({ success: false });
    }

    const passOk = await bcrypt.compare(password, user.password_hash);
    const phraseOk = user.phrase.trim() === phrase.trim();

    if (passOk && phraseOk) {
      clearAttempts(ip);
      const token = generateToken(user.id);
      setAuthCookie(res, token);
      console.log('BACK: Login success - user ID:', user.id, 'subscription status:', user.subscription_status);
      return res.json({ success: true, token });
    } else {
      recordFailure(ip);
      console.log('BACK: Login failed - wrong credentials');
      res.status(401).json({ success: false });
    }
  } catch (err) {
    console.error('BACK: Login error:', err);
    res.status(500).json({ success: false });
  }
});

// CREATE RECURRING CHECKOUT SESSION
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
  console.log('BACK: Checkout start - price_id:', price_id, 'user ID:', req.userId);

  try {
    const [[user]] = await pool.query('SELECT email, stripe_customer_id FROM users WHERE id = ?', [req.userId]);
    console.log('BACK: User for checkout - email:', user.email, 'customer ID:', user.stripe_customer_id);
    let customer;

    if (user.stripe_customer_id) {
      customer = await stripe.customers.retrieve(user.stripe_customer_id);
      console.log('BACK: Retrieved existing customer:', customer.id);
    } else {
      customer = await stripe.customers.create({
        email: user.email,
        metadata: { userId: req.userId.toString() }
      });
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customer.id, req.userId]);
      console.log('BACK: Created new customer:', customer.id);
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
    console.log('BACK: Created checkout session - ID:', session.id, 'metadata:', session.metadata);

    res.json({ url: session.url });
  } catch (err) {
    console.error('BACK: Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// RECOVER SESSION & ACTIVATE SUBSCRIPTION
app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  console.log('BACK: Recover session start - session_id:', session_id);

  if (!session_id) {
    console.log('BACK: Recover failed - no session_id');
    return res.status(400).json({ error: 'No session_id' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    console.log('BACK: Retrieved session - payment_status:', session.payment_status, 'mode:', session.mode, 'metadata:', session.metadata, 'subscription:', session.subscription || 'none');

    const userId = session.metadata?.userId;
    if (!userId) {
      console.log('BACK: Recover failed - no userId in metadata');
      return res.status(400).json({ error: 'No user in session' });
    }

    if (session.payment_status !== 'paid') {
      console.log('BACK: Recover failed - payment not paid');
      return res.status(400).json({ error: 'Payment not completed' });
    }

    // Activate
    await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [userId]);
    console.log('BACK: Activated subscription for user ID:', userId);

    const token = generateToken(userId);
    setAuthCookie(res, token);
    res.json({ success: true, token });
  } catch (err) {
    console.error('BACK: Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// PROFILE — SHOW ACTIVE / INACTIVE ONLY
app.get('/api/me', requireAuth, async (req, res) => {
  console.log('BACK: /api/me request - user ID:', req.userId);
  try {
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status, stripe_customer_id FROM users WHERE id = ?',
      [req.userId]
    );
    console.log('BACK: User data - username:', user.username, 'email:', user.email, 'status:', user.subscription_status, 'customer ID:', user.stripe_customer_id);

    // Sync with Stripe if needed
    if (user.subscription_status !== 'active' && user.stripe_customer_id) {
      const subs = await stripe.subscriptions.list({ customer: user.stripe_customer_id, status: 'active' });
      console.log('BACK: Active subs from Stripe:', subs.data.length);
      if (subs.data.length > 0) {
        await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [req.userId]);
        user.subscription_status = 'active';
        console.log('BACK: Synced - activated via Stripe check');
      }
    }

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: user.subscription_status === 'active'
    });
  } catch (err) {
    console.error('BACK: Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CANCEL SUBSCRIPTION IN STRIPE + DB
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  console.log('BACK: Cancel request - user ID:', req.userId);
  try {
    const [[user]] = await pool.query('SELECT stripe_customer_id FROM users WHERE id = ?', [req.userId]);
    console.log('BACK: User customer ID for cancel:', user.stripe_customer_id);

    if (user.stripe_customer_id) {
      const subs = await stripe.subscriptions.list({ customer: user.stripe_customer_id, status: 'active' });
      console.log('BACK: Active subs to cancel:', subs.data.length);
      for (const sub of subs.data) {
        await stripe.subscriptions.update(sub.id, { cancel_at_period_end: true });
        console.log('BACK: Updated sub to cancel at period end:', sub.id);
      }
    }

    await pool.query('UPDATE users SET subscription_status = "inactive" WHERE id = ?', [req.userId]);
    console.log('BACK: Set DB status to inactive');

    res.json({ success: true });
  } catch (err) {
    console.error('BACK: Cancel error:', err);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// STRIPE WEBHOOK
app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    console.log('BACK: Webhook received - type:', event.type, 'id:', event.id);
  } catch (err) {
    console.error('BACK: Webhook signature failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        console.log('BACK: Webhook checkout.completed - metadata:', session.metadata, 'customer:', session.customer);
        if (session.mode === 'subscription' && session.metadata?.userId) {
          await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [session.metadata.userId]);
          console.log('BACK: Webhook activated sub via checkout.completed for user:', session.metadata.userId);
        }
        break;
      }
      case 'invoice.paid': {
        const invoice = event.data.object;
        console.log('BACK: Webhook invoice.paid - customer:', invoice.customer, 'subscription:', invoice.subscription);
        if (invoice.subscription && invoice.customer) {
          const [[user]] = await pool.query('SELECT id FROM users WHERE stripe_customer_id = ?', [invoice.customer]);
          if (user) {
            await pool.query('UPDATE users SET subscription_status = "active" WHERE id = ?', [user.id]);
            console.log('BACK: Webhook kept active on renewal for user:', user.id);
          }
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        console.log('BACK: Webhook sub.deleted - customer:', sub.customer);
        const [[user]] = await pool.query('SELECT id FROM users WHERE stripe_customer_id = ?', [sub.customer]);
        if (user) {
          await pool.query('UPDATE users SET subscription_status = "inactive" WHERE id = ?', [user.id]);
          console.log('BACK: Webhook deactivated for user:', user.id);
        }
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log('BACK: Webhook payment_failed - customer:', invoice.customer);
        if (invoice.subscription && invoice.customer) {
          const [[user]] = await pool.query('SELECT id FROM users WHERE stripe_customer_id = ?', [invoice.customer]);
          if (user) {
            await pool.query('UPDATE users SET subscription_status = "inactive" WHERE id = ?', [user.id]);
            console.log('BACK: Webhook marked inactive due to failure for user:', user.id);
          }
        }
        break;
      }
      default:
        console.log('BACK: Unhandled webhook type:', event.type);
    }
  } catch (err) {
    console.error('BACK: Webhook handling error:', err);
  }

  res.json({ received: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('auth_token', { httpOnly: true, secure: true, sameSite: 'none', path: '/' });
  console.log('BACK: Logout - cookie cleared');
  res.json({ success: true });
});

app.post('/api/access-premium', async (req, res) => {
  const { token } = req.body;
  console.log('BACK: Access premium request - token provided?', !!token);

  if (!token) return res.status(401).send('<h1>Login Required</h1><p><a href="/login.html">Login</a></p>');

  const payload = verifyToken(token);
  if (!payload) return res.status(401).send('<h1>Session Expired</h1><p><a href="/login.html">Login again</a></p>');

  try {
    const [[user]] = await pool.query('SELECT subscription_status FROM users WHERE id = ?', [payload.userId]);
    console.log('BACK: Premium access check - status:', user.subscription_status, 'for user ID:', payload.userId);
    if (user.subscription_status !== 'active') {
      return res.status(403).send('<h1>Subscription Required</h1><p><a href="/profile.html">Subscribe</a></p>');
    }

    setAuthCookie(res, token);
    res.redirect('/subscriptions/premium.html');
  } catch (err) {
    console.error('BACK: Access premium error:', err);
    res.status(500).send('<h1>Server Error</h1>');
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 RECURRING SUBSCRIPTION BACKEND LIVE on port ${PORT}`);
});