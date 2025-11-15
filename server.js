// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'supersecret123!@#';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_i93P8B7vfplPpweehki6wKdWozoJGhmZ';

// ------------------------------------------------------------------
// 1. DOMAIN (used for Stripe success/cancel URLs)
// ------------------------------------------------------------------
let DOMAIN;
if (process.env.NODE_ENV === 'production') {
  DOMAIN = process.env.DOMAIN || 'https://techsport.app/streampaltest/public';
} else {
  DOMAIN = 'http://localhost:3000';
}
console.log('Server DOMAIN (Stripe redirects):', DOMAIN);

// ------------------------------------------------------------------
// 2. MySQL Pool
// ------------------------------------------------------------------
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
console.log('MySQL pool created');

// ------------------------------------------------------------------
// 3. CORS – FIXED (always send Access-Control-Allow-Credentials: true)
// ------------------------------------------------------------------
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:3000',
  'https://techsport.app',
  'https://www.techsport.app',
  'https://authappmain.onrender.com'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      console.log('CORS allowed for origin:', origin || 'no-origin');
      callback(null, true);
    } else {
      console.warn('CORS blocked (dev only) for origin:', origin);
      callback(null, true); // ← change to false in strict prod
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ------------------------------------------------------------------
// 4. Middleware
// ------------------------------------------------------------------
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ------------------------------------------------------------------
// 5. Health endpoint
// ------------------------------------------------------------------
app.get('/', (req, res) => {
  console.log('Health check – 200 OK');
  res.send('Server running');
});

// ------------------------------------------------------------------
// 6. JWT verification middleware
// ------------------------------------------------------------------
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    console.warn('verifyToken – missing/invalid Authorization header');
    return res.status(401).json({ error: 'Unauthorized – no token' });
  }
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    console.log('verifyToken – success, userId:', req.userId);
    next();
  } catch (err) {
    console.warn('verifyToken – invalid/expired token');
    return res.status(401).json({ error: 'Unauthorized – invalid token' });
  }
}

// ------------------------------------------------------------------
// 7. SIGN-UP
// ------------------------------------------------------------------
app.post('/signup', async (req, res) => {
  console.log('SIGNUP request received:', req.body);
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      console.warn('SIGNUP – missing fields');
      return res.status(400).json({ error: 'All fields required' });
    }

    const mnemonic = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);
    console.log('SIGNUP – hashing password & generating mnemonic');

    await pool.execute(
      'INSERT INTO users (username, email, password_hash, mnemonic) VALUES (?, ?, ?, ?)',
      [username, email, hash, mnemonic]
    );
    console.log('SIGNUP – user inserted, username:', username);
    res.json({ success: true, mnemonic });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      console.warn('SIGNUP – duplicate username/email');
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    console.error('SIGNUP – unexpected error:', err.message);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// ------------------------------------------------------------------
// 8. LOGIN – returns JWT
// ------------------------------------------------------------------
app.post('/login', async (req, res) => {
  console.log('LOGIN request received:', req.body);
  try {
    const { login, password, mnemonic } = req.body;
    if (!login || !password || !mnemonic) {
      console.warn('LOGIN – missing fields');
      return res.status(400).json({ error: 'All fields required' });
    }

    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE (username = ? OR email = ?) AND mnemonic = ?',
      [login, login, mnemonic]
    );

    if (rows.length === 0) {
      console.warn('LOGIN – credentials/mnemonic mismatch');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      console.warn('LOGIN – password mismatch');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '7d' });
    console.log('LOGIN – success, userId:', user.id, 'JWT issued');
    res.json({ success: true, token });
  } catch (err) {
    console.error('LOGIN – unexpected error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ------------------------------------------------------------------
// 9. PROFILE
// ------------------------------------------------------------------
app.get('/profile', verifyToken, async (req, res) => {
  console.log('PROFILE request – userId:', req.userId);
  try {
    const [rows] = await pool.execute(
      'SELECT username, email, subscription_active FROM users WHERE id = ?',
      [req.userId]
    );
    if (rows.length === 0) {
      console.warn('PROFILE – user not found');
      return res.status(404).json({ error: 'User not found' });
    }
    const user = rows[0];
    console.log('PROFILE – data returned for', user.username);
    res.json({
      username: user.username,
      email: user.email,
      subscription_active: user.subscription_active
    });
  } catch (err) {
    console.error('PROFILE – error:', err.message);
    res.status(500).json({ error: 'Profile failed' });
  }
});

// ------------------------------------------------------------------
// 10. CREATE CHECKOUT SESSION
// ------------------------------------------------------------------
app.post('/create-checkout-session', verifyToken, async (req, res) => {
  console.log('CHECKOUT request – userId:', req.userId, 'body:', req.body);
  try {
    const { type } = req.body;
    const priceId = type.toUpperCase() === 'WEEKLY' ? 'price_1SIBPkFF2HALdyFkogiGJG5w' : 'price_1SIBCzFF2HALdyFk7vOxByGq';
    if (!priceId) {
      console.warn('CHECKOUT – invalid type');
      return res.status(400).json({ error: 'Invalid subscription type' });
    }

    const [rows] = await pool.execute('SELECT customer_id, email FROM users WHERE id = ?', [req.userId]);
    const user = rows[0];
    let customerId = user.customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('CHECKOUT – new Stripe customer created:', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/cancel.html`,
      metadata: { userId: req.userId.toString() }
    });

    console.log('CHECKOUT – session created, id:', session.id);
    res.json({ url: session.url });
  } catch (err) {
    console.error('CHECKOUT – error:', err.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// ------------------------------------------------------------------
// 11. VERIFY SESSION
// ------------------------------------------------------------------
app.post('/verify-session', verifyToken, async (req, res) => {
  console.log('VERIFY-SESSION request – userId:', req.userId, 'body:', req.body);
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      console.warn('VERIFY-SESSION – missing sessionId');
      return res.status(400).json({ error: 'No session ID' });
    }
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.mode !== 'subscription' || !session.subscription) {
      console.warn('VERIFY-SESSION – not a subscription session');
      return res.status(400).json({ error: 'Invalid session' });
    }

    await pool.execute(
      'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?',
      [session.subscription, req.userId]
    );
    console.log('VERIFY-SESSION – subscription activated, subId:', session.subscription);
    res.json({ active: true });
  } catch (err) {
    console.error('VERIFY-SESSION – error:', err.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ------------------------------------------------------------------
// 12. CANCEL SUBSCRIPTION
// ------------------------------------------------------------------
app.post('/delete-subscription', verifyToken, async (req, res) => {
  console.log('CANCEL request – userId:', req.userId);
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id = ?', [req.userId]);
    const subId = rows[0]?.subscription_id;
    if (!subId) {
      console.warn('CANCEL – no active subscription');
      return res.status(400).json({ error: 'No subscription' });
    }

    await stripe.subscriptions.cancel(subId);
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE id = ?',
      [req.userId]
    );
    console.log('CANCEL – subscription cancelled, subId:', subId);
    res.json({ success: true });
  } catch (err) {
    console.error('CANCEL – error:', err.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// ------------------------------------------------------------------
// 13. CHECK SUBSCRIPTION
// ------------------------------------------------------------------
app.get('/check-subscription', verifyToken, async (req, res) => {
  console.log('CHECK-SUB request – userId:', req.userId);
  try {
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [req.userId]);
    const active = !!rows[0]?.subscription_active;
    console.log('CHECK-SUB – active:', active);
    res.json({ active });
  } catch (err) {
    console.error('CHECK-SUB – error:', err.message);
    res.status(500).json({ error: 'Check failed' });
  }
});

// ------------------------------------------------------------------
// 14. STRIPE WEBHOOK
// ------------------------------------------------------------------
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('WEBHOOK received – type:', event.type);
  } catch (err) {
    console.error('WEBHOOK signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.mode === 'subscription' && session.subscription && session.metadata.userId) {
      const { userId, subscription: subId, customer } = session;
      await pool.execute(
        'UPDATE users SET customer_id = ?, subscription_id = ?, subscription_active = TRUE WHERE id = ?',
        [customer, subId, userId]
      );
      console.log('WEBHOOK – subscription activated via webhook, userId:', userId, 'subId:', subId);
    }
  } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const sub = event.data.object;
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
      [sub.id]
    );
    console.log('WEBHOOK – subscription deactivated, subId:', sub.id);
  }

  res.json({ received: true });
});

// ------------------------------------------------------------------
// 15. Helper – simple 12-word mnemonic
// ------------------------------------------------------------------
function generateMnemonic() {
  const words = ['apple','banana','cat','dog','elephant','fox','grape','horse','ice','juice','kite','lemon'];
  return Array.from({ length: 12 }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
}

// ------------------------------------------------------------------
// 16. Start server
// ------------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Stripe success/cancel domain: ${DOMAIN}`);
});