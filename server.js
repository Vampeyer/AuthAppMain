// server.js – CommonJS (works on Node 22+)
require('dotenv').config();                     // <-- load .env first
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------
// 1. MySQL connection pool
// ---------------------------------------------------------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'authapp',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ---------------------------------------------------------------------
// 2. Session store
// ---------------------------------------------------------------------
const sessionStore = new MySQLStore({}, pool);

app.use(
  session({
    key: 'session_cookie',
    secret: process.env.SESSION_SECRET || 'fallback-secret',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7   // 7 days
    }
  })
);

// ---------------------------------------------------------------------
// 3. Middleware
// ---------------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/streampaltest/public', express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------
// 4. Helper: ensure logged-in user
// ---------------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ---------------------------------------------------------------------
// 5. ROUTES
// ---------------------------------------------------------------------

// ---- Home (static) ---------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---- Signup ---------------------------------------------------------
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, hash]
    );
    res.json({ success: true });
  } catch (e) {
    console.error('Signup error:', e);
    res.status(400).json({ error: e.sqlMessage || 'Signup failed' });
  }
});

// ---- Login -----------------------------------------------------------
app.post('/login', async (req, res) => {
  const { login, password, mnemonic } = req.body;   // login = username or email
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?',
      [login, login]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // optional mnemonic check can go here

    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ success: true });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- Logout ---------------------------------------------------------
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ---- Profile --------------------------------------------------------
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT u.username, u.email,
              s.active AS subscription_active
         FROM users u
         LEFT JOIN subscriptions s ON u.id = s.user_id AND s.active = 1
        WHERE u.id = ?`,
      [req.session.userId]
    );
    const user = rows[0];
    res.json({
      username: user.username,
      email: user.email,
      subscription_active: !!user.subscription_active
    });
  } catch (e) {
    console.error('Profile error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---- Create Stripe checkout session ---------------------------------
app.post('/create-checkout-session', requireAuth, async (req, res) => {
  const { type } = req.body;               // WEEKLY or MONTHLY
  const priceId =
    type === 'WEEKLY'
      ? process.env.STRIPE_PRICE_WEEKLY
      : process.env.STRIPE_PRICE_MONTHLY;

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.BASE_URL}/streampaltest/public/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/streampaltest/public/cancel.html`,
      client_reference_id: req.session.userId.toString()
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe error:', e);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// ---- Verify Stripe webhook (success) --------------------------------
app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook sig error:', err);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.client_reference_id;
      const subId = session.subscription;

      // simple activation – you can expand with invoice.paid etc.
      await pool.execute(
        `INSERT INTO subscriptions (user_id, stripe_sub_id, active)
         VALUES (?, ?, 1)
         ON DUPLICATE KEY UPDATE active = 1`,
        [userId, subId]
      );
    }
    res.json({ received: true });
  }
);

// ---- Delete / cancel subscription ------------------------------------
app.post('/delete-subscription', requireAuth, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE subscriptions SET active = 0 WHERE user_id = ? AND active = 1',
      [req.session.userId]
    );
    res.json({ success: true });
  } catch (e) {
    console.error('Cancel error:', e);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// ---- Check subscription (for movie_content.html) --------------------
app.get('/check-subscription', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT active FROM subscriptions WHERE user_id = ? AND active = 1',
      [req.session.userId]
    );
    res.json({ active: rows.length > 0 });
  } catch (e) {
    console.error('Check-sub error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------------------------------------------------------
// 6. Start server
// ---------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`   Public folder → http://localhost:${PORT}/streampaltest/public`);
});