// server.js
// ===============================================
// FULL SERVER – CORS + FALLBACK + PRICES
// ===============================================

require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const IS_PROD = process.env.NODE_ENV === 'production';

// ===============================================
// CONFIG – EDIT ONLY THIS BLOCK
// ===============================================
const CONFIG = {
  RENDER_ORIGIN: 'https://authappmain.onrender.com',
  LIVE_SERVER_ORIGIN: 'http://127.0.0.1:5500',
  DEV_SERVER_ORIGIN: 'http://localhost:3000',
  PROD_ORIGIN: 'https://authappmain.onrender.com',
  STRIPE_DOMAIN: IS_PROD ? 'https://authappmain.onrender.com' : 'http://localhost:3000'
};

const allowedOrigins = [
  CONFIG.RENDER_ORIGIN,
  CONFIG.LIVE_SERVER_ORIGIN,   // ← LIVE SERVER
  CONFIG.DEV_SERVER_ORIGIN,
  CONFIG.PROD_ORIGIN
];

let DOMAIN = CONFIG.STRIPE_DOMAIN;

// ===============================================
// CORS – allow Live Server
// ===============================================
app.use(cors({
  origin: function (origin, callback) {
    console.log('[CORS] Request from origin:', origin);
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// ===============================================
// MIDDLEWARE
// ===============================================
app.use(cookieParser());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ===============================================
// MYSQL POOL
// ===============================================
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

// ===============================================
// JWT OPTIONAL
// ===============================================
function verifyTokenOptional(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) {
    req.userId = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    req.userId = null;
    next();
  }
}

// ===============================================
// COOKIE OPTIONS
// ===============================================
function getCookieOptions() {
  return {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
    sameSite: 'none',
    secure: true
  };
}

// ===============================================
// LOGIN
// ===============================================
app.post('/login', async (req, res) => {
  const { login, password, mnemonic } = req.body;
  if (!login || !password || !mnemonic) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [login, login]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch || user.mnemonic !== mnemonic) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('authToken', token, getCookieOptions());
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ===============================================
// PROFILE
// ===============================================
app.get('/profile', verifyTokenOptional, async (req, res) => {
  if (!req.userId) {
    return res.json({ loggedIn: false });
  }

  try {
    const [rows] = await pool.execute(
      'SELECT username, email, subscription_active FROM users WHERE id = ?',
      [req.userId]
    );

    if (rows.length === 0) {
      return res.json({ loggedIn: false });
    }

    const user = rows[0];
    res.json({
      loggedIn: true,
      username: user.username,
      email: user.email,
      subscription_active: user.subscription_active === 1
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

// ===============================================
// PRICES
// ===============================================
const PRICES = {
  WEEKLY: {
    id: 'price_1SIBPkFF2HALdyFkogiGJG5w',
    amount: 499,
    currency: 'usd',
    label: '$4.99 / week'
  },
  MONTHLY: {
    id: 'price_1SIBCzFF2HALdyFk7vOxByGq',
    amount: 1499,
    currency: 'usd',
    label: '$14.99 / month'
  }
};

// ===============================================
// CREATE CHECKOUT SESSION
// ===============================================
app.post('/create-checkout-session', verifyTokenOptional, async (req, res) => {
  if (!req.userId) {
    return res.status(401).json({ error: 'Login required' });
  }

  const { type } = req.body;
  const price = PRICES[type.toUpperCase()];

  if (!price) {
    return res.status(400).json({ error: 'Invalid subscription type' });
  }

  try {
    const [rows] = await pool.execute(
      'SELECT customer_id, email FROM users WHERE id = ?',
      [req.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    let customerId = rows[0].customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: rows[0].email });
      customerId = customer.id;
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: price.id, quantity: 1 }],
      success_url: `${DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/cancel.html`,
      metadata: { userId: req.userId.toString() }
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Checkout error:', error.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// ===============================================
// LOGOUT
// ===============================================
app.post('/logout', (req, res) => {
  res.clearCookie('authToken', { path: '/', sameSite: 'none', secure: true });
  res.json({ success: true });
});

// ===============================================
// SERVER START
// ===============================================
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log('MySQL connected successfully');
    connection.release();
  } catch (error) {
    console.error('MySQL failed:', error.message);
  }

  app.listen(PORT, () => {
    console.log(`Server running at ${CONFIG.DEV_SERVER_ORIGIN}`);
    console.log(`Primary API: ${CONFIG.RENDER_ORIGIN}`);
    console.log(`Live Server allowed: ${CONFIG.LIVE_SERVER_ORIGIN}`);
  });
})();