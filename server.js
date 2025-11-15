// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'supersecret123!@#';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_i93P8B7vfplPpweehki6wKdWozoJGhmZ';

// Stripe price IDs
const PRICE_WEEKLY = 'price_1SIBPkFF2HALdyFkogiGJG5w'; // 7 days for $2.95
const PRICE_MONTHLY = 'price_1SIBCzFF2HALdyFk7vOxByGq'; // 30 days for $7.75

// Dynamic DOMAIN based on environment
let DOMAIN;
if (process.env.NODE_ENV === 'production') {
  DOMAIN = process.env.DOMAIN || 'https://techsport.app/streampaltest/public';
} else {
  DOMAIN = 'http://localhost:3000';
}

console.log('🌍 Server DOMAIN set to:', DOMAIN);
console.log('🔧 Environment:', process.env.NODE_ENV || 'development');

// MySQL Pool
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

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:3000',
  'https://techsport.app',
  'https://www.techsport.app',
  'https://spauth.techsport.app',
  'https://authappmain.onrender.com',
  'https://movies-auth-app.onrender.com'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn('⚠️ CORS request from unlisted origin:', origin);
      callback(null, true); // Allow for dev; set false in prod
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// JWT Verification Middleware (from Authorization header)
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

// Health Check
app.get('/', (req, res) => res.send('Server running'));

// Sign Up
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

    const mnemonic = generateMnemonic(); // Implement or use bip39 library
    const hash = await bcrypt.hash(password, 10);

    await pool.execute(
      'INSERT INTO users (username, email, password_hash, mnemonic) VALUES (?, ?, ?, ?)',
      [username, email, hash, mnemonic]
    );

    res.json({ success: true, mnemonic });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login - Return JWT
app.post('/login', async (req, res) => {
  try {
    const { login, password, mnemonic } = req.body;
    if (!login || !password || !mnemonic) return res.status(400).json({ error: 'All fields required' });

    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE (username = ? OR email = ?) AND mnemonic = ?',
      [login, login, mnemonic]
    );

    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile
app.get('/profile', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT username, email, subscription_active FROM users WHERE id = ?', [req.userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = rows[0];
    res.json({
      username: user.username,
      email: user.email,
      subscription_active: user.subscription_active
    });
  } catch (error) {
    console.error('Profile error:', error.message);
    res.status(500).json({ error: 'Profile failed' });
  }
});

// Create Checkout Session
app.post('/create-checkout-session', verifyToken, async (req, res) => {
  try {
    const { type } = req.body;
    const priceId = type.toUpperCase() === 'WEEKLY' ? PRICE_WEEKLY : PRICE_MONTHLY;
    if (!priceId) return res.status(400).json({ error: 'Invalid type' });

    const [rows] = await pool.execute('SELECT customer_id, email FROM users WHERE id = ?', [req.userId]);
    const user = rows[0];
    let customerId = user.customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
    } else {
      try {
        await stripe.customers.retrieve(customerId);
      } catch (err) {
        if (err.code === 'resource_missing') {
          const customer = await stripe.customers.create({ email: user.email });
          customerId = customer.id;
          await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
        } else {
          throw err;
        }
      }
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

    res.json({ url: session.url });
  } catch (error) {
    console.error('Checkout error:', error.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// Verify Session (for success page)
app.post('/verify-session', verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'No session ID' });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.mode !== 'subscription' || !session.subscription) return res.status(400).json({ error: 'Invalid session' });
    const [rows] = await pool.execute('SELECT id, customer_id FROM users WHERE id = ?', [req.userId]);
    if (rows.length === 0) return res.status(400).json({ error: 'User not found' });
    if (!rows[0].customer_id) {
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [session.customer, req.userId]);
    }
    await pool.execute(
      'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?',
      [session.subscription, req.userId]
    );
    res.json({ active: true });
  } catch (error) {
    console.error('Verify session error:', error.message);
    res.status(500).json({ error: 'Session verification failed' });
  }
});

// Cancel Subscription
app.post('/delete-subscription', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id = ?', [req.userId]);
    const subscriptionId = rows[0]?.subscription_id;
    if (!subscriptionId) return res.status(400).json({ error: 'No subscription' });

    await stripe.subscriptions.cancel(subscriptionId);
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE id = ?',
      [req.userId]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Cancel error:', error.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// Check Subscription
app.get('/check-subscription', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [req.userId]);
    res.json({ active: rows[0]?.subscription_active || false });
  } catch (error) {
    console.error('Check subscription error:', error.message);
    res.status(500).json({ error: 'Check failed' });
  }
});

// Webhook (unchanged)
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.mode === 'subscription' && session.subscription && session.metadata.userId) {
      const subscriptionId = session.subscription;
      const userId = session.metadata.userId;
      const customerId = session.customer;
      await pool.execute(
        'UPDATE users SET customer_id = ?, subscription_id = ?, subscription_active = TRUE WHERE id = ?',
        [customerId, subscriptionId, userId]
      );
    }
  } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const subscription = event.data.object;
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
      [subscription.id]
    );
  }

  res.json({ received: true });
});

// Helper: Generate Mnemonic (simple example; use bip39 for production)
function generateMnemonic() {
  const words = ['apple', 'banana', 'cat', 'dog', 'elephant', 'fox', 'grape', 'horse', 'ice', 'juice', 'kite', 'lemon'];
  return Array.from({ length: 12 }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Domain: ${DOMAIN}`);
});