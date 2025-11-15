// server.js - Movies App Backend
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // Set in Render

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-prod';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

app.use(cors({
  origin: 'https://techsport.app',
  credentials: true
}));
app.use(express.json());

// MySQL Pool
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware: Verify JWT
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = user.id;
    next();
  });
}

// Health Check
app.get('/', (req, res) => res.json({ status: 'API running' }));

// SIGNUP
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const [existing] = await pool.query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existing.length > 0) return res.status(400).json({ error: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    const mnemonic = generateMnemonic();

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, mnemonic) VALUES (?, ?, ?, ?)',
      [username, email, hash, mnemonic]
    );

    const token = jwt.sign({ id: result.insertId }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, mnemonic });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  const { login, password, mnemonic } = req.body;
  if (!login || !password || !mnemonic) return res.status(400).json({ error: 'Missing fields' });

  try {
    const [users] = await pool.query(
      'SELECT id, password_hash, mnemonic FROM users WHERE username = ? OR email = ?',
      [login, login]
    );
    if (users.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

    const user = users[0];
    if (user.mnemonic !== mnemonic) return res.status(400).json({ error: 'Invalid mnemonic' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PROFILE
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT username, email, subscription_active FROM users WHERE id = ?',
      [req.userId]
    );
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(users[0]);
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CHECK SUBSCRIPTION
app.get('/check-subscription', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT subscription_active FROM users WHERE id = ?',
      [req.userId]
    );
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ active: users[0].subscription_active });
  } catch (err) {
    console.error('Check sub error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CREATE CHECKOUT SESSION
app.post('/create-checkout-session', authenticateToken, async (req, res) => {
  const { type } = req.body;
  if (!type || !['WEEKLY', 'MONTHLY'].includes(type)) return res.status(400).json({ error: 'Invalid type' });

  const prices = {
    WEEKLY: 'price_1QExampleWeekly123',
    MONTHLY: 'price_1QExampleMonthly123'
  };

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price: prices[type],
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `https://techsport.app/streampaltest/public/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `https://techsport.app/streampaltest/public/profile.html`,
      client_reference_id: req.userId.toString(),
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: 'Payment setup failed' });
  }
});

// CONFIRM SUBSCRIPTION (called from success.html)
app.post('/confirm-subscription', authenticateToken, async (req, res) => {
  const { session_id } = req.body;
  if (!session_id) return res.status(400).json({ error: 'Missing session_id' });

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    await pool.query(
      'UPDATE users SET subscription_active = TRUE, stripe_session_id = ? WHERE id = ?',
      [session_id, req.userId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Confirm error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE SUBSCRIPTION
app.post('/delete-subscription', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'UPDATE users SET subscription_active = FALSE, stripe_session_id = NULL WHERE id = ?',
      [req.userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Generate 12-word mnemonic
function generateMnemonic() {
  const words = ['apple', 'banana', 'cat', 'dog', 'elephant', 'fish', 'grape', 'horse', 'ice', 'jungle', 'kiwi', 'lemon', 'mango', 'orange', 'pear', 'queen', 'rabbit', 'strawberry', 'tiger', 'umbrella', 'violet', 'watermelon', 'xray', 'yellow', 'zebra'];
  return Array.from({ length: 12 }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
}

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});