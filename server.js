// server.js - FULL FILE (deploy to Render)
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
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
  DOMAIN = 'https://www.techsport.app/streampaltest2';  // ← FRONTEND URL for redirects
} else {
  DOMAIN = 'http://localhost:3000';
}

console.log('🌍 Server DOMAIN set to:', DOMAIN);
console.log('🔧 Environment:', process.env.NODE_ENV || 'development');

// ---- FIXED CORS: ALLOW ALL YOUR ORIGINS ----
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:3000',
  'http://localhost:5173',  // ← VITE DEV
  'https://techsport.app',
  'https://www.techsport.app',
  'https://www.techsport.app/streampaltest2',  // ← HOSTINGER PROD
  'https://spauth.techsport.app',
  'https://authappmain.onrender.com',
  'https://movies-auth-app.onrender.com'
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile/curl)
    if (!origin) {
      console.log('✅ CORS: No origin - allowed');
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      console.log('✅ CORS allowed for:', origin);
      return callback(null, true);
    } else {
      console.warn('⚠️ CORS blocked origin:', origin);
      return callback(new Error('CORS blocked'));  // ← STRICT NOW
    }
  },
  credentials: true,  // ← COOKIES/JWT
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.use(cookieParser());

// Webhook (before other bodyParser)
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('✅ Webhook:', event.type);
  } catch (err) {
    console.error('💥 Webhook error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.mode === 'subscription' && session.subscription && session.metadata.userId) {
      const subscriptionId = session.subscription;
      const userId = session.metadata.userId;
      const customerId = session.customer;
      const [rows] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
      if (rows.length > 0) {
        await pool.execute(
          'UPDATE users SET customer_id = ?, subscription_id = ?, subscription_active = TRUE WHERE id = ?',
          [customerId, subscriptionId, userId]
        );
        console.log('✅ Subscription activated:', userId);
      }
    }
  } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const subscription = event.data.object;
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
      [subscription.id]
    );
    console.log('✅ Subscription deactivated:', subscription.id);
  }

  res.json({ received: true });
});

// Subscription middleware
async function checkSubscription(req, res, next) {
  const token = req.cookies?.authToken;
  if (!token) return res.status(403).send('Subscription required');

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0 || !rows[0].subscription_active) {
      return res.status(403).send('Active subscription required');
    }
    next();
  } catch (error) {
    res.status(401).send('Invalid token');
  }
}

// Other middleware
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));
app.use('/subscription', checkSubscription, express.static(path.join(__dirname, 'public', 'subscription')));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));

// MySQL
const dbConfig = {
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
const pool = mysql.createPool(dbConfig);

async function connectDB() {
  try {
    await pool.getConnection();
    console.log('✅ MySQL Connected');
    await pool.execute(`CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE,
      email VARCHAR(255) UNIQUE,
      password_hash VARCHAR(255),
      mnemonic TEXT,
      customer_id VARCHAR(255),
      subscription_id VARCHAR(255),
      subscription_active BOOLEAN DEFAULT FALSE
    )`);
    console.log('✅ Users table ready');
  } catch (err) {
    console.error('❌ MySQL Error:', err.message);
  }
}
connectDB();

const wordList = ['apple', 'banana', 'cat', 'dog', 'elephant', 'fox', 'grape', 'horse', 'ice', 'jungle', 'kiwi', 'lemon', 'monkey', 'nut', 'orange', 'pear', 'queen', 'rabbit', 'snake', 'tiger', 'umbrella', 'violet', 'whale', 'xray', 'yellow', 'zebra'];

function generateMnemonic() {
  let mnemonic = [];
  for (let i = 0; i < 12; i++) {
    mnemonic.push(wordList[Math.floor(Math.random() * wordList.length)]);
  }
  return mnemonic.join(' ');
}

async function verifyToken(req, res, next) {
  const token = req.cookies?.authToken;
  if (!token) return res.status(403).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Signup
app.post('/signup', async (req, res) => {
  console.log('🔥 Signup:', req.body);
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    const password_hash = await bcrypt.hash(password, 10);
    const mnemonic = generateMnemonic();

    await pool.execute(
      'INSERT INTO users (username, email, password_hash, mnemonic) VALUES (?, ?, ?, ?)',
      [username, email, password_hash, mnemonic]
    );

    res.json({ mnemonic, success: true });
  } catch (error) {
    console.error('💥 Signup error:', error.message);
    if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Username or email exists' });
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login
app.post('/login', async (req, res) => {
  console.log('🔐 Login:', req.body);
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
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ success: true });
  } catch (error) {
    console.error('💥 Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile
app.get('/profile', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT username, email, subscription_active, subscription_id FROM users WHERE id = ?',
      [req.userId]
    );

    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    res.json({
      username: rows[0].username,
      email: rows[0].email,
      subscription_active: rows[0].subscription_active
    });
  } catch (error) {
    console.error('💥 Profile error:', error.message);
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
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${DOMAIN}/profile?session_id={CHECKOUT_SESSION_ID}`,  // ← FIXED REDIRECT
      cancel_url: `${DOMAIN}/profile`,
      metadata: { userId: req.userId.toString() }
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('💥 Checkout error:', error.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// Verify Session
app.post('/verify-session', verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'No session ID' });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.mode !== 'subscription' || !session.subscription) return res.status(400).json({ error: 'Invalid session' });
    await pool.execute(
      'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?',
      [session.subscription, req.userId]
    );
    res.json({ active: true });
  } catch (error) {
    console.error('💥 Verify error:', error.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Delete Subscription
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
    console.error('💥 Cancel error:', error.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// Check Subscription
app.get('/check-subscription', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [req.userId]);
    res.json({ active: rows[0]?.subscription_active || false });
  } catch (error) {
    res.status(500).json({ error: 'Check failed' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('authToken');
  res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server on port ${PORT}`);
  console.log(`🌍 Domain: ${DOMAIN}`);
});