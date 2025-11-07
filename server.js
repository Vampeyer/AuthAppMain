// server.js
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

const isProduction = process.env.NODE_ENV === 'production';
const SERVER_DOMAIN = isProduction ? 'https://authappmain.onrender.com' : 'http://localhost:3000';
const FRONTEND_DOMAIN = process.env.FRONTEND_DOMAIN || (isProduction ? 'https://techsport.app/streampaltest/public' : 'http://localhost:3000');

// Middleware setup
app.use(cookieParser());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'https://techsport.app', 'https://spauth.techsport.app'],
  credentials: true
}));

// Webhook route with raw body parser (must be first)
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  console.log('📥 Webhook request received');
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('✅ Webhook verified:', { type: event.type, id: event.id });
  } catch (err) {
    console.error('💥 Webhook verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    console.log('🛒 Checkout session completed:', { sessionId: session.id, mode: session.mode });
    if (session.mode === 'subscription' && session.subscription && session.metadata.userId) {
      const subscriptionId = session.subscription;
      const userId = session.metadata.userId;
      const customerId = session.customer;
      console.log('🔍 Checking user existence for ID:', userId);
      const [rows] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
      if (rows.length === 0) {
        console.error('💥 User not found:', userId);
        return res.status(400).json({ error: 'User not found' });
      }
      console.log('📤 Updating user subscription:', { userId, subscriptionId, customerId });
      await pool.execute(
        'UPDATE users SET customer_id = ?, subscription_id = ?, subscription_active = TRUE WHERE id = ?',
        [customerId, subscriptionId, userId]
      );
      console.log('✅ Subscription activated:', { userId, subscriptionId, customerId });
    }
  } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const subscription = event.data.object;
    console.log('📤 Deactivating subscription:', subscription.id);
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
      [subscription.id]
    );
    console.log('✅ Subscription deactivated:', subscription.id);
  }

  res.json({ received: true });
});

// Subscription folder middleware (only for local/development)
async function checkSubscription(req, res, next) {
  console.log('🔒 Checking subscription access');
  const token = req.cookies?.authToken;
  if (!token) {
    console.error('❌ No token for subscription content');
    return res.status(403).send(`
      <script>
        alert('This page is for subscriptions. Please subscribe to access premium content.');
        window.location.href = '/profile.html';
      </script>
    `);
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('🔍 Fetching subscription status for user ID:', decoded.id);
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0 || !rows[0].subscription_active) {
      console.log('❌ Subscription check failed for user ID:', decoded.id);
      return res.status(403).send(`
        <script>
          alert('This page is for subscriptions. Please subscribe to access premium content.');
          window.location.href = '/profile.html';
        </script>
      `);
    }
    console.log('✅ Subscription check passed for user ID:', decoded.id);
    next();
  } catch (error) {
    console.error('💥 Subscription check error:', error.message);
    return res.status(403).send(`
      <script>
        alert('This page is for subscriptions. Please subscribe to access premium content.');
        window.location.href = '/profile.html';
      </script>
    `);
  }
}

if (!isProduction) {
  // Only serve protected static in local mode
  app.use('/subscription', checkSubscription, express.static(path.join(__dirname, 'public', 'subscription')));
}

// Other middleware
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));

if (!isProduction) {
  // Only serve general static in local mode
  app.use(express.static(path.join(__dirname, 'public')));
  app.get('/', (req, res) => {
    console.log('🏠 Serving root index.html locally');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// MySQL setup (add more logs)
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
    console.log('🔌 Attempting MySQL connection');
    await pool.getConnection();
    console.log('✅ MySQL Connected');
    console.log('📤 Applying database schema updates');
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_active BOOLEAN DEFAULT FALSE`);
    console.log('✅ Schema updates applied');
  } catch (err) {
    console.error('❌ MySQL Connection Error:', err.message);
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
  console.log('🔑 Verifying token');
  const token = req.cookies?.authToken;
  if (!token) {
    console.error('❌ No token in request');
    return res.status(403).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    console.log('✅ Token verified for user ID:', req.userId);
    next();
  } catch (error) {
    console.error('❌ Invalid token:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/signup', async (req, res) => {
  console.log('🔥 SIGNUP request:', req.body);
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      console.error('❌ Missing fields in signup');
      return res.status(400).json({ error: 'Missing fields' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    console.log('🔍 Checking for existing user:', { username, email });
    // ... (rest of your signup code, add logs similarly to try/catch blocks)
    // Truncated for brevity, but add console.log before/after DB inserts and errors
  } catch (error) {
    console.error('💥 Signup error:', error.message);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Add similar console logs to /login, /profile, /create-checkout-session, /verify-session, /delete-subscription, /check-subscription, /logout
// For example, in /login:
app.post('/login', async (req, res) => {
  console.log('🔐 LOGIN request:', req.body);
  try {
    // ... your code ...
    console.log('🔍 Querying user:', { login });
    // After query
    console.log('✅ User found, checking password');
    // etc.
  } catch (error) {
    console.error('💥 Login error:', error.message);
  }
});

// Update success_url in /create-checkout-session to use FRONTEND_DOMAIN
// In the session creation:
const session = await stripe.checkout.sessions.create({
  // ... your code ...
  success_url: `${FRONTEND_DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
  cancel_url: `${FRONTEND_DOMAIN}/cancel.html`,
  // ...
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} (Production: ${isProduction})`);
});