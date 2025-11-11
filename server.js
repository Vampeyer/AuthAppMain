// server.js - FULL FILE WITH EXTRA CONSOLE LOGS (deploy to Render)
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
console.log('🔑 JWT SECRET length:', SECRET_KEY.length);
console.log('💳 Stripe key present:', !!process.env.STRIPE_SECRET_KEY);

// ---- FIXED CORS WITH EXTRA LOGS ----
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

app.use((req, res, next) => {
  console.log(`📥 Incoming request: ${req.method} ${req.path} from origin: ${req.headers.origin || 'no-origin'} | User-Agent: ${req.headers['user-agent']?.substring(0, 50)}...`);
  next();
});

app.use(cors({
  origin: function(origin, callback) {
    console.log('🔍 CORS check for origin:', origin || 'no-origin');
    // Allow requests with no origin (mobile/curl/Postman)
    if (!origin) {
      console.log('✅ CORS: No origin - allowed');
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      console.log('✅ CORS allowed for:', origin);
      res.header('Access-Control-Allow-Origin', origin);  // ← EXPLICITLY SET HEADER
      res.header('Access-Control-Allow-Credentials', 'true');
      return callback(null, true);
    } else {
      console.warn('⚠️ CORS blocked origin:', origin);
      return callback(new Error('CORS blocked - origin not allowed'));
    }
  },
  credentials: true,  // ← COOKIES/JWT
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// Handle preflight OPTIONS explicitly with logs
app.options('*', (req, res) => {
  console.log('🔄 Handling OPTIONS preflight for:', req.path, 'from origin:', req.headers.origin);
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie');
  res.sendStatus(200);
});

app.use(cookieParser());
console.log('🍪 Cookie parser enabled');

// Webhook (before other bodyParser) - with logs
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  console.log('🪝 Webhook received:', req.headers['stripe-signature'] ? 'signed' : 'unsigned');
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('✅ Webhook processed:', event.type, 'ID:', event.id);
  } catch (err) {
    console.error('💥 Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    console.log('💳 Checkout completed for user:', session.metadata.userId, 'subscription:', session.subscription);
    if (session.mode === 'subscription' && session.subscription && session.metadata.userId) {
      const subscriptionId = session.subscription;
      const userId = session.metadata.userId;
      const customerId = session.customer;
      try {
        const [rows] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
        if (rows.length > 0) {
          await pool.execute(
            'UPDATE users SET customer_id = ?, subscription_id = ?, subscription_active = TRUE WHERE id = ?',
            [customerId, subscriptionId, userId]
          );
          console.log('✅ Subscription activated in DB for user:', userId);
        } else {
          console.error('❌ User not found for webhook:', userId);
        }
      } catch (dbErr) {
        console.error('💥 DB error in webhook:', dbErr.message);
      }
    }
  } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const subscription = event.data.object;
    console.log('🗑️ Subscription canceled:', subscription.id);
    try {
      await pool.execute(
        'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
        [subscription.id]
      );
      console.log('✅ Subscription deactivated in DB');
    } catch (dbErr) {
      console.error('💥 DB error in cancel webhook:', dbErr.message);
    }
  } else {
    console.log('📝 Webhook type ignored:', event.type);
  }

  res.json({ received: true });
});

// Subscription middleware - with logs
async function checkSubscription(req, res, next) {
  console.log('🔒 Checking subscription for path:', req.path);
  const token = req.cookies?.authToken;
  console.log('🍪 Token present:', !!token);
  
  if (!token) {
    console.error('❌ No token for subscription access');
    return res.status(403).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('✅ Token decoded, user ID:', decoded.id);
    
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [decoded.id]);
    console.log('👤 User subscription status:', rows[0]?.subscription_active);
    
    if (rows.length === 0) {
      console.error('❌ User not found for ID:', decoded.id);
      return res.status(403).json({ error: 'User not found' });
    }
    
    if (!rows[0].subscription_active) {
      console.error('❌ Subscription inactive for user:', decoded.id);
      return res.status(403).json({ error: 'Subscription required' });
    }
    
    console.log('✅ Subscription check passed');
    next();
  } catch (error) {
    console.error('💥 Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Other middleware - with logs
app.use(bodyParser.json({ limit: '100mb' }));
console.log('📦 Body parser JSON enabled');
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));
console.log('📦 Body parser URL encoded enabled');
app.use('/subscription', checkSubscription, express.static(path.join(__dirname, 'public', 'subscription')));
console.log('📁 Static subscription folder protected');
app.use(express.static(path.join(__dirname, 'public')));
console.log('📁 Public static files served');

// Routes
app.get('/', (req, res) => {
  console.log('🏠 Root route hit');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  console.log('❤️ Health check - OK');
  res.json({ status: 'OK', timestamp: new Date().toISOString(), env: process.env.NODE_ENV });
});

// MySQL setup - with logs
const dbConfig = {
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD ? '***HIDDEN***' : 'MISSING',
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
console.log('🗄️ MySQL config loaded (password hidden)');
const pool = mysql.createPool(dbConfig);

async function connectDB() {
  try {
    const conn = await pool.getConnection();
    console.log('✅ MySQL connection successful');
    conn.release();
    
    const [tables] = await pool.execute('SHOW TABLES LIKE "users"');
    if (tables.length === 0) {
      await pool.execute(`CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        email VARCHAR(255) UNIQUE,
        password_hash VARCHAR(255),
        mnemonic TEXT,
        customer_id VARCHAR(255),
        subscription_id VARCHAR(255),
        subscription_active BOOLEAN DEFAULT FALSE
      )`);
      console.log('✅ Users table created');
    } else {
      console.log('✅ Users table exists');
    }
  } catch (err) {
    console.error('❌ MySQL connection failed:', err.message);
    console.error('Full error:', err);
  }
}
connectDB();

const wordList = ['apple', 'banana', 'cat', 'dog', 'elephant', 'fox', 'grape', 'horse', 'ice', 'jungle', 'kiwi', 'lemon', 'monkey', 'nut', 'orange', 'pear', 'queen', 'rabbit', 'snake', 'tiger', 'umbrella', 'violet', 'whale', 'xray', 'yellow', 'zebra'];

function generateMnemonic() {
  let mnemonic = [];
  for (let i = 0; i < 12; i++) {
    mnemonic.push(wordList[Math.floor(Math.random() * wordList.length)]);
  }
  const phrase = mnemonic.join(' ');
  console.log('🔑 Generated mnemonic (first 20 chars):', phrase.substring(0, 20) + '...');
  return phrase;
}

async function verifyToken(req, res, next) {
  console.log('🔐 Verifying token for:', req.path);
  const token = req.cookies?.authToken;
  console.log('🍪 Token length:', token ? token.length : 0);
  
  if (!token) {
    console.error('❌ No token provided');
    return res.status(403).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('✅ Token verified for user ID:', decoded.id, 'expires:', new Date(decoded.exp * 1000).toISOString());
    req.userId = decoded.id;
    next();
  } catch (error) {
    console.error('💥 Token invalid:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Signup - with detailed logs
app.post('/signup', async (req, res) => {
  console.log('🔥 Signup attempt - body:', req.body);
  try {
    const { username, email, password } = req.body;
    console.log('📝 Signup fields - username:', username ? 'present' : 'missing', 'email:', email ? 'present' : 'missing', 'password length:', password ? password.length : 0);
    
    if (!username || !email || !password) {
      console.error('❌ Missing fields in signup');
      return res.status(400).json({ error: 'Missing fields' });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    console.log('🔒 Password hashed');
    const mnemonic = generateMnemonic();

    await pool.execute(
      'INSERT INTO users (username, email, password_hash, mnemonic) VALUES (?, ?, ?, ?)',
      [username, email, password_hash, mnemonic]
    );
    console.log('✅ User inserted - ID auto-generated');

    console.log('🎉 Signup success for:', username);
    res.json({ mnemonic, success: true });
  } catch (error) {
    console.error('💥 Signup error:', error.code, error.message);
    if (error.code === 'ER_DUP_ENTRY') {
      console.error('❌ Duplicate username/email');
      return res.status(400).json({ error: 'Username or email exists' });
    }
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login - with detailed logs
app.post('/login', async (req, res) => {
  console.log('🔐 Login attempt - body keys:', Object.keys(req.body));
  console.log('📝 Login fields - login length:', req.body.login ? req.body.login.length : 0, 'password length:', req.body.password ? req.body.password.length : 0, 'mnemonic length:', req.body.mnemonic ? req.body.mnemonic.length : 0);
  
  try {
    const { login, password, mnemonic } = req.body;
    if (!login || !password || !mnemonic) {
      console.error('❌ Missing fields in login');
      return res.status(400).json({ error: 'All fields required' });
    }

    console.log('🔍 Querying user for login:', login.substring(0, 10) + '...', 'mnemonic first words:', mnemonic.split(' ').slice(0, 2).join(' ') + '...');
    const [rows] = await pool.execute(
      'SELECT id, username, password_hash, mnemonic FROM users WHERE (username = ? OR email = ?) AND mnemonic = ?',
      [login, login, mnemonic]
    );
    console.log('👤 Query returned', rows.length, 'rows');

    if (rows.length === 0) {
      console.error('❌ No user found for login/mnemonic');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    console.log('🔑 Comparing passwords for user ID:', user.id);
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      console.error('❌ Password mismatch for user ID:', user.id);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '7d' });
    console.log('🍪 Setting JWT cookie for user ID:', user.id);
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ success: true });
    console.log('🎉 Login success for user ID:', user.id);
  } catch (error) {
    console.error('💥 Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile - with detailed logs
app.get('/profile', verifyToken, async (req, res) => {
  console.log('👤 Profile request for user ID:', req.userId);
  try {
    const [rows] = await pool.execute(
      'SELECT username, email, subscription_active, subscription_id FROM users WHERE id = ?',
      [req.userId]
    );
    console.log('📊 Profile query returned', rows.length, 'rows');

    if (rows.length === 0) {
      console.error('❌ User not found for profile ID:', req.userId);
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = {
      username: rows[0].username,
      email: rows[0].email,
      subscription_active: rows[0].subscription_active
    };
    console.log('📤 Sending profile data:', { username: userData.username, subActive: userData.subscription_active });
    res.json(userData);
  } catch (error) {
    console.error('💥 Profile query error:', error.message);
    res.status(500).json({ error: 'Profile failed' });
  }
});

// Create Checkout Session - with logs
app.post('/create-checkout-session', verifyToken, async (req, res) => {
  console.log('💳 Create checkout for user ID:', req.userId, 'type:', req.body.type);
  try {
    const { type } = req.body;
    const priceId = type.toUpperCase() === 'WEEKLY' ? PRICE_WEEKLY : PRICE_MONTHLY;
    console.log('💰 Selected price ID:', priceId);
    if (!priceId) return res.status(400).json({ error: 'Invalid type' });

    const [rows] = await pool.execute('SELECT customer_id, email FROM users WHERE id = ?', [req.userId]);
    console.log('🛒 User data for Stripe:', { customerId: rows[0]?.customer_id, email: rows[0]?.email });
    const user = rows[0];
    let customerId = user.customer_id;

    if (!customerId) {
      console.log('👤 Creating new Stripe customer');
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('✅ New customer created:', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${DOMAIN}/profile?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/profile`,
      metadata: { userId: req.userId.toString() }
    });
    console.log('🔗 Checkout session created:', session.id, 'url:', session.url.substring(0, 50) + '...');
    res.json({ url: session.url });
  } catch (error) {
    console.error('💥 Checkout creation error:', error.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// Verify Session - with logs
app.post('/verify-session', verifyToken, async (req, res) => {
  console.log('🔍 Verify session for user ID:', req.userId, 'session ID:', req.body.sessionId);
  try {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'No session ID' });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    console.log('📋 Retrieved session mode:', session.mode, 'subscription:', session.subscription);
    if (session.mode !== 'subscription' || !session.subscription) return res.status(400).json({ error: 'Invalid session' });
    
    await pool.execute(
      'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?',
      [session.subscription, req.userId]
    );
    console.log('✅ Session verified and subscription activated');
    res.json({ active: true });
  } catch (error) {
    console.error('💥 Session verify error:', error.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Delete Subscription - with logs
app.post('/delete-subscription', verifyToken, async (req, res) => {
  console.log('🗑️ Cancel subscription for user ID:', req.userId);
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id = ?', [req.userId]);
    const subscriptionId = rows[0]?.subscription_id;
    console.log('💸 Current subscription ID:', subscriptionId);
    if (!subscriptionId) return res.status(400).json({ error: 'No subscription' });

    await stripe.subscriptions.cancel(subscriptionId);
    console.log('✅ Stripe subscription canceled');
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE id = ?',
      [req.userId]
    );
    console.log('✅ DB updated - subscription deactivated');
    res.json({ success: true });
  } catch (error) {
    console.error('💥 Cancel error:', error.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// Check Subscription - with logs
app.get('/check-subscription', verifyToken, async (req, res) => {
  console.log('✅ Check subscription for user ID:', req.userId);
  try {
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [req.userId]);
    const active = rows[0]?.subscription_active || false;
    console.log('📊 Subscription active:', active);
    res.json({ active });
  } catch (error) {
    console.error('💥 Check subscription error:', error.message);
    res.status(500).json({ error: 'Check failed' });
  }
});

// Logout - with logs
app.post('/logout', (req, res) => {
  console.log('🚪 Logout request - clearing cookie');
  const token = req.cookies?.authToken;
  console.log('🍪 Clearing token length:', token ? token.length : 0);
  res.clearCookie('authToken');
  res.json({ success: true });
  console.log('✅ Logout complete');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`🌍 Full domain: ${DOMAIN}`);
  console.log(`📡 CORS allowed origins: ${allowedOrigins.join(', ')}`);
});