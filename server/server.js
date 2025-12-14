// server.js — HYBRID AUTH: httpOnly Cookies + Authorization Headers
require('dotenv').config({ path: '.env.production' });

console.log('================================================');
console.log('BACKEND STARTING — HYBRID AUTH SYSTEM');
console.log('================================================');

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // npm install cookie-parser
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { generateMnemonic } = require('bip39');
const pool = require('./db');
const { checkRateLimit, recordFailure, clearAttempts } = require('./fail2ban');

const app = express();

// ==================== COOKIE PARSER ====================
app.use(cookieParser());

// ==================== CORS (UPDATED FOR COOKIES) ====================
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

  res.setHeader('Access-Control-Allow-Credentials', 'true'); // CRITICAL for cookies
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // ADDED: For form data
app.use(express.static(path.join(__dirname, '../public')));

// ==================== JWT ====================
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_EXPIRY = '20m'; // 20 minutes
const COOKIE_MAX_AGE = 20 * 60 * 1000; // 20 minutes in milliseconds

const generateToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

// ==================== HYBRID AUTH MIDDLEWARE ====================
// Checks BOTH cookies AND Authorization headers
const requireAuth = (req, res, next) => {
  console.log('🔐 AUTH CHECK for path:', req.path);
  console.log('   Cookies present?:', req.cookies ? 'YES' : 'NO');
  if (req.cookies) {
    console.log('   Cookie keys:', Object.keys(req.cookies));
    console.log('   auth_token cookie:', req.cookies.auth_token ? 'PRESENT' : 'MISSING');
  }
  console.log('   Authorization header?:', req.headers.authorization ? 'YES' : 'NO');
  
  let token = null;
  
  // Try to get token from httpOnly cookie first (preferred)
  if (req.cookies && req.cookies.auth_token) {
    token = req.cookies.auth_token;
    console.log('   ✅ Token found in cookie');
  }
  // Fallback to Authorization header (for API calls)
  else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
    console.log('   ✅ Token found in Authorization header');
  }

  if (!token) {
    console.log('   ❌ AUTH FAILED → No token for path:', req.path);
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Login Required</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login</a> to access this content.</p>
      `);
    } else {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  const payload = verifyToken(token);
  if (!payload) {
    console.log('   ❌ AUTH FAILED → Invalid token for path:', req.path);
    if (req.accepts('html')) {
      return res.status(401).send(`
        <h1>Session Expired</h1>
        <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login again</a>.</p>
      `);
    } else {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }

  req.userId = payload.userId;
  console.log('   ✅ AUTH SUCCESS → User ID:', req.userId, 'for path:', req.path);
  next();
};

// ==================== HELPER: SET AUTH COOKIE ====================
const setAuthCookie = (res, token) => {
  // For Render.com backend, we need to set cookie for the render.com domain
  // NOT for techsport.app since that's a different domain
  res.cookie('auth_token', token, {
    httpOnly: true,        // Cannot be accessed by JavaScript (XSS protection)
    secure: true,          // Only sent over HTTPS
    sameSite: 'none',      // Required for cross-origin (your setup)
    maxAge: COOKIE_MAX_AGE,
    // Remove domain restriction - let it default to current domain (render.com)
    path: '/'
  });
  console.log('🍪 Auth cookie set for current domain (onrender.com)');
};

// ==================== PROTECTED SUBSCRIPTIONS FOLDER ====================
app.use('/subscriptions', requireAuth, async (req, res, next) => {
  try {
    const [[user]] = await pool.query(
      'SELECT subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );
    const now = Math.floor(Date.now() / 1000);
    if (user.subscription_status !== 'active' || user.subscription_period_end <= now) {
      console.log('❌ ACCESS DENIED → No active subscription for path:', req.path);
      if (req.accepts('html')) {
        return res.status(403).send(`
          <h1>Subscription Required</h1>
          <p>You need an active subscription to access this content. <a href="https://techsport.app/streampaltest/public/profile.html">Subscribe here</a>.</p>
        `);
      } else {
        return res.status(403).json({ error: 'No active subscription' });
      }
    }
    next();
  } catch (err) {
    console.error('Subscription check error:', err);
    if (req.accepts('html')) {
      res.status(500).send('<h1>Server Error</h1><p>Please try again later.</p>');
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
}, express.static(path.join(__dirname, 'subscriptions')));

// ==================== ROUTES ====================

// SIGNUP — WITH COOKIE
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('📝 SIGNUP ATTEMPT →', { username, email });

  try {
    const [[exists]] = await pool.query('SELECT 1 FROM users WHERE username = ? OR email = ?', [username, email]);
    if (exists) return res.status(400).json({ success: false, error: 'Username or email taken' });

    const phrase = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (username, email, password_hash, phrase) VALUES (?, ?, ?, ?)',
      [username, email, hash, phrase]
    );

    const token = generateToken(result.insertId);
    setAuthCookie(res, token); // Set httpOnly cookie

    console.log('✅ NEW USER CREATED → ID:', result.insertId);
    res.json({ success: true, phrase, token }); // Still send token for localStorage backup
  } catch (err) {
    console.error('❌ Signup error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// LOGIN — WITH COOKIE + FAIL2BAN
app.post('/api/login', async (req, res) => {
  const { username, password, phrase } = req.body;
  const ip = req.ip;
  console.log('🔐 LOGIN ATTEMPT →', username, 'IP:', ip);

  const limit = checkRateLimit(ip);
  if (limit.banned) {
    return res.status(429).json({ success: false, error: `Too many attempts. Try again in ${limit.remaining} seconds.` });
  }

  try {
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      recordFailure(ip);
      return res.status(401).json({ success: false });
    }

    const passOk = await bcrypt.compare(password, user.password_hash);
    const phraseOk = user.phrase.trim() === phrase.trim();

    if (passOk && phraseOk) {
      const token = generateToken(user.id);
      setAuthCookie(res, token); // Set httpOnly cookie
      clearAttempts(ip);
      console.log('✅ LOGIN SUCCESS → Token generated for User ID:', user.id);
      return res.json({ success: true, token }); // Still send token for localStorage backup
    } else {
      recordFailure(ip);
      console.log('❌ LOGIN FAILED → Wrong credentials');
      res.status(401).json({ success: false });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false });
  }
});

// PROFILE + AUTO-EXPIRE
app.get('/api/me', requireAuth, async (req, res) => {
  console.log('👤 PROFILE REQUEST → User ID:', req.userId);
  try {
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    const now = Math.floor(Date.now() / 1000);
    let active = user.subscription_status === 'active' && user.subscription_period_end > now;

    if (user.subscription_status === 'active' && user.subscription_period_end <= now) {
      await pool.query('UPDATE users SET subscription_status = "inactive", subscription_period_end = 0 WHERE id = ?', [req.userId]);
      active = false;
    }

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: active,
      days_left: active ? Math.ceil((user.subscription_period_end - now) / 86400) : 0
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CHECKOUT
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  const { price_id } = req.body;
  console.log('💳 CHECKOUT START → Price ID:', price_id, 'User ID:', req.userId);

  try {
    const [[user]] = await pool.query('SELECT stripe_customer_id FROM users WHERE id = ?', [req.userId]);
    let customerId = user.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ metadata: { userId: req.userId.toString() } });
      customerId = customer.id;
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('✅ NEW CUSTOMER CREATED → ID:', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      mode: 'payment',
      success_url: `https://techsport.app/streampaltest/public/profile.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `https://techsport.app/streampaltest/public/profile.html?cancel=true`,
      metadata: { userId: req.userId.toString(), priceId: price_id }
    });

    console.log('✅ CHECKOUT SESSION CREATED → ID:', session.id);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// RECOVER + ACTIVATE ACCESS — WITH COOKIE
app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  console.log('🔄 RECOVER SESSION START → Session ID:', session_id);

  if (!session_id) {
    console.log('❌ RECOVER FAILED → No session_id');
    return res.status(400).json({ error: 'No session_id' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    console.log('📦 SESSION RETRIEVED → Status:', session.payment_status);

    const userId = session.metadata?.userId;
    if (!userId) {
      console.log('❌ RECOVER FAILED → No userId in metadata');
      return res.status(400).json({ error: 'No user in session' });
    }

    if (session.payment_status !== 'paid') {
      console.log('❌ RECOVER FAILED → Payment not paid');
      return res.status(400).json({ error: 'Payment not completed' });
    }

    const priceId = session.metadata?.priceId;
    const now = Math.floor(Date.now() / 1000);
    let periodEnd = 0;

    if (priceId === 'price_1SYeXVFF2HALdyFkMR0pVo2u') {
      periodEnd = now + 7 * 86400; // Weekly
    } else if (priceId === 'price_1SYeY3FF2HALdyFk8znKF3un') {
      periodEnd = now + 30 * 86400; // Monthly
    } else if (priceId === 'price_1SYeZVFF2HALdyFkxBfvFuTJ') {
      periodEnd = now + 365 * 86400; // Yearly
    } else {
      console.log('❌ RECOVER FAILED → Unknown priceId', priceId);
      return res.status(400).json({ error: 'Unknown product' });
    }

    await pool.query(
      'UPDATE users SET subscription_status = "active", subscription_period_end = ? WHERE id = ?',
      [periodEnd, userId]
    );

    console.log('✅ ACCESS ACTIVATED → User ID:', userId);

    const token = generateToken(userId);
    setAuthCookie(res, token); // Set/refresh the cookie
    console.log('✅ RECOVER SUCCESS → Token & Cookie set');
    res.json({ success: true, token });
  } catch (err) {
    console.error('Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// CANCEL ACCESS
app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  console.log('❌ CANCEL REQUEST → User ID:', req.userId);

  try {
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", subscription_period_end = 0 WHERE id = ?',
      [req.userId]
    );

    console.log('✅ CANCEL SUCCESS → User ID:', req.userId);
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel error:', err);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// LOGOUT — CLEAR COOKIE
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/'
  });
  console.log('🚪 User logged out, cookie cleared');
  res.json({ success: true });
});

// ====================
// ACCESS PREMIUM PAGE - SPECIAL ROUTE
// This is the KEY fix for cross-origin premium access!
// ====================
app.post('/api/access-premium', async (req, res) => {
  const { token } = req.body;
  
  console.log('🔑 ACCESS PREMIUM REQUEST RECEIVED');
  console.log('   Token provided:', token ? 'YES' : 'NO');
  console.log('   Request body:', req.body);
  
  if (!token) {
    console.log('❌ No token provided in request body');
    return res.status(401).send(`
      <h1>Login Required</h1>
      <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login</a> first.</p>
    `);
  }

  const payload = verifyToken(token);
  if (!payload) {
    console.log('❌ Invalid token - verification failed');
    return res.status(401).send(`
      <h1>Session Expired</h1>
      <p>Please <a href="https://techsport.app/streampaltest/public/login.html">login again</a>.</p>
    `);
  }

  console.log('✅ Token verified - User ID:', payload.userId);

  try {
    const [[user]] = await pool.query(
      'SELECT subscription_status, subscription_period_end FROM users WHERE id = ?',
      [payload.userId]
    );
    
    console.log('   User subscription_status:', user.subscription_status);
    console.log('   User subscription_period_end:', user.subscription_period_end);
    
    const now = Math.floor(Date.now() / 1000);
    console.log('   Current time (UNIX):', now);
    console.log('   Subscription active?:', user.subscription_status === 'active' && user.subscription_period_end > now);
    
    if (user.subscription_status !== 'active' || user.subscription_period_end <= now) {
      console.log('❌ No active subscription - access denied');
      return res.status(403).send(`
        <h1>Subscription Required</h1>
        <p>You need an active subscription to access this content. <a href="https://techsport.app/streampaltest/public/profile.html">Subscribe here</a>.</p>
      `);
    }

    // Set the cookie so subsequent requests on this domain work
    console.log('🍪 Setting auth cookie...');
    setAuthCookie(res, token);
    
    console.log('✅ Access granted! Redirecting to /subscriptions/premium.html');
    console.log('   Cookie should now be set for domain: .techsport.app');
    
    // Redirect to the premium page
    // The cookie we just set will be included in this request
    res.redirect('/subscriptions/premium.html');
    
  } catch (err) {
    console.error('❌ Access premium error:', err);
    res.status(500).send('<h1>Server Error</h1><p>Please try again later.</p>');
  }
});

// STATIC FILES
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 BACKEND IS LIVE — HYBRID AUTH SYSTEM');
  console.log(`   Listening on port ${PORT}`);
});

/* 
PRICE IDS:
W single price_1SYeXVFF2HALdyFkMR0pVo2u
M single - price_1SYeY3FF2HALdyFk8znKF3un
Y single - price_1SYeZVFF2HALdyFkxBfvFuTJ
*/

/* 
PRICE IDS:
W single price_1SYeXVFF2HALdyFkMR0pVo2u
M single - price_1SYeY3FF2HALdyFk8znKF3un
Y single - price_1SYeZVFF2HALdyFkxBfvFuTJ
*/