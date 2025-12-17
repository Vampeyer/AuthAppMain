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



// ================================================================================
// STEP 2: REPLACE /api/me WITH THIS VERSION (Accurate Time Display)
// ================================================================================

app.get('/api/me', requireAuth, async (req, res) => {
  console.log('👤 PROFILE REQUEST → User ID:', req.userId);
  try {
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    const now = Math.floor(Date.now() / 1000);
    let active = user.subscription_status === 'active' && user.subscription_period_end > now;

    // Auto-expire if period ended
    if (user.subscription_status === 'active' && user.subscription_period_end <= now) {
      await pool.query('UPDATE users SET subscription_status = "inactive", subscription_period_end = 0 WHERE id = ?', [req.userId]);
      active = false;
    }

    // Calculate time remaining in different units
    const secondsLeft = active ? (user.subscription_period_end - now) : 0;
    const minutesLeft = Math.ceil(secondsLeft / 60);
    const hoursLeft = Math.ceil(secondsLeft / 3600);
    const daysLeft = Math.ceil(secondsLeft / 86400);

    console.log('   Subscription active:', active);
    console.log('   Time left:', secondsLeft, 'seconds =', minutesLeft, 'minutes =', hoursLeft, 'hours =', daysLeft, 'days');

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: active,
      seconds_left: secondsLeft,     // For accurate display
      minutes_left: minutesLeft,     // Minutes
      hours_left: hoursLeft,         // Hours
      days_left: daysLeft,           // Days (backward compatibility)
      period_end: user.subscription_period_end, // Raw timestamp
      current_time: now              // Server time
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});





// ================================================================================
// EXAMPLE: ADD 1 HOUR SUBSCRIPTION - COMPLETE CODE
// Copy and paste these sections into your server.js
// ================================================================================

// ==================== STEP 1: UPDATE /api/recover-session ====================
// Find this section in your server.js and ADD the new price condition

app.get('/api/recover-session', async (req, res) => {
  const { session_id } = req.query;
  console.log('🔄 RECOVER SESSION START → Session ID:', session_id);

  if (!session_id) {
    console.log('❌ RECOVER FAILED → No session_id');
    return res.status(400).json({ error: 'No session_id' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    console.log('📦 SESSION RETRIEVED → Status:', session.payment_status, 'Mode:', session.mode);

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

    // EXISTING PRICES
    if (priceId === 'price_1SYeXVFF2HALdyFkMR0pVo2u') {
      periodEnd = now + 7 * 86400; // Weekly (7 days = 604,800 seconds)
      console.log('⏰ WEEKLY access granted → 7 days');
    } 
    else if (priceId === 'price_1SYeY3FF2HALdyFk8znKF3un') {
      periodEnd = now + 30 * 86400; // Monthly (30 days = 2,592,000 seconds)
      console.log('⏰ MONTHLY access granted → 30 days');
    } 
    else if (priceId === 'price_1SYeZVFF2HALdyFkxBfvFuTJ') {
      periodEnd = now + 365 * 86400; // Yearly (365 days = 31,536,000 seconds)
      console.log('⏰ YEARLY access granted → 365 days');
    }
    
    // ========================================
    // ADD YOUR NEW PRICES HERE:
    // ========================================
    
    // 5 MINUTES ACCESS
    else if (priceId === 'price_1SeMmCFF2HALdyFk4gylCDXx') {
      periodEnd = now + 5 * 60; // 5 minutes = 300 seconds
      console.log('⏰ 5 MINUTE access granted');
    }
    
    // // 1 HOUR ACCESS
    // else if (priceId === 'price_YOUR_1HOUR_PRICE_ID_HERE') {
    //   periodEnd = now + 60 * 60; // 1 hour = 3,600 seconds
    //   console.log('⏰ 1 HOUR access granted');
    // }
    
    // // 3 HOURS ACCESS
    // else if (priceId === 'price_YOUR_3HOUR_PRICE_ID_HERE') {
    //   periodEnd = now + 3 * 60 * 60; // 3 hours = 10,800 seconds
    //   console.log('⏰ 3 HOURS access granted');
    // }

    
    // ========================================
    // END OF NEW PRICES
    // ========================================
    
    else {
      console.log('❌ RECOVER FAILED → Unknown priceId:', priceId);
      return res.status(400).json({ error: 'Unknown product' });
    }

    console.log('📅 Period End:', periodEnd, '→', new Date(periodEnd * 1000));

    await pool.query(
      'UPDATE users SET subscription_status = "active", subscription_period_end = ? WHERE id = ?',
      [periodEnd, userId]
    );

    console.log('✅ ACCESS ACTIVATED → User ID:', userId);

    const token = generateToken(userId);
    setAuthCookie(res, token);
    res.json({ success: true, token });
  } catch (err) {
    console.error('Recover error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});



// ================================================================================
// STEP 3: UPDATE PRICE IDs AT BOTTOM OF FILE (For Reference)
// ================================================================================

/* 
SUBSCRIPTION PRICE IDs:

⚡ QUICK ACCESS:
5min   - $0.25  → price_YOUR_5MIN_PRICE_ID_HERE
1hr    - $0.99  → price_YOUR_1HOUR_PRICE_ID_HERE
3hr    - $1.99  → price_YOUR_3HOUR_PRICE_ID_HERE
12hr   - $4.99  → price_YOUR_12HOUR_PRICE_ID_HERE
24hr   - $7.99  → price_YOUR_24HOUR_PRICE_ID_HERE

📅 EXTENDED ACCESS:
Weekly  - $2.95  → price_1SYeXVFF2HALdyFkMR0pVo2u
Monthly - $7.75  → price_1SYeY3FF2HALdyFk8znKF3un
Yearly  - $75.00 → price_1SYeZVFF2HALdyFkxBfvFuTJ
*/


// ================================================================================
// QUICK REFERENCE: TIME CALCULATIONS
// ================================================================================

/*
COMMON DURATION CALCULATIONS:

Minutes:
5 min   = 5 * 60           = 300
10 min  = 10 * 60          = 600
15 min  = 15 * 60          = 900
30 min  = 30 * 60          = 1,800

Hours:
1 hr    = 60 * 60          = 3,600
2 hr    = 2 * 60 * 60      = 7,200
3 hr    = 3 * 60 * 60      = 10,800
6 hr    = 6 * 60 * 60      = 21,600
12 hr   = 12 * 60 * 60     = 43,200
24 hr   = 24 * 60 * 60     = 86,400

Days:
1 day   = 24 * 60 * 60     = 86,400
7 days  = 7 * 24 * 60 * 60 = 604,800
30 days = 30 * 24 * 60 * 60 = 2,592,000

Formula:
periodEnd = now + (duration_in_seconds)
*/


// ================================================================================
// TESTING YOUR NEW DURATIONS
// ================================================================================

/*
For testing, temporarily change to very short durations:

// Test 1 minute instead of 1 hour
periodEnd = now + 60; // 1 minute

// Test 5 seconds instead of 5 minutes
periodEnd = now + 5; // 5 seconds

This way you can see the expiration happen quickly without waiting!

Remember to change back to real durations before production deployment.
*/




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





// Debug Subscription 

app.get('/api/debug-subscription', requireAuth, async (req, res) => {
  try {
    const [[user]] = await pool.query(
      'SELECT id, username, subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );
    
    const now = Math.floor(Date.now() / 1000);
    const nowMs = Date.now();
    
    const periodEnd = user.subscription_period_end;
    const difference = periodEnd - now;
    
    console.log('🔍 DEBUG SUBSCRIPTION CHECK:');
    console.log('   User ID:', user.id);
    console.log('   Username:', user.username);
    console.log('   Status:', user.subscription_status);
    console.log('   Period End (raw from DB):', periodEnd);
    console.log('   Current time (seconds):', now);
    console.log('   Current time (ms):', nowMs);
    console.log('   Difference:', difference, 'seconds');
    console.log('   Difference:', Math.floor(difference / 60), 'minutes');
    console.log('   Difference:', Math.floor(difference / 3600), 'hours');
    console.log('   Period End as Date:', new Date(periodEnd * 1000));
    console.log('   Current time as Date:', new Date(now * 1000));
    
    res.json({
      user_id: user.id,
      username: user.username,
      status: user.subscription_status,
      period_end_raw: periodEnd,
      period_end_date: new Date(periodEnd * 1000).toISOString(),
      current_time_seconds: now,
      current_time_date: new Date(now * 1000).toISOString(),
      difference_seconds: difference,
      difference_minutes: Math.floor(difference / 60),
      difference_hours: Math.floor(difference / 3600),
      looks_correct: difference >= 250 && difference <= 350 // Should be ~300 for 5 minutes
    });
  } catch (err) {
    console.error('Debug error:', err);
    res.status(500).json({ error: 'Debug failed' });
  }
});