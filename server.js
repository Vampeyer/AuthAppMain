// server.js
// ===============================================
// LOGIN + SIGNUP + SUBSCRIPTION (NO WEBHOOK)
// ===============================================

require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');

// ---------- STRIPE ----------
let rawKey = process.env.STRIPE_SECRET_KEY || '';
rawKey = rawKey.trim().replace(/[' "\r\n]/g, '');
if (!rawKey) throw new Error('STRIPE_SECRET_KEY missing');
console.log('[STRIPE] key (first 10):', rawKey.substring(0, 10) + '...');

const stripe = require('stripe')(rawKey, {
  apiVersion: '2023-10-16',
  maxNetworkRetries: 0,
  timeout: 10000
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123!@#';
const IS_PROD = process.env.NODE_ENV === 'production';
const DOMAIN = IS_PROD ? 'https://authappmain.onrender.com' : 'http://localhost:3000';

// ---------- CORS ----------
app.use(cors({
  origin: [
    'http://127.0.0.1:5500',
    'http://localhost:3000',
    'https://techsport.app',
    'https://authappmain.onrender.com'
  ],
  credentials: true
}));

// ---------- MIDDLEWARE ----------
app.use(cookieParser());
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));  // AFTER ALL ROUTES

// ---------- MYSQL ----------
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

// Auto-add columns
(async () => {
  try {
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_active BOOLEAN DEFAULT FALSE`);
    console.log('[DB] Schema ready');
  } catch (e) { console.error('[DB] Schema error:', e.message); }
})();

// ---------- JWT ----------
function verifyTokenOptional(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) { req.userId = null; return next(); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) { req.userId = null; next(); }
}

async function verifyTokenRequired(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

// ---------- MNEMONIC ----------
function generateMnemonic() {
  const list = ['apple','banana','cat','dog','elephant','fox','grape','horse','ice','jungle','kiwi','lemon',
                'monkey','nut','orange','pear','queen','rabbit','snake','tiger','umbrella','violet',
                'whale','xray','yellow','zebra'];
  const words = [];
  for (let i = 0; i < 12; i++) words.push(list[Math.floor(Math.random() * list.length)]);
  return words.join(' ');
}

// ---------- SUBSCRIPTION FOLDER ----------
async function checkSubscription(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.status(403).send(`<script>alert('Subscribe to access premium content.');location='/profile.html';</script>`);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0 || !rows[0].subscription_active) {
      return res.status(403).send(`<script>alert('Subscribe to access premium content.');location='/profile.html';</script>`);
    }
    next();
  } catch (e) {
    return res.status(403).send(`<script>alert('Subscribe to access premium content.');location='/profile.html';</script>`);
  }
}
app.use('/subscription', checkSubscription, express.static(path.join(__dirname, 'public', 'subscription')));

// ---------- SIGNUP ----------
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

  try {
    const [exists] = await pool.execute('SELECT id FROM users WHERE username=? OR email=?', [username, email]);
    if (exists.length) return res.status(400).json({ error: 'User exists' });

    const mnemonic = generateMnemonic();
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username,email,password_hash,mnemonic) VALUES (?,?,?,?)',
      [username, email, hash, mnemonic]
    );

    const token = jwt.sign({ id: result.insertId }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('authToken', token, { httpOnly:true, secure:IS_PROD, sameSite:'strict', maxAge:7*24*60*60*1000 });
    res.json({ success:true, mnemonic });
  } catch (e) { 
    console.error('[signup] error:', e.message);
    res.status(500).json({ error: 'Signup failed' }); 
  }
});

// ---------- LOGIN ----------
app.post('/login', async (req, res) => {
  const { login, password, mnemonic } = req.body;
  if (!login || !password || !mnemonic) return res.status(400).json({ error: 'All fields required' });

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username=? OR email=?', [login, login]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match || user.mnemonic !== mnemonic) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('authToken', token, { httpOnly:true, secure:IS_PROD, sameSite:'strict', maxAge:7*24*60*60*1000 });
    res.json({ success:true });
  } catch (e) { 
    console.error('[login] error:', e.message);
    res.status(500).json({ error: 'Login failed' }); 
  }
});

// ---------- PROFILE ----------
app.get('/profile', verifyTokenOptional, async (req, res) => {
  if (!req.userId) return res.json({ loggedIn:false });

  try {
    const [rows] = await pool.execute('SELECT username,email,subscription_active FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.json({ loggedIn:false });

    const u = rows[0];
    res.json({
      loggedIn:true,
      username:u.username,
      email:u.email,
      subscription_active: !!u.subscription_active
    });
  } catch (e) { 
    console.error('[profile] error:', e.message);
    res.status(500).json({ error:'Profile load failed' }); 
  }
});

// ---------- PRICES ----------
const PRICES = {
  WEEKLY:  { id: 'price_1SIBPkFF2HALdyFkogiGJG5w', amount: 295, label: '$2.95 / week' },
  MONTHLY: { id: 'price_1SIBCzFF2HALdyFk7vOxByGq', amount: 775, label: '$7.75 / month' }
};

// ---------- CHECKOUT ----------
app.post('/create-checkout-session', verifyTokenRequired, async (req, res) => {
  const { type } = req.body;
  const price = PRICES[type.toUpperCase()];
  if (!price) return res.status(400).json({ error: 'Invalid type' });

  try {
    await stripe.prices.retrieve(price.id);

    const [rows] = await pool.execute('SELECT customer_id,email FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });

    let customerId = rows[0].customer_id;
    if (!customerId) {
      const cust = await stripe.customers.create({ email: rows[0].email });
      customerId = cust.id;
      await pool.execute('UPDATE users SET customer_id=? WHERE id=?', [customerId, req.userId]);
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

    console.log(`[checkout] created: ${session.id}`);
    res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout] error:', e.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// ---------- VERIFY SESSION (FALLBACK) ----------
app.post('/verify-session', verifyTokenRequired, async (req, res) => {
  const { session_id } = req.body;
  if (!session_id) return res.status(400).json({ error: 'No session_id' });

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['subscription'] });
    if (session.payment_status !== 'paid' || !session.subscription) {
      return res.status(400).json({ error: 'Not paid' });
    }

    const subId = typeof session.subscription === 'object' ? session.subscription.id : session.subscription;

    await pool.execute(
      `UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?`,
      [subId, req.userId]
    );

    console.log(`[verify] SUBSCRIPTION ACTIVATED | user: ${req.userId} | sub: ${subId}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[verify] error:', e.message);
    res.status(500).json({ error: 'Failed' });
  }
});

// ---------- CANCEL ----------
app.post('/delete-subscription', verifyTokenRequired, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id=?', [req.userId]);
    const subId = rows[0]?.subscription_id;
    if (!subId) return res.status(400).json({ error: 'No subscription' });

    await stripe.subscriptions.cancel(subId);
    await pool.execute('UPDATE users SET subscription_id=NULL, subscription_active=FALSE WHERE id=?', [req.userId]);
    res.json({ success: true });
  } catch (e) {
    console.error('[cancel] error:', e.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// ---------- LOGOUT ----------
app.post('/logout', (req, res) => {
  res.clearCookie('authToken', { path:'/', sameSite:'strict', secure:IS_PROD });
  res.json({ success: true });
});

// ---------- START ----------
app.listen(PORT, async () => {
  try {
    await pool.getConnection();
    console.log('MySQL connected');
  } catch (e) { console.error('MySQL error:', e.message); }
  console.log(`Server on ${PORT} | DOMAIN: ${DOMAIN}`);
});