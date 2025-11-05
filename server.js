// server.js
// ===============================================
// FULL SERVER – ALL FUNCTIONS DEFINED + 500 FIXED
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

// ---------- CLEAN STRIPE KEY ----------
let rawKey = process.env.STRIPE_SECRET_KEY || '';
rawKey = rawKey.trim().replace(/[' "]/g, '');   // remove spaces / quotes
if (!rawKey) throw new Error('STRIPE_SECRET_KEY missing');
console.log('[STRIPE] key (first 10):', rawKey.substring(0, 10) + '...');
const stripe = require('stripe')(rawKey);

// ---------- APP & CONFIG ----------
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
app.use(express.static(path.join(__dirname, 'public')));

// ---------- MYSQL POOL ----------
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

// ---------- JWT HELPERS ----------
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
  } catch (e) {
    req.userId = null;
    next();
  }
}

async function verifyTokenRequired(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ error: 'Login required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- WORD LIST & MNEMONIC ----------
const wordList = ['apple','banana','cat','dog','elephant','fox','grape','horse','ice','jungle','kiwi','lemon',
                  'monkey','nut','orange','pear','queen','rabbit','snake','tiger','umbrella','violet',
                  'whale','xray','yellow','zebra'];

function generateMnemonic() {
  const words = [];
  for (let i = 0; i < 12; i++) words.push(wordList[Math.floor(Math.random() * wordList.length)]);
  return words.join(' ');
}

// ---------- SUBSCRIPTION FOLDER PROTECTION ----------
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

// ---------- STRIPE WEBHOOK ----------
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
  catch (e) { return res.status(400).send(`Webhook Error: ${e.message}`); }

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    if (s.mode === 'subscription' && s.subscription && s.metadata.userId) {
      await pool.execute(
        'UPDATE users SET customer_id=?, subscription_id=?, subscription_active=TRUE WHERE id=?',
        [s.customer, s.subscription, s.metadata.userId]
      );
    }
  } else if (['customer.subscription.deleted','customer.subscription.canceled'].includes(event.type)) {
    const sub = event.data.object;
    await pool.execute('UPDATE users SET subscription_id=NULL, subscription_active=FALSE WHERE subscription_id=?', [sub.id]);
  }
  res.json({ received: true });
});

// ---------- SIGNUP (phrase generated on server) ----------
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
  } catch (e) { res.status(500).json({ error: 'Signup failed' }); }
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
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
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
  } catch (e) { res.status(500).json({ error:'Profile load failed' }); }
});

// ---------- PRICE IDs ----------
const PRICES = {
  WEEKLY:  { id:'price_1SIBPkFF2HALdyFkogiGJG5w', amount:295, label:'$2.95 / week' },
  MONTHLY: { id:'price_1SIBCzFF2HALdyFk7vOxByGq', amount:775, label:'$7.75 / month' }
};

// ---------- CREATE CHECKOUT SESSION ----------
app.post('/create-checkout-session', verifyTokenRequired, async (req, res) => {
  const { type } = req.body;
  const price = PRICES[type.toUpperCase()];
  if (!price) return res.status(400).json({ error:'Invalid type' });

  try {
    const [rows] = await pool.execute('SELECT customer_id,email FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.status(404).json({ error:'User not found' });

    let customerId = rows[0].customer_id;
    if (!customerId) {
      const cust = await stripe.customers.create({ email:rows[0].email });
      customerId = cust.id;
      await pool.execute('UPDATE users SET customer_id=? WHERE id=?', [customerId, req.userId]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price:price.id, quantity:1 }],
      success_url: `${DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/cancel.html`,
      metadata: { userId: req.userId.toString() }
    });

    console.log('[checkout] created:', session.id, session.url);
    res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout] error:', e.message);
    res.status(500).json({ error:'Checkout failed' });
  }
});

// ---------- CANCEL SUBSCRIPTION ----------
app.post('/delete-subscription', verifyTokenRequired, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id=?', [req.userId]);
    const subId = rows[0]?.subscription_id;
    if (!subId) return res.status(400).json({ error:'No subscription' });

    await stripe.subscriptions.cancel(subId);
    await pool.execute('UPDATE users SET subscription_id=NULL, subscription_active=FALSE WHERE id=?', [req.userId]);
    res.json({ success:true });
  } catch (e) { res.status(500).json({ error:'Cancel failed' }); }
});

// ---------- LOGOUT ----------
app.post('/logout', (req, res) => {
  res.clearCookie('authToken', { path:'/', sameSite:'strict', secure:IS_PROD });
  res.json({ success:true });
});

// ---------- START SERVER ----------
(async () => {
  try {
    await pool.getConnection();
    console.log('MySQL connected');
  } catch (e) { console.error('MySQL error:', e.message); }

  app.listen(PORT, () => console.log(`Server listening on ${PORT} – DOMAIN: ${DOMAIN}`));
})();