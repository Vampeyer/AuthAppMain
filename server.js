const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-2025';

// CORS
app.use(cors({ origin: 'https://techsport.app', credentials: true }));
app.use(express.json());

// DB Pool
let pool;
async function initDb() {
  pool = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT || 3306,
    waitForConnections: true,
    connectionLimit: 10
  });
  await pool.getConnection().catch(err => {
    console.error('DB CONNECTION FAILED:', err);
    process.exit(1);
  });
  console.log('MySQL Connected');
}

// Auth Middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = user.id;
    next();
  });
}

// Routes
app.get('/', (req, res) => res.json({ status: 'API OK' }));

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const [e] = await pool.query('SELECT id FROM users WHERE username=? OR email=?', [username, email]);
    if (e.length) return res.status(400).json({ error: 'User exists' });
    const hash = await bcrypt.hash(password, 10);
    const mnemonic = Array.from({length:12},()=>['cat','dog','ice','apple'][Math.floor(Math.random()*4)]).join(' ');
    const [r] = await pool.query('INSERT INTO users (username,email,password_hash,mnemonic) VALUES (?,?,?,?)', [username,email,hash,mnemonic]);
    const token = jwt.sign({ id: r.insertId }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, mnemonic });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/login', async (req, res) => {
  const { login, password, mnemonic } = req.body;
  try {
    const [u] = await pool.query('SELECT id,password_hash,mnemonic FROM users WHERE username=? OR email=?', [login,login]);
    if (!u.length || u[0].mnemonic !== mnemonic) return res.status(400).json({ error: 'Invalid' });
    if (!await bcrypt.compare(password, u[0].password_hash)) return res.status(400).json({ error: 'Invalid' });
    const token = jwt.sign({ id: u[0].id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.get('/profile', auth, async (req, res) => {
  const [r] = await pool.query('SELECT username,email,subscription_active FROM users WHERE id=?', [req.userId]);
  res.json(r[0] || { error: 'Not found' });
});

app.get('/check-subscription', auth, async (req, res) => {
  const [r] = await pool.query('SELECT subscription_active FROM users WHERE id=?', [req.userId]);
  res.json({ active: !!r[0]?.subscription_active });
});

app.post('/create-checkout-session', auth, async (req, res) => {
  const { type } = req.body;
  const prices = { WEEKLY: 'price_1xxx', MONTHLY: 'price_1yyy' };
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{ price: prices[type], quantity: 1 }],
    mode: 'subscription',
    success_url: `https://techsport.app/streampaltest/public/success.html?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `https://techsport.app/streampaltest/public/profile.html`,
    client_reference_id: req.userId.toString()
  });
  res.json({ url: session.url });
});

app.post('/confirm-subscription', auth, async (req, res) => {
  const { session_id } = req.body;
  const session = await stripe.checkout.sessions.retrieve(session_id);
  if (session.payment_status === 'paid') {
    await pool.query('UPDATE users SET subscription_active=1, stripe_session_id=? WHERE id=?', [session_id, req.userId]);
    res.json({ success: true });
  } else res.status(400).json({ error: 'Not paid' });
});

app.post('/delete-subscription', auth, async (req, res) => {
  await pool.query('UPDATE users SET subscription_active=0, stripe_session_id=NULL WHERE id=?', [req.userId]);
  res.json({ success: true });
});

// Start
initDb().then(() => app.listen(PORT, () => console.log(`Server on ${PORT}`)));