require('dotenv').config({ path: '.env.production' });

console.log('=== BACKEND STARTING ===');
console.log('BACKEND URL →', process.env.APP_URL || 'http://localhost:3000');
console.log('DB CONNECTING →', process.env.DB_HOST, '/', process.env.DB_NAME);
console.log('DB USER →', process.env.DB_USER);
console.log('Environment →', process.env.NODE_ENV);

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { register, login, generateToken, verifyToken, generateMnemonic } = require('./auth');
const pool = require('./db');

const app = express();

// === WEBHOOK FIRST (raw body) ===
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log('Webhook received →', event.type);

    if (event.type === 'invoice.paid') {
      const sub = await stripe.subscriptions.retrieve(event.data.object.subscription);
      const customer = await stripe.customers.retrieve(sub.customer);
      const userId = customer.metadata?.userId || sub.metadata.userId;
      const endTime = sub.current_period_end;

      if (userId) {
        await pool.query(
          `UPDATE users SET stripe_subscription_id=?, subscription_status='active', subscription_period_end=? WHERE id=?`,
          [sub.id, endTime, userId]
        );
        console.log(`Subscription ACTIVATED → User ${userId}`);
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const customer = await stripe.customers.retrieve(sub.customer);
      const userId = customer.metadata?.userId;
      if (userId) {
        await pool.query('UPDATE users SET subscription_status="inactive", subscription_period_end=NULL, stripe_subscription_id=NULL WHERE id=?', [userId]);
        console.log(`Subscription CANCELLED → User ${userId}`);
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('Webhook failed:', err.message);
    res.status(400).send('Webhook error');
  }
});


// === CORS FIX — THIS IS ALL YOU NEED ===
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 
    req.headers.origin || 'http://localhost:3000' || 'https://techsport.app'
  );
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});
console.log('CORS enabled for localhost and techsport.app');

// === REST OF YOUR CODE (UNCHANGED) ===



app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// === AUTH MIDDLEWARE ===
const requireAuth = (req, res, next) => {
  const payload = verifyToken(req.cookies.jwt);
  if (!payload) {
    console.log('Auth failed — no valid token');
    return res.send('<script>alert("Please login");location="/login.html"</script>');
  }
  req.userId = payload.userId;
  console.log('User authenticated → ID:', req.userId);
  next();
};

// === API ROUTES ===
app.post('/api/signup', async (req, res) => {
  console.log('Signup attempt →', req.body.username);
  try {
    const phrase = generateMnemonic();
    await register({ ...req.body, phrase });
    console.log('Signup SUCCESS →', req.body.username);
    res.json({ success: true, phrase });
  } catch (e) {
    console.log('Signup FAILED →', e.message);
    res.status(400).json({ success: false, error: 'Username or email taken' });
  }
});

app.post('/api/login', async (req, res) => {
  console.log('Login attempt →', req.body.username);
  try {
    const user = await login(req.body);
    if (!user) throw new Error('Invalid credentials');
    res.cookie('jwt', generateToken(user.id), { httpOnly: true, sameSite: 'none', secure: true, maxAge: 604800000 });
    console.log('Login SUCCESS → User ID:', user.id);
    res.json({ success: true });
  } catch {
    console.log('Login FAILED → Wrong credentials');
    res.status(401).json({ success: false });
  }
});

app.get('/api/logout', (req, res) => {
  res.clearCookie('jwt', { sameSite: 'none', secure: true });
  res.json({ success: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [[u]] = await pool.query('SELECT username,email,subscription_status,subscription_period_end FROM users WHERE id=?', [req.userId]);
    const now = Math.floor(Date.now() / 1000);
    const active = u.subscription_status === 'active' && u.subscription_period_end > now;
    const daysLeft = active ? Math.ceil((u.subscription_period_end - now) / 86400) : 0;

    console.log(`Profile loaded → ${u.username} | Active: ${active} | Days left: ${daysLeft}`);
    res.json({ username: u.username, email: u.email, subscription_active: active, days_left: daysLeft });
  } catch (err) {
    console.error('API /me error:', err.message);
    res.status(500).json(null);
  }
});

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  // your existing working code — keep it
  // just make sure success_url uses process.env.APP_URL
});

app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  // your existing working code — keep it
});

// === PREMIUM PROTECTION ===
app.get('/subscriptions/*', requireAuth, async (req, res) => {
  const [[u]] = await pool.query('SELECT subscription_status, subscription_period_end FROM users WHERE id=?', [req.userId]);
  const now = Math.floor(Date.now() / 1000);
  const active = u.subscription_status === 'active' && u.subscription_period_end > now;

  if (!active) {
    console.log('Premium blocked → User not active');
    return res.send('<script>alert("Subscription required");location="/profile.html"</script>');
  }

  const filePath = path.join(__dirname, '../public', req.path);
  const resolved = path.resolve(filePath);
  const base = path.resolve(path.join(__dirname, '../public/subscriptions'));

  if (!resolved.startsWith(base)) {
    console.log('Blocked traversal attempt');
    return res.status(403).send('Forbidden');
  }

  res.sendFile(resolved);
});

// === CATCH-ALL (ONLY ONE!) ===
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`BACKEND LIVE → https://authappmain.onrender.com`);
  console.log(`All API calls go to: https://authappmain.onrender.com/api/...`);
});