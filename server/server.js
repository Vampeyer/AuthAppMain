


// Load a specific .env file
require('dotenv').config({ path: '.env.development' });

// CHANGE .env file being used for development  / production  

// require('dotenv').config({ path: '.env.production' });
//require('dotenv').config();

console.log('=== SERVER STARTING ===');
console.log('Test' , process.env.TEST)
console.log('Environment: ', process.env.NODE_ENV || 'development');
console.log('DB Name: ', process.env.DB_NAME);
console.log('Stripe Key Loaded: ', process.env.STRIPE_SECRET_KEY ? 'Yes' : 'No');
console.log('Webhook Secret Loaded: ', process.env.STRIPE_WEBHOOK_SECRET ? 'Yes' : 'No');

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { register, login, generateToken, verifyToken, generateMnemonic } = require('./auth');
const pool = require('./db');

const app = express();

// Webhook (raw body required)
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    console.log('Webhook verified: ', event.type);
  } catch (err) {
    console.error('Webhook signature verification failed: ', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'invoice.paid') {
      const invoice = event.data.object;
      console.log('Invoice paid event - fetching subscription...');
      const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
      console.log('Subscription fetched: ', subscription.id);
      console.log('Subscription full object: ', JSON.stringify(subscription, null, 2)); // Log full subscription for debugging
      const customer = await stripe.customers.retrieve(subscription.customer);
      console.log('Customer fetched: ', customer.id);
      console.log('Customer full object: ', JSON.stringify(customer, null, 2)); // Log full customer for debugging
      const userId = invoice.metadata.userId || subscription.metadata.userId || customer.metadata?.userId;
      console.log('Extracted userId: ', userId);
      let endTime = subscription.current_period_end;
      console.log('Extracted endTime: ', endTime);
      console.log('EndTime type: ', typeof endTime);

      // Backup: If endTime is undefined, calculate default based on price ID
      if (!Number.isFinite(endTime)) {
        console.warn('End time invalid - calculating default');
        const priceId = invoice.lines.data[0].price.id;
        console.log('Price ID from invoice: ', priceId);
        const defaultDays = priceId === 'price_1SIBPkFF2HALdyFkogiGJG5w' ? 7 : 30; // Weekly or monthly
        endTime = Math.floor(Date.now() / 1000) + (defaultDays * 86400);
        console.log('Calculated default endTime: ', endTime);
      }

      if (userId && Number.isFinite(endTime)) {
        console.log('Updating user subscription in DB...');
        await pool.query(
          `UPDATE users SET stripe_subscription_id = ?, subscription_status = 'active', subscription_period_end = ? WHERE id = ?`,
          [subscription.id, endTime, userId]
        );
        console.log(`Subscription activated for user ${userId} until ${new Date(endTime * 1000).toLocaleString()}`);
      } else {
        console.error('Invalid user ID or end time - skipping update');
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const customer = await stripe.customers.retrieve(sub.customer);
      const userId = customer.metadata?.userId;
      if (userId) {
        await pool.query('UPDATE users SET subscription_status = "inactive", subscription_period_end = NULL WHERE id = ?', [userId]);
        console.log(`Subscription cancelled for user ${userId}`);
      }
    }
  } catch (err) {
    console.error('Webhook processing error: ', err.message);
  }

  res.json({ received: true });
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public'), { setHeaders: (res, fp) => fp.includes('.well-known') && res.status(404).end() }));

// Authentication middleware
const requireAuth = (req, res, next) => {
  const payload = verifyToken(req.cookies.jwt);
  if (!payload) {
    console.log('Auth failed: no token');
    return res.send('<script>alert("Please log in");location="/login.html"</script>');
  }
  req.userId = payload.userId;
  next();
};

// Subscription check middleware
const checkSubscription = async (req, res, next) => {
  try {
    console.log('Subscription check started for user ID: ', req.userId);
    const [[user]] = await pool.query('SELECT subscription_status, subscription_period_end FROM users WHERE id = ?', [req.userId]);
    console.log('User subscription data fetched: ', user);
    const now = Math.floor(Date.now() / 1000);
    console.log('Current time (seconds): ', now);
    const active = user.subscription_status === 'active' && user.subscription_period_end > now;
    console.log('Subscription active check result: ', active);
    if (!active) {
      return res.send('<script>alert("Active subscription required");location="/profile.html"</script>');
    }
    next();
  } catch (err) {
    console.error('Subscription check error: ', err.message);
    res.status(500).send('Server error');
  }
};

// Routes
app.post('/api/signup', async (req, res) => {
  console.log('Signup request: ', req.body);
  try {
    const phrase = generateMnemonic();
    await register({ ...req.body, phrase });
    console.log('Signup success');
    res.json({ success: true, phrase });
  } catch (err) {
    const msg = err.message.includes('username') ? 'Username taken' : 'Email taken';
    console.error('Signup error: ', msg);
    res.status(400).json({ success: false, error: msg });
  }
});

app.post('/api/login', async (req, res) => {
  console.log('Login request: ', req.body);
  try {
    const user = await login(req.body);
    if (!user) throw new Error('Invalid credentials');
    res.cookie('jwt', generateToken(user.id), { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    console.log('Login success for user ID: ', user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Login error: ', err.message);
    res.status(401).json({ success: false });
  }
});

app.get('/api/logout', (req, res) => {
  res.clearCookie('jwt');
  console.log('Logout success');
  res.json({ success: true });
});



app.get('/api/me', requireAuth, async (req, res) => {
  try {
    console.log('Get me request for user ID: ', req.userId);
    const [[user]] = await pool.query(
      'SELECT username, email, subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    const now = Math.floor(Date.now() / 1000);
    let active = false;
    let daysLeft = 0;

    if (user.subscription_status === 'active' && user.subscription_period_end && user.subscription_period_end > now) {
      active = true;
      daysLeft = Math.ceil((user.subscription_period_end - now) / 86400); // correct days left
    }

    console.log(`Active: ${active} | End time: ${user.subscription_period_end} | Days left: ${daysLeft}`);

    res.json({
      username: user.username,
      email: user.email,
      subscription_active: active,
      days_left: daysLeft,
      subscription_status: user.subscription_status,
      subscription_period_end: user.subscription_period_end
    });
  } catch (err) {
    console.error('Get me error: ', err.message);
    res.status(500).json(null);
  }
});

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  console.log('Checkout request: ', req.body);
  try {
    const { price_id } = req.body;
    const [[user]] = await pool.query('SELECT email, stripe_customer_id FROM users WHERE id = ?', [req.userId]);
    let customerId = user.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { userId: req.userId.toString() }
      });
      await pool.query('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customer.id, req.userId]);
      customerId = customer.id;
      console.log('New customer created: ', customerId);
    } else {
      // Update metadata if existing customer
      await stripe.customers.update(customerId, {
        metadata: { userId: req.userId.toString() }
      });
      console.log('Updated metadata for existing customer: ', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: price_id, quantity: 1 }],
      success_url: `${process.env.APP_URL || 'http://localhost:3000'}/profile.html?payment=success`,
      cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}/profile.html?payment=cancel`,
      metadata: { userId: req.userId.toString() }
    });

    console.log('Checkout session created: ', session.id);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout session error: ', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cancel-subscription-now', requireAuth, async (req, res) => {
  console.log('Cancel request for user ID: ', req.userId);
  try {
    const [[user]] = await pool.query('SELECT stripe_subscription_id FROM users WHERE id = ?', [req.userId]);
    
    if (!user?.stripe_subscription_id) {
      return res.status(400).json({ success: false, error: 'No active subscription found' });
    }

    // Correct way to cancel (delete) a Stripe subscription
    await stripe.subscriptions.cancel(user.stripe_subscription_id);

    // Clear from your DB
    await pool.query(
      'UPDATE users SET subscription_status = "inactive", subscription_period_end = NULL, stripe_subscription_id = NULL WHERE id = ?',
      [req.userId]
    );

    console.log('Subscription successfully cancelled for user ID: ', req.userId);
    res.json({ success: true });
  } catch (err) {
    console.error('Cancel subscription error: ', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Protected premium folder
// ──────────────────────────────────────────────────────────────────────────────
//  PREMIUM CONTENT PROTECTION — THE CORRECT & BULLETPROOF WAY
// ──────────────────────────────────────────────────────────────────────────────
app.get('/subscriptions/*', requireAuth, async (req, res) => {
  try {
    console.log(`Premium access attempt → User ID: ${req.userId} | Path: ${req.path}`);

    // Re-check subscription fresh from DB (never trust old data)
    const [[user]] = await pool.query(
      'SELECT subscription_status, subscription_period_end FROM users WHERE id = ?',
      [req.userId]
    );

    if (!user) {
      console.log('User not found in DB during premium check');
      return res.status(404).send('User not found');
    }

    const now = Math.floor(Date.now() / 1000);
    const isActive = user.subscription_status === 'active' && user.subscription_period_end > now;

    console.log(`Subscription check → status: ${user.subscription_status}, ends: ${user.subscription_period_end}, now: ${now} → ACTIVE = ${isActive}`);

    if (!isActive) {
      console.log('Access DENIED → Redirecting to profile');
      return res.send(`
        <script>
          alert("Premium subscription required!");
          window.location.href = "/profile.html";
        </script>
      `);
    }

    // ─── USER IS LEGIT → SERVE THE REQUESTED FILE ────────────────────────────
    const requestedFile = req.path.replace('/subscriptions', '');
    let filePath = path.join(__dirname, '../public/subscriptions', requestedFile);

    // Security: Prevent directory traversal (e.g. /subscriptions/../../server.js)
    const resolvedPath = path.resolve(filePath);
    const publicDir = path.resolve(path.join(__dirname, '../public/subscriptions'));
    
    if (!resolvedPath.startsWith(publicDir)) {
      console.log('Directory traversal attempt blocked:', req.path);
      return res.status(403).send('Forbidden');
      return;
    }

    // Default to index.html if accessing folder
    if (requestedFile.endsWith('/') || requestedFile === '') {
      filePath = path.join(publicDir, 'index.html');
    } else {
      filePath = resolvedPath;
    }

    console.log('Serving premium file:', filePath);

    res.sendFile(filePath, (err) => {
      if (err) {
        console.log('File not found:', filePath);
        res.status(404).send('Premium content not found');
      } else {
        console.log('Premium content served successfully to user', req.userId);
      }
    });

  } catch (err) {
    console.error('Error in premium route:', err.message);
    res.status(500).send('Server error');
  }
});


//+++++++++++++++++++++++++++++++++++++++++++++++++++++
// Protected premium content — BULLETPROOF VERSION
app.get('/subscriptions/*', requireAuth, async (req, res) => {
  // ... entire block above ...
});

// Catch-all route (must be last!)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', req.path === '/' ? 'index.html' : req.path));
});

// _____________________________________________________________________________________________________________

// Catch-all route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', req.path === '/' ? 'index.html' : req.path));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});