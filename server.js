require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'supersecret123!@#';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_i93P8B7vfplPpweehki6wKdWozoJGhmZ';

// Stripe price IDs
const PRICE_WEEKLY = 'price_1SIBPkFF2HALdyFkogiGJG5w'; // 7 days for $2.95
const PRICE_MONTHLY = 'price_1SIBCzFF2HALdyFk7vOxByGq'; // 30 days for $7.75

const isProduction = process.env.NODE_ENV === 'production';
const DOMAIN = isProduction ? process.env.BASE_URL : 'http://localhost:3000';

// Middleware setup
app.use(cookieParser());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'https://techsport.app', 'https://spauth.techsport.app'],
  credentials: true
}));

// Webhook route with raw body parser (must be first)
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  console.log('Webhook request received');
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('Webhook verified:', event.type);
  } catch (err) {
    console.error('Webhook verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    console.log('Checkout completed:', session.id);
    if (session.mode === 'subscription' && session.subscription && session.metadata.userId) {
      const subscriptionId = session.subscription;
      const userId = session.metadata.userId;
      const customerId = session.customer;
      console.log('Checking user:', userId);
      const [rows] = await pool.execute('SELECT id FROM users WHERE id = ?', [userId]);
      if (rows.length === 0) {
        console.error('User not found:', userId);
        return res.status(400).json({ error: 'User not found' });
      }
      console.log('Updating subscription for user:', userId);
      await pool.execute(
        'UPDATE users SET customer_id = ?, subscription_id = ?, subscription_active = TRUE WHERE id = ?',
        [customerId, subscriptionId, userId]
      );
      console.log('Subscription activated:', subscriptionId);
    }
  } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const subscription = event.data.object;
    console.log('Deactivating subscription:', subscription.id);
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
      [subscription.id]
    );
    console.log('Subscription deactivated');
  }

  res.json({ received: true });
});

// Subscription middleware (local only)
async function checkSubscription(req, res, next) {
  console.log('Checking subscription access');
  const token = req.cookies?.authToken;
  if (!token) {
    console.error('No token for subscription content');
    return res.status(403).send(`
      <script>
        alert('Subscription required.');
        window.location.href = '/profile.html';
      </script>
    `);
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('Fetching subscription status for user:', decoded.id);
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0 || !rows[0].subscription_active) {
      console.log('Subscription check failed for user:', decoded.id);
      return res.status(403).send(`
        <script>
          alert('Subscription required.');
          window.location.href = '/profile.html';
        </script>
      `);
    }
    console.log('Subscription check passed for user:', decoded.id);
    next();
  } catch (error) {
    console.error('Subscription check error:', error.message);
    return res.status(403).send(`
      <script>
        alert('Subscription required.');
        window.location.href = '/profile.html';
      </script>
    `);
  }
}

if (!isProduction) {
  app.use('/subscription', checkSubscription, express.static(path.join(__dirname, 'public', 'subscription')));
}

// Other middleware
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MySQL setup
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
    console.log('MySQL Connected');
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_active BOOLEAN DEFAULT FALSE`);
    console.log('Schema updates applied');
  } catch (err) {
    console.error('MySQL Connection Error:', err.message);
  }
}
connectDB();

async function verifyToken(req, res, next) {
  console.log('Verifying token');
  const token = req.cookies?.authToken;
  if (!token) {
    console.error('No token provided');
    return res.status(403).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    console.log('Token verified for user:', req.userId);
    next();
  } catch (error) {
    console.error('Invalid token:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Signup route
app.post('/signup', async (req, res) => {
  console.log('SIGNUP request:', req.body);
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      console.error('Missing fields in signup');
      return res.status(400).json({ error: 'Missing fields' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    console.log('Checking for existing user:', username, email);
    const [rows] = await pool.execute('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (rows.length > 0) {
      console.error('User already exists');
      return res.status(400).json({ error: 'User already exists' });
    }
    console.log('Creating new user');
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, password_hash]
    );
    console.log('User created:', result.insertId);
    res.json({ success: true });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  console.log('LOGIN request:', req.body);
  try {
    const { login, password } = req.body;
    if (!login || !password) {
      console.error('Missing fields in login');
      return res.status(400).json({ error: 'Missing fields' });
    }
    console.log('Querying user:', login);
    const [rows] = await pool.execute(
      'SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?',
      [login, login]
    );
    if (rows.length === 0) {
      console.error('User not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = rows[0];
    console.log('User found, checking password');
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      console.error('Password mismatch');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    console.log('Password match, generating token');
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('authToken', token, { httpOnly: true, secure: isProduction });
    console.log('Login successful for user:', user.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile route
app.get('/profile', verifyToken, async (req, res) => {
  console.log('PROFILE request for user:', req.userId);
  try {
    const [rows] = await pool.execute(
      'SELECT username, email, subscription_active, subscription_id FROM users WHERE id = ?',
      [req.userId]
    );
    if (rows.length === 0) {
      console.error('User not found:', req.userId);
      return res.status(404).json({ error: 'User not found' });
    }
    const user = rows[0];
    console.log('Profile loaded:', user.username, 'Subscription:', user.subscription_active ? 'Active' : 'Inactive');
    res.json({
      username: user.username,
      email: user.email,
      subscription_active: user.subscription_active
    });
  } catch (error) {
    console.error('Profile error:', error.message);
    res.status(500).json({ error: 'Profile failed' });
  }
});

// Create checkout session
app.post('/create-checkout-session', verifyToken, async (req, res) => {
  console.log('CREATE CHECKOUT request for user:', req.userId);
  try {
    const { type } = req.body;
    const priceId = type.toUpperCase() === 'WEEKLY' ? PRICE_WEEKLY : PRICE_MONTHLY;
    if (!priceId) return res.status(400).json({ error: 'Invalid type' });

    console.log('Fetching user for checkout:', req.userId);
    const [rows] = await pool.execute('SELECT customer_id, email FROM users WHERE id = ?', [req.userId]);
    const user = rows[0];
    let customerId = user.customer_id;

    if (!customerId) {
      console.log('Creating new Stripe customer');
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('New customer created:', customerId);
    } else {
      try {
        await stripe.customers.retrieve(customerId);
        console.log('Existing customer verified:', customerId);
      } catch (err) {
        if (err.code === 'resource_missing') {
          console.log('Invalid customer ID, creating new');
          const customer = await stripe.customers.create({ email: user.email });
          customerId = customer.id;
          await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
          console.log('New customer created:', customerId);
        } else {
          throw err;
        }
      }
    }

    console.log('Creating Checkout session');
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/cancel.html`,
      metadata: { userId: req.userId.toString() }
    });
    console.log('Checkout session created:', session.id);
    res.json({ url: session.url });
  } catch (error) {
    console.error('Checkout error:', error.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// Verify session
app.post('/verify-session', verifyToken, async (req, res) => {
  console.log('VERIFY SESSION request for user:', req.userId);
  try {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'No session ID' });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.mode !== 'subscription' || !session.subscription) return res.status(400).json({ error: 'Invalid session' });
    const [rows] = await pool.execute('SELECT id, customer_id FROM users WHERE id = ?', [req.userId]);
    if (rows.length === 0) return res.status(400).json({ error: 'User not found' });
    if (!rows[0].customer_id) {
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [session.customer, req.userId]);
    }
    await pool.execute(
      'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?',
      [session.subscription, req.userId]
    );
    console.log('Subscription activated:', session.subscription);
    res.json({ active: true });
  } catch (error) {
    console.error('Verify session error:', error.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Delete subscription
app.post('/delete-subscription', verifyToken, async (req, res) => {
  console.log('DELETE SUBSCRIPTION request for user:', req.userId);
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id = ?', [req.userId]);
    const subscriptionId = rows[0]?.subscription_id;
    if (!subscriptionId) return res.status(400).json({ error: 'No subscription' });

    await stripe.subscriptions.cancel(subscriptionId);
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE id = ?',
      [req.userId]
    );
    console.log('Subscription cancelled for user:', req.userId);
    res.json({ success: true });
  } catch (error) {
    console.error('Cancel error:', error.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

// Check subscription
app.get('/check-subscription', verifyToken, async (req, res) => {
  console.log('CHECK SUBSCRIPTION request for user:', req.userId);
  try {
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [req.userId]);
    console.log('Subscription check:', rows[0]?.subscription_active || false);
    res.json({ active: rows[0]?.subscription_active || false });
  } catch (error) {
    console.error('Check subscription error:', error.message);
    res.status(500).json({ error: 'Check failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});