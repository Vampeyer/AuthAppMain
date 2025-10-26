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
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Your Stripe price IDs
const PRICE_WEEKLY = 'price_1SIBPkFF2HALdyFkogiGJG5w';
const PRICE_MONTHLY = 'price_1SIBCzFF2HALdyFk7vOxByGq';
const DOMAIN = process.env.NODE_ENV === 'production' ? 'https://movies-auth-app.onrender.com' : 'http://localhost:3000';



app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Webhook route with raw body parser
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // Ensure raw body is used for signature verification
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('✅ Webhook received and verified:', {
      type: event.type,
      id: event.id,
      customer: event.data.object.customer || 'N/A',
      subscription: event.data.object.subscription || 'N/A'
    });
  } catch (err) {
    console.log('💥 Webhook signature error:', {
      message: err.message,
      headers: req.headers,
      bodyLength: req.body?.length
    });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      if (session.mode === 'subscription' && session.subscription) {
        const subscriptionId = session.subscription;
        const customerId = session.customer;

        // Verify customer exists in DB
        const [rows] = await pool.execute(
          'SELECT id FROM users WHERE customer_id = ?',
          [customerId]
        );
        if (rows.length === 0) {
          console.log('💥 Webhook error: Customer not found:', customerId);
          return res.status(400).json({ error: 'Customer not found' });
        }

        // Update subscription status
        const [result] = await pool.execute(
          'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE customer_id = ?',
          [subscriptionId, customerId]
        );
        console.log('✅ Subscription activated:', {
          customerId,
          subscriptionId,
          rowsAffected: result.affectedRows
        });
      } else {
        console.log('⚠️ Webhook: Not a subscription session:', session.mode);
      }
    } else if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
      const subscription = event.data.object;
      const [result] = await pool.execute(
        'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE subscription_id = ?',
        [subscription.id]
      );
      console.log('✅ Subscription deactivated:', {
        subscriptionId: subscription.id,
        rowsAffected: result.affectedRows
      });
    } else if (event.type === 'invoice.payment_failed') {
      console.log('⚠️ Payment failed for subscription:', event.data.object.subscription);
    }
  } catch (err) {
    console.log('💥 Webhook processing error:', {
      eventType: event.type,
      error: err.message,
      stack: err.stack
    });
    return res.status(500).json({ error: 'Webhook processing failed' });
  }

  res.json({ received: true });
});

// Fallback endpoint to verify session
app.post('/verify-session', verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      console.log('💥 Verify session error: No session ID provided');
      return res.status(400).json({ error: 'No session ID' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.mode !== 'subscription' || !session.subscription) {
      console.log('💥 Verify session error: Invalid session', session.mode);
      return res.status(400).json({ error: 'Invalid session' });
    }

    const [rows] = await pool.execute(
      'SELECT customer_id FROM users WHERE id = ?',
      [req.userId]
    );
    if (rows.length === 0 || rows[0].customer_id !== session.customer) {
      console.log('💥 Verify session error: Customer mismatch', {
        userId: req.userId,
        sessionCustomer: session.customer
      });
      return res.status(400).json({ error: 'Customer mismatch' });
    }

    const [result] = await pool.execute(
      'UPDATE users SET subscription_id = ?, subscription_active = TRUE WHERE id = ?',
      [session.subscription, req.userId]
    );
    console.log('✅ Fallback subscription activated:', {
      userId: req.userId,
      subscriptionId: session.subscription,
      rowsAffected: result.affectedRows
    });

    res.json({ active: result.affectedRows > 0 });
  } catch (error) {
    console.log('💥 Verify session error:', error.message);
    res.status(500).json({ error: 'Session verification failed' });
  }
});

// JSON body parser for other routes
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'https://techsport.app', 'https://spauth.techsport.app'],
  credentials: true
}));

const dbConfig = { 
  host: 'srv1267.hstgr.io', 
  user: 'u418580423_rootie', 
  password: '0Idontknow0$%$%', 
  database: 'u418580423_scm_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
const pool = mysql.createPool(dbConfig);

async function connectDB() {
  try {
    await pool.getConnection();
    console.log('✅ MySQL Connected');

    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255)`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_active BOOLEAN DEFAULT FALSE`);
    await pool.execute(`ALTER TABLE users ADD COLUMN IF NOT EXISTS picture_base64 TEXT`);
  } catch (err) {
    console.log('❌ MySQL Error:', err.message);
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
  const token = req.cookies.authToken;
  if (!token) {
    console.log('❌ No token in request');
    return res.status(403).json({ error: 'No token' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    console.log('✅ Token verified for user ID:', req.userId);
    next();
  } catch (error) {
    console.log('❌ Invalid token:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/signup', async (req, res) => {
  console.log('🔥 SIGNUP:', req.body);
  try {
    const { username, email, password, subscription_type } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const mnemonic = generateMnemonic();

    await pool.execute(`CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE,
      email VARCHAR(255) UNIQUE,
      password_hash VARCHAR(255),
      mnemonic TEXT,
      customer_id VARCHAR(255),
      subscription_id VARCHAR(255),
      subscription_active BOOLEAN DEFAULT FALSE,
      picture_base64 TEXT
    )`);

    await pool.execute(
      'INSERT INTO users (username, email, password_hash, mnemonic) VALUES (?, ?, ?, ?)',
      [username, email, password_hash, mnemonic]
    );

    console.log('✅ Signup success:', username);
    res.json({ mnemonic, success: true });
  } catch (error) {
    console.log('💥 Signup error:', error.message);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username or email exists' });
    }
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/login', async (req, res) => {
  console.log('🔐 LOGIN:', req.body);
  try {
    const { login, password, mnemonic } = req.body;
    if (!login || !password || !mnemonic) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE (username = ? OR email = ?) AND mnemonic = ?',
      [login, login, mnemonic]
    );
    
    if (rows.length === 0) {
      console.log('❌ No user found for login:', login);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      console.log('❌ Password mismatch for user:', login);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '7d' });
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    console.log('✅ Login success:', user.username, 'Cookie set:', token.substring(0, 20) + '...');
    res.json({ success: true });
  } catch (error) {
    console.log('💥 Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/profile', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT username, email, subscription_active, subscription_id, picture_base64 FROM users WHERE id = ?',
      [req.userId]
    );
    
    if (rows.length === 0) {
      console.log('❌ User not found for ID:', req.userId);
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = rows[0];
    console.log(`👤 Profile loaded: ${user.username} - Subscription: ${user.subscription_active ? 'Active' : 'Inactive'}`);
    
    res.json({ 
      username: user.username, 
      email: user.email,
      subscription_active: user.subscription_active,
      picture_base64: user.picture_base64
    });
  } catch (error) {
    console.log('💥 Profile error:', error.message);
    res.status(500).json({ error: 'Profile failed' });
  }
});

app.post('/create-checkout-session', verifyToken, async (req, res) => {
  try {
    const { type } = req.body;
    const priceId = type.toUpperCase() === 'WEEKLY' ? PRICE_WEEKLY : PRICE_MONTHLY;
    if (!priceId) return res.status(400).json({ error: 'Invalid type' });

    const [rows] = await pool.execute('SELECT customer_id, email FROM users WHERE id = ?', [req.userId]);
    const user = rows[0];
    let customerId = user.customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await pool.execute('UPDATE users SET customer_id = ? WHERE id = ?', [customerId, req.userId]);
      console.log('✅ New Stripe customer created:', customerId);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${DOMAIN}/cancel.html`,
      metadata: { userId: req.userId.toString() }
    });

    console.log('✅ Checkout session created:', {
      sessionId: session.id,
      customerId,
      priceId
    });
    res.json({ url: session.url });
  } catch (error) {
    console.log('💥 Checkout error:', error.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

app.post('/delete-subscription', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_id FROM users WHERE id = ?', [req.userId]);
    const subscriptionId = rows[0]?.subscription_id;
    if (!subscriptionId) return res.status(400).json({ error: 'No subscription' });

    await stripe.subscriptions.cancel(subscriptionId);
    await pool.execute(
      'UPDATE users SET subscription_id = NULL, subscription_active = FALSE WHERE id = ?',
      [req.userId]
    );
    console.log('✅ Subscription cancelled for user ID:', req.userId);
    res.json({ success: true });
  } catch (error) {
    console.log('💥 Cancel error:', error.message);
    res.status(500).json({ error: 'Cancel failed' });
  }
});

app.get('/check-subscription', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT subscription_active FROM users WHERE id = ?', [req.userId]);
    console.log('✅ Subscription check for user ID:', req.userId, 'Active:', rows[0]?.subscription_active || false);
    res.json({ active: rows[0]?.subscription_active || false });
  } catch (error) {
    console.log('💥 Check subscription error:', error.message);
    res.status(500).json({ error: 'Check failed' });
  }
});

app.post('/upload-picture', verifyToken, async (req, res) => {
  try {
    const { image_base64 } = req.body;
    await pool.execute('UPDATE users SET picture_base64 = ? WHERE id = ?', [image_base64, req.userId]);
    console.log('✅ Picture uploaded for user ID:', req.userId);
    res.json({ success: true });
  } catch (error) {
    console.log('💥 Upload picture error:', error.message);
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('authToken');
  console.log('✅ User logged out');
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`🚀 Server: http://localhost:${PORT}`);
});