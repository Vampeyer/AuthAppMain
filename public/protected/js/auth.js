// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL Pool (your Hostinger DB)
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

const sessionStore = new MySQLStore({}, pool);

app.use(session({
  key: 'session_cookie',
  secret: process.env.SESSION_SECRET || 'fallback',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/streampaltest/public', express.static(path.join(__dirname, 'public')));

const requireAuth = (req, res, next) => (req.session?.userId ? next() : res.status(401).json({ error: 'Unauthorized' }));

// Auto-create users table
(async () => {
  try {
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
      )
    `);
    console.log('users table ready');
  } catch (e) { console.error('Table error:', e); }
})();

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, hash]);
    res.json({ success: true });
  } catch (e) {
    console.error('Signup:', e);
    res.status(400).json({ error: e.sqlMessage || 'Signup failed' });
  }
});

app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?',
      [login, login]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.userId = rows[0].id;
    req.session.username = rows[0].username;
    res.json({ success: true });
  } catch (e) {
    console.error('Login:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/profile', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT username, email FROM users WHERE id = ?', [req.session.userId]);
    const u = rows[0] || {};
    res.json({ username: u.username, email: u.email, subscription_active: false });
  } catch (e) {
    console.error('Profile:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Public: http://localhost:${PORT}/streampaltest/public`);
});