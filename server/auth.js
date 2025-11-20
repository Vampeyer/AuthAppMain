const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bip39 = require('bip39');
const pool = require('./db');
const JWT_SECRET = process.env.JWT_SECRET;

const generateMnemonic = () => bip39.generateMnemonic(128);

const register = async ({ username, email, password, phrase }) => {
  const pwHash = await bcrypt.hash(password, 12);
  const phraseHash = await bcrypt.hash(phrase.trim(), 12);

  try {
    await pool.execute(
      'INSERT INTO users (username, email, password_hash, phrase_hash) VALUES (?, ?, ?, ?)',
      [username.toLowerCase(), email.toLowerCase(), pwHash, phraseHash]
    );
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      if (err.message.includes('username')) throw new Error('username already taken');
      if (err.message.includes('email')) throw new Error('email already taken');
    }
    throw err;
  }
};

const login = async ({ username, password, phrase }) => {
  const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username.toLowerCase()]);
  if (!rows[0]) return null;
  const user = rows[0];
  const pwOk = await bcrypt.compare(password, user.password_hash);
  const phraseOk = await bcrypt.compare(phrase.trim(), user.phrase_hash);
  return pwOk && phraseOk ? user : null;
};

const generateToken = id => jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = token => { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } };

module.exports = { register, login, generateToken, verifyToken, generateMnemonic };