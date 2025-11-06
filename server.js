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
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_i93P8B7vfplPpweehki6wKdWozoJGhmZ';

// Stripe price IDs (unchanged)
const PRICE_WEEKLY = 'price_1SIBPkFF2HALdyFkogiGJG5w'; // 7 days for $2.95
const PRICE_MONTHLY = 'price_1SIBCzFF2HALdyFk7vOxByGq'; // 30 days for $7.75

let DOMAIN;  // Production/Development: Switch based on NODE_ENV.
if (process.env.NODE_ENV === 'production') {
  DOMAIN = 'https://movies-auth-app.onrender.com';  // Production: Your Render app URL. Update if app name changes (e.g., to 'authappmain').
} else {
  DOMAIN = 'http://localhost:3000';  // Development: Local server for testing.
}

// Middleware setup (CORS allows local and production origins; credentials for cookies/JWT)
app.use(cookieParser());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'https://techsport.app', 'https://spauth.techsport.app'],  // Production/Development: Covers local Live Server and Hostinger domain.
  credentials: true
}));

// Webhook route with raw body parser (must be first) - unchanged, handles Stripe events
app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  // ... (full webhook code unchanged)
});

// Other middleware (no static serving here; Hostinger handles public folder in production)
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '100mb', extended: true }));

// MySQL setup - unchanged, connects to Hostinger DB via .env
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

// ... (connectDB function, table alterations, routes like /signup, /login, /profile, /create-checkout-session, /verify-session, /delete-subscription, /check-subscription, /logout unchanged)

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server: ${DOMAIN}`);
});

// Add this route in server.js — helps auth.js detect if backend is alive
app.head('/ping', (req, res) => {
  res.status(200).send();
});