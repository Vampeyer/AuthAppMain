# Movies App Authentication System

A simple vanilla JS, HTML, CSS (with Bootstrap 5.3) authentication app with Node.js backend and MySQL database. Supports signup, login with 12-key phrase, and subscription management (weekly/monthly). No image upload or protected content.

## Prerequisites
- Node.js (v18+ recommended)
- XAMPP (for MySQL)
- MySQL database named `auth_app`

## Setup
1. **Install Dependencies:**
npm init -y
npm install express mysql2 bcrypt jsonwebtoken body-parser cors


2. **Database Setup:**
- Start XAMPP Apache and MySQL.
- In phpMyAdmin, create database `auth_app` (no need to create tables; server does it automatically).

3. **Run Server:**
node server.js



4. **Access App:**
- Open `http://localhost:3000/` (loads `index.html`).
- Signup at `http://localhost:3000/signup.html`.
- Login at `http://localhost:3000/login.html`.
- Profile at `http://localhost:3000/profile.html`.
- Movie Content at `http://localhost:3000/movie_content.html` (subscription required).

## Configuring Subscription Durations
- In `server.js`, edit the `SUBSCRIPTION_DURATIONS` object:

const SUBSCRIPTION_DURATIONS = {
WEEKLY: 7,   // Change to e.g., 1 for 1-day test
MONTHLY: 30  // Change to e.g., 2 for 2-day test
};

- Restart server after changes.

## Stripe Integration
1. **Enable Stripe Test Mode:**
 - Set `STRIPE_TEST_MODE = true` in `server.js`.
 - Replace `STRIPE_TEST_KEY` and `STRIPE_WEBHOOK_SECRET` with your Stripe test keys (from Stripe dashboard).

2. **Hooking Up Endpoints:**
 - In `/subscribe` endpoint, add Stripe checkout session creation (require `stripe` package: `npm install stripe`):
const stripe = require('stripe')(STRIPE_TEST_KEY);
// Inside try block after database update
const session = await stripe.checkout.sessions.create({
payment_method_types: ['card'],
line_items: [{
price_data: {
currency: 'usd',
product_data: {
name: ${type} Subscription,
},
unit_amount: type === 'WEEKLY' ? 500 : 1000, // e.g., $5/$10 test
},
quantity: 1,
}],
mode: 'payment',
success_url: 'http://localhost:3000/success.html',
cancel_url: 'http://localhost:3000/cancel.html',
metadata: { userId: decoded.id, subscriptionType: type }
});
// Return session.id to frontend for redirect
res.json({ success: true, sessionId: session.id });
text- In frontend (profile.html), update `subscribe` function to redirect to Stripe checkout:
window.subscribe = async function(type) {
const token = getToken();
try {
const response = await fetch(${API_URL}/subscribe, {
method: 'POST',
headers: {
'Content-Type': 'application/json',
'Authorization': token
},
body: JSON.stringify({ type })
});
const data = await response.json();
if (data.success) {
alert(✅ ${type === 'WEEKLY' ? 'Weekly' : 'Monthly'} activated!);
window.location.href = 'movie_content.html';
}
} catch (error) {
alert('Subscription failed');
}
};
text- For webhooks, the `/webhook` endpoint handles payment success—update to activate subscription in DB.

5. **Test Stripe:**
- Use Stripe CLI for local webhooks: `stripe listen --forward-to localhost:3000/webhook`.
- Test payments with Stripe test cards (e.g., 4242 4242 4242 4242).

## **Troubleshooting**
- Ensure all HTML files are in `public/` folder.
- If "Cannot GET /" persists, check if `index.html` is in `public/`.
- For subscription expiry, current date is hardcoded in `/profile` for testing; remove for production.

**App now runs smoothly—subscription expiry shown on profile!** 🎉