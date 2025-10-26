Movies App - Quick Setup and Configuration Guide

### Setup
1. Install Node.js (v18+ recommended) and XAMPP.
2. Place all files in a folder (e.g., `C:\Users\guy\Desktop\JSNOWNOW-and-React\AuthApp-Full-Vanilla`).
3. Create a `public` subfolder and add HTML files (`index.html`, `signup.html`, `login.html`, `profile.html`, `movie_content.html`).
4. Run `npm init -y` and `npm install express mysql2 bcrypt jsonwebtoken body-parser cors` in the terminal.
5. Start XAMPP, create a `auth_app` database in phpMyAdmin.
6. Run `node server.js` and access `http://localhost:3000/`.

### Change Subscription Time
- Open `server.js` in a text editor.
- Find: `const SUBSCRIPTION_DURATIONS = { WEEKLY: 7, MONTHLY: 30 };`.
- Change `7` (weekly) or `30` (monthly) to your desired days (e.g., `WEEKLY: 1`, `MONTHLY: 15`).
- Save and restart the server with `node server.js`.

### Set Up Stripe
1. Enable test mode in `server.js`: Set `STRIPE_TEST_MODE = true`.
2. Get test API keys from [stripe.com](https://stripe.com) and replace `STRIPE_TEST_KEY` and `STRIPE_WEBHOOK_SECRET` in `server.js`.
3. Install Stripe: Run `npm install stripe`.
4. Update `/subscribe` in `server.js` with Stripe checkout code (see `codeblock.txt` for example).
5. Update `profile.html` `subscribe` function for Stripe redirect (see `codeblock.txt`).
6. Test with Stripe CLI: Run `stripe listen --forward-to localhost:3000/webhook`.

Done! Adjust times or add Stripe as needed.