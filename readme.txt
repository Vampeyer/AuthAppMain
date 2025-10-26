README.txt Content
Movies App Authentication System
Project Overview
This is a secure authentication and subscription management app for a movies streaming service. It allows users to sign up, log in with a 12-word passphrase, manage 7-day or 30-day subscriptions via Stripe, and access premium content. Frontend is vanilla JS/HTML/CSS with Bootstrap. Backend handles API routes, MySQL DB, and Stripe webhooks. Auth uses JWT tokens with HTTP-only cookies (industry best for security, preventing XSS attacks—better than localStorage).
What It Does

User signup/login with passphrase.
Manage subscriptions (7/30-day via Stripe).
Profile view (username, email, status).
Premium content in /subscription folder restricted to active subscribers.
Webhooks activate subscriptions post-payment.

Technologies Used

Backend: Node.js/Express.js (server.js in root).
Database: MySQL (mysql2).
Auth: JWT (jsonwebtoken), bcrypt (password hashing), HTTP-only cookies (cookie-parser).
Payments: Stripe (stripe module).
Frontend: Vanilla JS/HTML/CSS, Bootstrap 5.3 (public/ folder), auth.js in protected/js/.
Tools: dotenv (env vars), cors, body-parser.

Local Setup with XAMPP (Node.js + MySQL)

Clone repo and navigate to root.
Install deps: npm install.
Start XAMPP > Apache/MySQL.
phpMyAdmin (http://localhost/phpmyadmin): Create DB (e.g., scm_system).
Run SQL to create users table (see server.js for schema).
Update .env with DB details (MYSQL_HOST=localhost, MYSQL_USER=root, MYSQL_PASSWORD= , MYSQL_DATABASE=scm_system).
Setup Stripe: Dashboard > API Keys > Copy test key to .env (STRIPE_SECRET_KEY=sk_test_...).
Install Stripe CLI: npm install -g @stripe/stripe-cli.
Login: stripe login.
Run webhook: stripe listen --forward-to http://localhost:3000/webhook > Copy secret to .env (STRIPE_WEBHOOK_SECRET=whsec_...).
Start app: npm run dev.
Visit http://localhost:3000 > Signup/login > Subscribe (test card: 4242 4242 4242 4242).

Online Setup (Render Backend, Hostinger Frontend)

Push code to GitHub (exclude .env, node_modules).
Render (Backend): render.com > New Web Service > Connect repo > Node > Build npm install, Start node server.js > Free plan > Add env vars from .env (use live Stripe keys for production).
Hostinger (Frontend): hPanel > File Manager > Upload public/ to public_html/spauth > Set subdomain spauth.techsport.app > Install SSL.
Update Stripe webhook: Dashboard > Webhooks > Add https://movies-auth-app.onrender.com/webhook > Copy secret to Render env.
Test: https://spauth.techsport.app > Signup/login > Subscribe.

Implementing Content in Subscription Folder

Create files in public/subscription/ (e.g., premium_video.html):

Copy movie_content.html as template.


Update navbar in all HTML files to link to them (e.g., /subscription/premium_video.html).
Access: Only available after subscription (subscription_active = TRUE).
If not subscribed: Alert "This page is for subscriptions..." > Redirect to profile.
Push to GitHub > Redeploy Render/Hostinger.

Need for Webhooks
Webhooks are essential for real-time Stripe event handling (e.g., checkout.session.completed after payment). They automatically update the DB (subscription_active = TRUE) without user action, enabling premium access. Without webhooks, subscriptions wouldn't activate, and content would remain locked. Use Stripe CLI for local testing, dashboard for production.

Step-by-Step Deployment to Render (Backend)

Create GitHub Repo:

github.com > New repo > Name movies-auth-app.
Clone locally: git clone https://github.com/yourusername/movies-auth-app.git.
Copy your app files into the repo folder (server.js, package.json, public/, protected/).
Commit/push: git add . && git commit -m "Initial commit" && git push origin main.


Sign Up/Login to Render:

render.com > Sign up with GitHub.


Create Web Service:

Dashboard > New > Web Service > Connect movies-auth-app repo.
Settings:

Name: movies-auth-app.
Environment: Node.
Branch: main.
Build Command: npm install.
Start Command: node server.js.
Plan: Free.


Advanced > Environment Variables: Add all from .env (e.g., MYSQL_HOST=srv1267.hstgr.io, STRIPE_SECRET_KEY=sk_live_...).


Create:

Click Create Web Service > Wait for build (2-5 mins).
URL: https://movies-auth-app.onrender.com > Test API (e.g., /profile with token).


Update Stripe Webhook:

stripe.com/dashboard/webhooks > Add endpoint > URL: https://movies-auth-app.onrender.com/webhook > Events: checkout.session.completed, etc. > Copy secret to Render env > Redeploy.



Step-by-Step Deployment to Hostinger (Frontend)

Prepare Files:

Copy public/ and protected/ to a folder spauth-upload.
Update API_URL in JS files to https://movies-auth-app.onrender.com for production.


Upload:

hPanel > File Manager > public_html > Create spauth.
Upload contents of spauth-upload to public_html/spauth.
Permissions: Folders 755, files 644.


Subdomain:

hPanel > Domains > Subdomains > Add spauth > Point to /public_html/spauth.


SSL:

hPanel > Security > SSL > Install for techsport.app and spauth.techsport.app.


Test:

https://spauth.techsport.app > Signup/login > Subscribe (calls Render backend).