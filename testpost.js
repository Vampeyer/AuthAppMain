// testpost.js
// Run: node testpost.js

require('dotenv').config();
const fetch = require('node-fetch');

const API_URL = 'https://authappmain.onrender.com';
const JWT_TOKEN = 'PASTE_YOUR_AUTHTOKEN_HERE';

(async () => {
  try {
    const response = await fetch(`${API_URL}/create-checkout-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': `authToken=${JWT_TOKEN}` },
      body: JSON.stringify({ type: 'WEEKLY' })
    });
    const data = await response.json();
    console.log('URL:', data.url);
  } catch (error) {
    console.error('ERROR:', error);
  }
})();