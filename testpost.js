// testpost.js
// Run: node testpost.js

require('dotenv').config();
const axios = require('axios');

const API_URL = 'https://authappmain.onrender.com';
const JWT_TOKEN = 'PASTE_YOUR_AUTHTOKEN_HERE'; // ← Copy from browser

(async () => {
  try {
    const response = await axios.post(
      `${API_URL}/create-checkout-session`,
      { type: 'WEEKLY' },
      {
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `authToken=${JWT_TOKEN}`
        },
        withCredentials: true
      }
    );

    console.log('SUCCESS! URL:', response.data.url);
  } catch (error) {
    console.error('ERROR:', error.response?.data || error.message);
  }
})();