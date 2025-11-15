// protected/js/auth.js
const API_URL = 'https://authappmain.onrender.com';

let authToken = sessionStorage.getItem('authToken');

function setToken(token) {
  authToken = token;
  sessionStorage.setItem('authToken', token);
}

function getToken() {
  return authToken;
}

function clearToken() {
  authToken = null;
  sessionStorage.removeItem('authToken');
}

async function authFetch(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };
  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return fetch(`${API_URL}${url}`, {
    ...options,
    headers
  });
}

// Test connection on load
window.addEventListener('load', async () => {
  try {
    const res = await fetch(`${API_URL}/`);
    console.log('API status:', res.status);
  } catch (err) {
    console.error('API connection failed:', err);
  }
});