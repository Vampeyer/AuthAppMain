// public/protected/js/auth.js
const API_URL = 'https://authappmain.onrender.com';

// ------------------------------------------------------------------
// 1. Token storage
// ------------------------------------------------------------------
let authToken = sessionStorage.getItem('authToken');

// ------------------------------------------------------------------
// 2. EXPORTS (named) – REQUIRED FOR import { authFetch }
// ------------------------------------------------------------------
export function setToken(token) {
  authToken = token;
  sessionStorage.setItem('authToken', token);
  console.log('setToken – JWT stored');
}

export function getToken() {
  return authToken;
}

export function clearToken() {
  authToken = null;
  sessionStorage.removeItem('authToken');
  console.log('clearToken – JWT removed');
}

export async function authFetch(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
    console.log('authFetch – sending Bearer token');
  }

  const response = await fetch(`${API_URL}${url}`, {
    ...options,
    headers,
    credentials: 'omit'
  });

  console.log(`authFetch ${options.method || 'GET'} ${url} → ${response.status}`);
  return response;
}

// ------------------------------------------------------------------
// 3. Health check
// ------------------------------------------------------------------
window.addEventListener('load', async () => {
  try {
    const r = await fetch(`${API_URL}/`);
    console.log('API health –', r.status);
  } catch (e) {
    console.error('API unreachable:', e.message);
  }
});