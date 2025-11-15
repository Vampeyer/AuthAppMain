// public/protected/js/auth.js
const API_URL = 'https://authappmain.onrender.com';

// ------------------------------------------------------------------
// 1. Token storage (sessionStorage)
// ------------------------------------------------------------------
let authToken = sessionStorage.getItem('authToken');

// ------------------------------------------------------------------
// 2. EXPORTED FUNCTIONS (named exports)
// ------------------------------------------------------------------
export function setToken(token) {
  authToken = token;
  sessionStorage.setItem('authToken', token);
  console.log('setToken – JWT stored in sessionStorage');
}

export function getToken() {
  return authToken;
}

export function clearToken() {
  authToken = null;
  sessionStorage.removeItem('authToken');
  console.log('clearToken – JWT removed');
}

// ------------------------------------------------------------------
// 3. authFetch – adds Bearer token if present
// ------------------------------------------------------------------
export async function authFetch(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
    console.log('authFetch – adding JWT to request');
  }

  const response = await fetch(`${API_URL}${url}`, {
    ...options,
    headers,
    credentials: 'omit'   // ← no cookies → CORS safe
  });

  console.log(`authFetch ${options.method || 'GET'} ${url} → ${response.status}`);
  return response;
}

// ------------------------------------------------------------------
// 4. Health check on load
// ------------------------------------------------------------------
window.addEventListener('load', async () => {
  try {
    const r = await fetch(`${API_URL}/`);
    console.log('API health check – status:', r.status);
  } catch (e) {
    console.error('API health check failed:', e.message);
  }
});