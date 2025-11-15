// auth.js – v20251115
const API_URL = 'https://authappmain.onrender.com';

let authToken = sessionStorage.getItem('authToken');

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

  try {
    const response = await fetch(`${API_URL}${url}`, {
      ...options,
      headers,
      credentials: 'omit'
    });

    console.log(`authFetch GET ${url} → ${response.status}`);
    return response;
  } catch (err) {
    console.error('authFetch network error:', err);
    throw err;
  }
}

// Health check
fetch(`${API_URL}/`)
  .then(r => console.log('API health –', r.status))
  .catch(() => console.log('API health – offline'));