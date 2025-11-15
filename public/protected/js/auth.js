// auth.js – v20251115
const API_URL = 'https://authappmain.onrender.com';

let authToken = sessionStorage.getItem('authToken');

export function setToken(token) {
  authToken = token;
  sessionStorage.setItem('authToken', token);
  console.log('setToken – JWT stored');
}

export function getToken() { return authToken; }

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
  }

  const response = await fetch(`${API_URL}${url}`, {
    ...options,
    headers,
    credentials: 'omit'
  });

  console.log(`authFetch → ${url} [${response.status}]`);
  return response;
}

// Health check
window.addEventListener('load', async () => {
  try {
    const r = await fetch(`${API_URL}/`);
    console.log('API health:', r.status);
  } catch (e) {
    console.error('API down:', e.message);
  }
});