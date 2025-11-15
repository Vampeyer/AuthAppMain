// public/protected/js/auth.js
const API_URL = 'https://authappmain.onrender.com';

let authToken = sessionStorage.getItem('authToken');

export function setToken(t) {
  authToken = t;
  sessionStorage.setItem('authToken', t);
  console.log('setToken – stored JWT');
}

export function getToken() { return authToken; }

export function clearToken() {
  authToken = null;
  sessionStorage.removeItem('authToken');
  console.log('clearToken – removed JWT');
}

export async function authFetch(url, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...opts.headers
  };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

  const response = await fetch(`${API_URL}${url}`, {
    ...opts,
    headers,
    credentials: 'omit'
  });
  console.log(`authFetch ${opts.method || 'GET'} ${url} – status: ${response.status}`);
  return response;
}

window.addEventListener('load', async () => {
  try {
    const r = await fetch(`${API_URL}/`);
    console.log('API health check –', r.status);
  } catch (e) {
    console.error('API health check failed:', e.message);
  }
});