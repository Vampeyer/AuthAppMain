// protected/js/auth.js
const RENDER_API = 'https://authappmain.onrender.com';
const LOCAL_API = 'http://localhost:3000';

let API_URL = RENDER_API;
let api = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
  timeout: 10000
});

async function testAPI(url) {
  try {
    await axios.get(`${url}/profile`, { timeout: 3000, withCredentials: true });
    return true;
  } catch (e) {
    return false;
  }
}

(async () => {
  const works = await testAPI(RENDER_API);
  if (!works) {
    console.warn('[auth.js] Render down → localhost');
    API_URL = LOCAL_API;
    api = axios.create({
      baseURL: API_URL,
      withCredentials: true,
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    attachInterceptors();
  }
  console.log('[auth.js] API_URL:', API_URL);
  window.API_URL = API_URL;
})();

function attachInterceptors() {
  api.interceptors.request.use(cfg => {
    console.log('[axios] →', cfg.method.toUpperCase(), cfg.url);
    return cfg;
  });
  api.interceptors.response.use(
    res => {
      console.log('[axios] ←', res.status, res.config.url);
      return res;
    },
    err => {
      console.error('[axios] ← ERROR', err.response?.status, err.config?.url);
      return Promise.reject(err);
    }
  );
}
attachInterceptors();

window.API = {
  async login(login, password, mnemonic) {
    try {
      const r = await api.post('/login', { login, password, mnemonic });
      if (r.data.success) location.href = '/profile.html';
    } catch (e) { alert('Login failed'); }
  },

  async loadProfile() {
    try {
      const res = await api.get('/profile');
      return res.data;
    } catch (e) {
      return { loggedIn: false };
    }
  },

  async subscribe(type) {
    try {
      const r = await api.post('/create-checkout-session', { type });
      if (r.data.url) location.href = r.data.url;
    } catch (e) {
      alert('Checkout failed');
    }
  },

  async cancelSubscription() {
    if (!confirm('Cancel?')) return;
    try {
      await api.post('/delete-subscription');
      alert('Cancelled'); location.reload();
    } catch (e) { alert('Failed'); }
  },

  async logout() {
    await api.post('/logout');
    location.href = '/login.html';
  }
};