// protected/js/auth.js
const RENDER_API = 'https://authappmain.onrender.com';
const LOCAL_API = 'http://localhost:3000';

let API_URL = RENDER_API;

async function testAPI(url) {
  try {
    await fetch(`${url}/profile`, { credentials: 'include', timeout: 3000 });
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
  }
  console.log('[auth.js] API_URL:', API_URL);
})();

window.API = {
  async login(login, password, mnemonic) {
    try {
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login, password, mnemonic }),
        credentials: 'include'
      });
      const data = await response.json();
      if (data.success) location.href = '/profile.html';
    } catch (e) { alert('Login failed'); }
  },

  async loadProfile() {
    try {
      const response = await fetch(`${API_URL}/profile`, {
        credentials: 'include'
      });
      return await response.json();
    } catch (e) {
      return { loggedIn: false };
    }
  },

  async subscribe(type) {
    try {
      const response = await fetch(`${API_URL}/create-checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type }),
        credentials: 'include'
      });
      const data = await response.json();
      if (data.url) window.location.href = data.url;
    } catch (e) { alert('Checkout failed'); }
  },

  async cancelSubscription() {
    if (!confirm('Cancel?')) return;
    try {
      const response = await fetch(`${API_URL}/delete-subscription`, {
        method: 'POST',
        credentials: 'include'
      });
      const data = await response.json();
      if (data.success) {
        alert('Cancelled');
        location.reload();
      }
    } catch (e) { alert('Failed'); }
  },

  async logout() {
    try {
      await fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include'
      });
      location.href = '/login.html';
    } catch (e) { alert('Logout failed'); }
  }
};