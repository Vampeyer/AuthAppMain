// public/protected/js/auth.js
// ========================================
//  AUTO-DETECTION: Render → Localhost → Fallback
// ========================================

const RENDER_API = 'https://authappmain.onrender.com';
const LOCAL_API = 'http://localhost:3000';

// Detect if we're on Hostinger (no server)
const isHostinger = location.hostname === 'techsport.app' || location.hostname.endsWith('.hstgr.io');

let API_URL = RENDER_API;  // default

// Test Render
async function testRender() {
  try {
    console.log('Testing Render API...');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const r = await fetch(`${RENDER_API}/profile`, {
      method: 'HEAD',
      credentials: 'include',
      signal: controller.signal
    });
    clearTimeout(timeout);
    return r.ok;
  } catch (err) {
    console.error('Render unreachable:', err.message);
    return false;
  }
}

// Set API_URL
(async () => {
  if (isHostinger) {
    console.log('Running on Hostinger → using Render API');
  } else if (location.port === '5500' || location.port === '3000') {
    // Live Server (5500) or Express (3000)
    console.log('Local dev → trying Render, fallback to localhost:3000');
    const renderUp = await testRender();
    API_URL = renderUp ? RENDER_API : LOCAL_API;
  } else {
    API_URL = LOCAL_API;
  }

  window.API_URL = API_URL;
  console.log('API_URL →', API_URL);
})();

// Logged fetch
window.loggedFetch = async (url, opts = {}) => {
  console.log('CALL →', url, opts.method || 'GET');
  try {
    const r = await fetch(url, { ...opts, credentials: 'include' });
    console.log('RESPONSE ←', url, r.status);
    if (!r.ok && r.status !== 401) {
      const text = await r.text();
      console.error('API ERROR:', r.status, text);
    }
    return r;
  } catch (e) {
    console.error('FETCH ERROR →', url, e.message);
    throw e;
  }
};