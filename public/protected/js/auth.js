// public/protected/js/auth.js
// ========================================
//  GLOBAL API URL + LOGGING
// ========================================

const API_URL = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
  ? 'http://localhost:3000'
  : 'https://authappmain.onrender.com';

console.log('🔧 auth.js loaded – API_URL:', API_URL);

// Optional logged fetch (use it everywhere for extra logs)
window.loggedFetch = async (url, opts = {}) => {
  console.log('📡 CALL →', url, opts.method || 'GET');
  try {
    const r = await fetch(url, { ...opts, credentials: 'include' });
    console.log('📡 RESPONSE ←', url, r.status);
    return r;
  } catch (e) {
    console.error('💥 FETCH ERROR →', url, e);
    throw e;
  }
};

window.API_URL = API_URL;