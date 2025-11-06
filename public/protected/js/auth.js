// public/protected/js/auth.js
// PRODUCTION-FIRST, LOCALHOST-FALLBACK STRATEGY
// Works on: Live Server (any port), Hostinger, Render, localhost:3000, localhost:5500, etc.

let API_URL = 'https://authappmain.onrender.com'; // ← Your real Render URL

// ONLY fallback to localhost if we're clearly in dev mode AND Render is unreachable
if (window.location.hostname === 'localhost' || 
    window.location.hostname === '127.0.0.1' || 
    window.location.hostname.includes('techsport.app')) {

  // First: try to reach Render (even on localhost!)
  const testRender = async () => {
    try {
      const res = await fetch(`${API_URL}/ping`, { method: 'HEAD', credentials: 'include' });
      if (res.ok) {
        console.log('✅ Connected to Render backend:', API_URL);
        return API_URL;
      }
    } catch (err) {
      // Render is down or blocked → fall back to localhost
      console.warn('⚠️ Render backend unreachable, switching to localhost');
    }
    return null;
  };

  // Final fallback: localhost on current port OR default 3000
  const fallbackLocal = () => {
    const currentPort = window.location.port || '3000';
    const localUrl = `${window.location.protocol}//${window.location.hostname}:${currentPort}`;
    console.log('🔄 Using local backend:', localUrl);
    return localUrl;
  };

  // Set API_URL intelligently
  (async () => {
    const renderWorks = await testRender();
    API_URL = renderWorks || fallbackLocal();
  })();
}

// Optional: expose for debugging in console
window.DEBUG_API_URL = () => console.log('Current API_URL →', API_URL);