// protected/js/auth.js
function getApiUrl() {
  const h = window.location.hostname;
  if (h.includes('techsport.app')) return 'https://your-render-service.onrender.com';
  if (h === 'localhost' || h === '127.0.0.1') return 'http://localhost:3000';
  return 'https://your-render-service.onrender.com';
}
const API_URL = getApiUrl();