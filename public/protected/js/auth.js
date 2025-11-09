// protected/js/auth.js

// Function to determine the correct API URL
function getApiUrl() {
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;
  const port = window.location.port;
  
  console.log('Current hostname:', hostname);
  console.log('Current protocol:', protocol);
  console.log('Current port:', port);
  
  // If we're on authappmain.onrender.com, the API is on the same domain
  if (hostname === 'authappmain.onrender.com') {
    console.log('Detected authappmain.onrender.com - using same domain API');
    return 'https://authappmain.onrender.com';
  }
  
  // Check if we're on techsport.app domain - use authappmain
  if (hostname.includes('techsport.app')) {
    console.log('Detected techsport.app domain - using authappmain Render server');
    return 'https://authappmain.onrender.com';
  }
  
  // Check if we're on localhost or 127.0.0.1
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    // If on port 3000, use same domain (localhost:3000)
    if (port === '3000' || port === '3001') {
      console.log('Detected localhost:' + port + ' - using same domain for API');
      return protocol + '//' + hostname + ':' + port;
    }
    // If on port 5500 (Live Server) or any other port, try localhost:3000 first
    console.log('Detected localhost:' + port + ' - will try localhost:3000 first');
    return 'http://localhost:3000';
  }
  
  // Default to Render production server
  console.log('Using default authappmain Render server');
  return 'https://authappmain.onrender.com';
}

const API_URL = getApiUrl();
console.log('API_URL set to:', API_URL);

// Fallback API URL for localhost testing
let FALLBACK_API_URL = 'https://authappmain.onrender.com';

// Test API connection on page load with fallback
window.addEventListener('load', async () => {
  try {
    console.log('Testing API connection to:', API_URL);
    const response = await fetch(`${API_URL}/health`, {
      method: 'GET',
      credentials: 'include'
    });
    console.log('API connection test response status:', response.status);
    if (response.ok) {
      console.log('✅ API connection successful to:', API_URL);
    } else {
      console.warn('⚠️ API connection returned non-OK status:', response.status);
      // Try fallback if we're on localhost:5500
      if (window.location.port === '5500') {
        console.log('Trying fallback to authappmain...');
        await tryFallback();
      }
    }
  } catch (error) {
    console.error('❌ API connection test failed:', error.message);
    console.error('Primary API URL was:', API_URL);
    
    // Try fallback if we're on localhost:5500 and localhost:3000 failed
    if (window.location.port === '5500') {
      console.log('Trying fallback to authappmain...');
      await tryFallback();
    } else {
      console.error('Ensure your server is running at:', API_URL);
    }
  }
});

async function tryFallback() {
  try {
    const response = await fetch(`${FALLBACK_API_URL}/health`, {
      method: 'GET',
      credentials: 'include'
    });
    if (response.ok) {
      console.log('✅ Fallback successful! Using authappmain.onrender.com');
      // Update API_URL globally
      window.API_URL = FALLBACK_API_URL;
    }
  } catch (error) {
    console.error('❌ Fallback to authappmain also failed');
  }
}

// Make API_URL globally accessible
window.API_URL = API_URL;