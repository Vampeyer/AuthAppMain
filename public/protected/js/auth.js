// protected/js/auth.js

// Function to determine the correct API URL
function getApiUrl() {
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;
  
  console.log('Current hostname:', hostname);
  console.log('Current protocol:', protocol);
  
  // If we're on authappmain.onrender.com, the API is on the same domain
  if (hostname === 'authappmain.onrender.com') {
    console.log('Detected authappmain.onrender.com - using same domain API');
    return 'https://authappmain.onrender.com';
  }
  
  // Check if we're on techsport.app domain
  if (hostname.includes('techsport.app')) {
    console.log('Detected techsport.app domain - using Render production server');
    return 'https://authappmain.onrender.com';
  }
  
  // Check if we're on localhost or 127.0.0.1
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    console.log('Detected localhost - attempting local server first');
    return 'http://localhost:3000';
  }
  
  // Default to Render production server
  console.log('Using default Render production server');
  return 'https://authappmain.onrender.com';
}

let API_URL = getApiUrl();
console.log('API_URL set to:', API_URL);

// Test API connection on page load
window.addEventListener('load', async () => {
  try {
    console.log('Testing API connection to:', API_URL);
    const response = await fetch(`${API_URL}/`, {
      method: 'GET',
      credentials: 'include'
    });
    console.log('API connection test response status:', response.status);
    if (response.ok) {
      console.log('✅ API connection successful');
    } else {
      console.warn('⚠️ API connection returned non-OK status:', response.status);
    }
  } catch (error) {
    console.error('❌ API connection test failed:', error.message);
    console.error('Ensure your server is running at:', API_URL);
  }
});