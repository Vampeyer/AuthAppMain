// protected/js/auth.js
const API_URL = window.location.hostname.includes('techsport.app') ? 'https://movies-auth-app.onrender.com' : 'http://localhost:3000';

async function getToken() {
  try {
    const response = await fetch(`${API_URL}/profile`, { credentials: 'include' });
    console.log('Token check response:', response.status);
    if (!response.ok) return null;
    return 'valid';
  } catch (error) {
    console.error('Token check error:', error);
    return null;
  }
}

document.getElementById('signupForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('signupUsername').value;
  const email = document.getElementById('signupEmail').value;
  const password = document.getElementById('signupPassword').value;
  const subscription_type = document.getElementById('subscriptionType').value;
  try {
    console.log('Sending signup request:', { username, email, subscription_type });
    const response = await fetch(`${API_URL}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, subscription_type }),
      credentials: 'include'
    });
    const data = await response.json();
    console.log('Signup response:', data);
    if (data.error) return alert(data.error);
    document.getElementById('mnemonicDisplay').textContent = `Your 12-word key phrase (save this!): ${data.mnemonic}`;
    document.getElementById('mnemonicDisplay').style.display = 'block';
    document.getElementById('saveConfirmation').style.display = 'block';
    document.getElementById('signupForm').style.display = 'none';
  } catch (error) {
    console.error('Signup error:', error);
    alert('Signup failed: ' + error.message);
  }
});

if (window.location.pathname.includes('profile.html')) {
  fetch(`${API_URL}/profile`, {
    credentials: 'include'
  }).then(res => res.json()).then(data => {
    console.log('Profile response:', data);
    if (data.error) {
      console.log('Profile error redirecting:', data.error);
      alert(data.error);
      window.location.href = '/login.html';
      return;
    }
    document.getElementById('usernameDisplay').textContent = data.username;
    document.getElementById('emailDisplay').textContent = data.email;
    const statusCircle = document.getElementById('statusCircle');
    const statusText = document.getElementById('statusText');
    if (data.subscription_active) {
      statusCircle.classList.add('green');
      statusCircle.classList.remove('red');
      statusText.textContent = 'Active';
    } else {
      statusText.textContent = 'Inactive';
    }
    if (data.picture_base64) {
      document.getElementById('profilePic').src = `data:image/png;base64,${data.picture_base64}`;
    }
  }).catch(error => {
    console.error('Profile fetch error:', error);
    alert('Profile load failed: ' + error.message);
    window.location.href = '/login.html';
  });
}

function uploadPicture() {
  const file = document.getElementById('pictureUpload').files[0];
  if (!file) return alert('Select a file');
  const reader = new FileReader();
  reader.onload = async (e) => {
    const image_base64 = e.target.result.split(',')[1];
    try {
      console.log('Uploading picture');
      const response = await fetch(`${API_URL}/upload-picture`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_base64 }),
        credentials: 'include'
      });
      const data = await response.json();
      console.log('Upload picture response:', data);
      if (data.error) return alert(data.error);
      location.reload();
    } catch (error) {
      console.error('Upload picture error:', error);
      alert('Upload failed: ' + error.message);
    }
  };
  reader.readAsDataURL(file);
}

async function subscribe(type) {
  try {
    console.log('Starting subscription:', type);
    const response = await fetch(`${API_URL}/create-checkout-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type }),
      credentials: 'include'
    });
    const data = await response.json();
    console.log('Subscribe response:', data);
    if (data.error) return alert(data.error);
    if (data.url) window.location.href = data.url;
    else location.reload();
  } catch (error) {
    console.error('Subscribe error:', error);
    alert('Subscription failed: ' + error.message);
  }
}

if (window.location.pathname.includes('movie_content.html')) {
  fetch(`${API_URL}/check-subscription`, {
    credentials: 'include'
  }).then(response => response.json()).then(data => {
    console.log('Check subscription response:', data);
    if (data.error || !data.active) {
      alert('No active subscription. Redirecting...');
      window.location.href = '/profile.html';
    }
  }).catch(error => {
    console.error('Check subscription error:', error);
    alert('Error checking subscription: ' + error.message);
    window.location.href = '/profile.html';
  });
}