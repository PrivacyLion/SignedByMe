/**
 * SignedByMe Enterprise Demo
 * Tests the stateless authentication flow
 */
(function() {
  const API = "https://api.beta.privacy-lion.com";
  
  // State
  let state = {
    sessionToken: null,
    sessionId: null,
    qrData: null,
    invoice: null,
    did: null,
    stwoVerified: false,
    idToken: null
  };

  // DOM helpers
  const $ = (sel) => document.querySelector(sel);
  const show = (id) => document.getElementById(id)?.classList.remove('hidden');
  const hide = (id) => document.getElementById(id)?.classList.add('hidden');
  
  function setStep(n) {
    for (let i = 1; i <= 4; i++) {
      const el = $(`#step${i}`);
      el.classList.remove('active', 'done');
      if (i < n) el.classList.add('done');
      if (i === n) el.classList.add('active');
    }
  }

  function setStatus(id, msg, type = '') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
    el.className = 'status ' + type;
    show(id);
  }

  async function apiPost(path, body) {
    const resp = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (!resp.ok) throw data;
    return data;
  }

  async function apiGet(path) {
    const resp = await fetch(`${API}${path}`);
    const data = await resp.json();
    if (!resp.ok) throw data;
    return data;
  }

  // Create session
  async function createSession() {
    const name = $('#enterprise-name').value || 'Test Corp';
    const amount = parseInt($('#amount-sats').value) || 100;
    let callback = $('#callback-url').value;
    
    // Use httpbin as a test callback if none provided
    if (!callback) {
      callback = 'https://httpbin.org/post';
    }

    try {
      setStatus('status-create', 'Creating session...', 'pending');
      
      const resp = await apiPost('/v1/enterprise/session', {
        enterprise_id: 'test-' + Date.now(),
        enterprise_name: name,
        amount_sats: amount,
        callback_url: callback,
        domain: window.location.hostname || 'localhost'
      });

      state.sessionToken = resp.session_token;
      state.sessionId = resp.session_id;
      state.qrData = resp.qr_data;

      setStatus('status-create', `Session created!\nID: ${resp.session_id}\nExpires: ${new Date(resp.expires_at * 1000).toLocaleString()}`, 'success');

      // Show QR card
      showQR();
      setStep(2);

    } catch (e) {
      console.error(e);
      setStatus('status-create', 'Error: ' + (e.detail || e.message || JSON.stringify(e)), 'error');
    }
  }

  function showQR() {
    hide('card-create');
    show('card-qr');

    // Generate QR
    const container = $('#qr-container');
    container.innerHTML = '';
    new QRCode(container, {
      text: state.qrData,
      width: 256,
      height: 256,
      colorDark: '#1a1a2e',
      colorLight: '#ffffff'
    });

    // Show deep link
    $('#deep-link').textContent = state.qrData;

    // Start polling for invoice (simulated - in real scenario, webhook would notify)
    setStatus('status-waiting', `Session: ${state.sessionId}\nWaiting for user to scan QR and submit invoice...\n\nNote: Since this demo uses httpbin.org as callback, you'll need to manually enter the invoice details when the app submits.`, 'pending');
  }

  function copyDeepLink() {
    navigator.clipboard.writeText(state.qrData);
    alert('Deep link copied to clipboard!');
  }

  function newSession() {
    state = { sessionToken: null, sessionId: null, qrData: null, invoice: null, did: null, stwoVerified: false, idToken: null };
    hide('card-qr');
    hide('card-invoice');
    hide('card-verified');
    show('card-create');
    hide('status-create');
    setStep(1);
  }

  // Manually enter invoice (since we can't receive webhooks in browser)
  function showInvoiceEntry() {
    // For demo, allow manual invoice entry
    const invoice = prompt('Enter the BOLT11 invoice from the mobile app:');
    if (!invoice) return;
    
    const did = prompt('Enter the user DID (e.g., did:btcr:02abc...):', 'did:btcr:test');
    if (!did) return;

    state.invoice = invoice;
    state.did = did;
    state.stwoVerified = true; // Assume verified for demo

    showInvoiceCard();
  }

  function showInvoiceCard() {
    hide('card-qr');
    show('card-invoice');
    setStep(3);

    $('#invoice-display').textContent = state.invoice;
    $('#user-did').value = state.did;
    $('#stwo-status').value = state.stwoVerified ? '✓ Verified' : '✗ Not verified';
  }

  async function confirmPayment() {
    const preimage = $('#preimage-input').value.trim();
    
    if (!preimage || preimage.length !== 64) {
      alert('Please enter a valid 64-character hex preimage');
      return;
    }

    try {
      setStatus('status-invoice', 'Confirming payment...', 'pending');

      const resp = await apiPost('/v1/login/confirm', {
        session_token: state.sessionToken,
        preimage: preimage
      });

      if (resp.verified) {
        state.idToken = resp.id_token;
        showVerified();
      } else {
        setStatus('status-invoice', 'Verification failed: ' + JSON.stringify(resp), 'error');
      }

    } catch (e) {
      console.error(e);
      setStatus('status-invoice', 'Error: ' + (e.detail || e.message || JSON.stringify(e)), 'error');
    }
  }

  function simulatePayment() {
    // Generate a random "preimage" for testing
    // In real scenario, this comes from the Lightning payment
    const randomBytes = new Uint8Array(32);
    crypto.getRandomValues(randomBytes);
    const preimage = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    
    $('#preimage-input').value = preimage;
    setStatus('status-invoice', `Simulated preimage generated.\n\nNote: This won't actually verify against the real invoice payment_hash.\nIn production, you'd get the real preimage from your Lightning node after paying.`, 'pending');
  }

  function showVerified() {
    hide('card-invoice');
    show('card-verified');
    setStep(4);

    $('#id-token').value = state.idToken;
  }

  function decodeToken() {
    try {
      const parts = state.idToken.split('.');
      if (parts.length !== 3) throw new Error('Invalid JWT');
      
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      
      setStatus('status-verified', `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}`, 'success');
    } catch (e) {
      setStatus('status-verified', 'Error decoding: ' + e.message, 'error');
    }
  }

  // API status checks
  async function checkHealth() {
    try {
      const data = await apiGet('/healthz');
      setStatus('api-status', JSON.stringify(data, null, 2), 'success');
    } catch (e) {
      setStatus('api-status', 'Error: ' + JSON.stringify(e), 'error');
    }
  }

  async function getInfo() {
    try {
      const data = await apiGet('/v1/enterprise/info');
      setStatus('api-status', JSON.stringify(data, null, 2), 'success');
    } catch (e) {
      setStatus('api-status', 'Error: ' + JSON.stringify(e), 'error');
    }
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', () => {
    // Bind buttons
    $('#btn-create-session')?.addEventListener('click', createSession);
    $('#btn-copy-link')?.addEventListener('click', copyDeepLink);
    $('#btn-new-session')?.addEventListener('click', newSession);
    $('#btn-confirm')?.addEventListener('click', confirmPayment);
    $('#btn-simulate-pay')?.addEventListener('click', simulatePayment);
    $('#btn-decode-token')?.addEventListener('click', decodeToken);
    $('#btn-start-over')?.addEventListener('click', newSession);
    $('#btn-health')?.addEventListener('click', checkHealth);
    $('#btn-info')?.addEventListener('click', getInfo);

    // Add manual invoice entry button to QR card
    const qrCard = $('#card-qr');
    if (qrCard) {
      const btn = document.createElement('button');
      btn.className = 'btn btn-secondary';
      btn.textContent = 'Enter Invoice Manually';
      btn.style.marginTop = '12px';
      btn.addEventListener('click', showInvoiceEntry);
      qrCard.appendChild(btn);
    }

    setStep(1);
    console.log('SignedByMe Enterprise Demo initialized');
  });
})();
